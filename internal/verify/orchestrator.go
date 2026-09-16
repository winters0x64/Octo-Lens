package verify

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
)

type Orchestrator struct {
	org    string
	client *github.Client
}

func NewOrchestrator(org string, client *github.Client) *Orchestrator {
	return &Orchestrator{org: org, client: client}
}

const (
	branchPrefix = "octolens-verify-"
	workflowPath = ".github/workflows/octolens-verify.yml"
	// artifactPrefix matches both the repo-secrets job's "octolens-verify"
	// artifact and each environment job's "octolens-verify-env-N" artifact.
	artifactPrefix = "octolens-verify"

	// callTimeout bounds a single GitHub API call. This is enforced via an
	// explicit context deadline rather than the http.Client's Timeout field
	// because at least one method used here (DownloadArtifact, to follow
	// GitHub's redirect to a pre-signed artifact URL) calls the transport's
	// RoundTrip directly instead of going through http.Client.Do — and
	// http.Client.Timeout is only ever enforced inside Do, so it is silently
	// never applied to calls that bypass it. A context deadline, by
	// contrast, is honored by the underlying transport during actual network
	// I/O regardless of which path a given method takes to get there, so
	// it's the only reliable place to enforce this across every call.
	callTimeout = 60 * time.Second
)

// withDeadline returns a context bounded to callTimeout for a single network
// call. See the callTimeout doc comment for why this can't just be an
// http.Client.Timeout instead.
func withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, callTimeout)
}

func (o *Orchestrator) VerifyRepo(ctx context.Context, repoName string, repoSecrets []string, envGroups []EnvironmentSecrets) (*RepoVerifyResult, error) {
	result := &RepoVerifyResult{
		Repo:   o.org + "/" + repoName,
		Status: "failure",
	}

	totalSecrets := len(repoSecrets)
	for _, g := range envGroups {
		totalSecrets += len(g.Names)
	}
	if totalSecrets == 0 {
		result.Status = "skipped"
		return result, nil
	}

	branchName := branchPrefix + fmt.Sprintf("%d", time.Now().Unix())

	baseSHA, err := o.getDefaultBranchSHA(ctx, repoName)
	if err != nil {
		return result, err
	}

	if err := o.createBranch(ctx, repoName, branchName, baseSHA); err != nil {
		return result, err
	}
	log.Printf("[verify] created branch %s on %s/%s", branchName, o.org, repoName)

	defer func() {
		o.cleanup(context.Background(), repoName, branchName)
	}()

	if err := o.pushWorkflow(ctx, repoName, branchName, repoSecrets, envGroups); err != nil {
		return result, err
	}
	log.Printf("[verify] pushed workflow to %s/%s/%s", o.org, repoName, branchName)

	runID, err := o.waitForRun(ctx, repoName, branchName)
	if err != nil {
		return result, fmt.Errorf("wait for run: %w", err)
	}
	result.RunID = runID
	log.Printf("[verify] found run %d on %s/%s", runID, o.org, repoName)

	if err := o.waitForCompletion(ctx, repoName, runID); err != nil {
		return result, fmt.Errorf("wait for completion: %w", err)
	}
	log.Printf("[verify] run %d completed on %s/%s", runID, o.org, repoName)

	secrets, err := o.downloadResults(ctx, repoName, runID)
	if err != nil {
		return result, fmt.Errorf("download results: %w", err)
	}
	result.Secrets = secrets
	result.Status = "success"

	return result, nil
}

func (o *Orchestrator) getDefaultBranchSHA(ctx context.Context, repoName string) (string, error) {
	cctx, cancel := withDeadline(ctx)
	defer cancel()
	ref, _, err := o.client.Git.GetRef(cctx, o.org, repoName, "refs/heads/main")
	if err != nil {
		cctx2, cancel2 := withDeadline(ctx)
		defer cancel2()
		ref, _, err = o.client.Git.GetRef(cctx2, o.org, repoName, "refs/heads/master")
		if err != nil {
			return "", fmt.Errorf("get default branch SHA for %s/%s: %w", o.org, repoName, err)
		}
	}
	return ref.GetObject().GetSHA(), nil
}

func (o *Orchestrator) createBranch(ctx context.Context, repoName, branchName, baseSHA string) error {
	cctx, cancel := withDeadline(ctx)
	defer cancel()
	ref := &github.Reference{
		Ref:    github.Ptr("refs/heads/" + branchName),
		Object: &github.GitObject{SHA: github.Ptr(baseSHA)},
	}
	_, _, err := o.client.Git.CreateRef(cctx, o.org, repoName, ref)
	if err != nil {
		return fmt.Errorf("create branch %s on %s/%s: %w", branchName, o.org, repoName, err)
	}
	return nil
}

func (o *Orchestrator) pushWorkflow(ctx context.Context, repoName, branchName string, repoSecrets []string, envGroups []EnvironmentSecrets) error {
	cctx, cancel := withDeadline(ctx)
	defer cancel()
	content := GenerateWorkflow(o.org+"/"+repoName, repoSecrets, envGroups)
	opts := &github.RepositoryContentFileOptions{
		Message: github.Ptr("[octolens] verify secrets (auto-cleanup)"),
		Content: []byte(content),
		Branch:  github.Ptr(branchName),
	}
	_, _, err := o.client.Repositories.CreateFile(cctx, o.org, repoName, workflowPath, opts)
	if err != nil {
		return fmt.Errorf("push workflow to %s/%s: %w", o.org, repoName, err)
	}
	return nil
}

func (o *Orchestrator) waitForRun(ctx context.Context, repoName, branchName string) (int64, error) {
	time.Sleep(5 * time.Second)

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		cctx, cancel := withDeadline(ctx)
		runs, _, err := o.client.Actions.ListWorkflowRunsByFileName(cctx, o.org, repoName, "octolens-verify.yml",
			&github.ListWorkflowRunsOptions{
				Branch:      branchName,
				ListOptions: github.ListOptions{PerPage: 1},
			})
		cancel()
		if err == nil && runs.GetTotalCount() > 0 && len(runs.WorkflowRuns) > 0 {
			runID := runs.WorkflowRuns[0].GetID()
			if runID > 0 {
				return runID, nil
			}
		}
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return 0, fmt.Errorf("workflow run did not appear within 2 minutes on %s/%s", o.org, repoName)
}

func (o *Orchestrator) waitForCompletion(ctx context.Context, repoName string, runID int64) error {
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		cctx, cancel := withDeadline(ctx)
		run, _, err := o.client.Actions.GetWorkflowRunByID(cctx, o.org, repoName, runID)
		cancel()
		if err == nil && run.GetStatus() == "completed" {
			return nil
		}
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("run %d on %s/%s did not complete within 10 minutes", runID, o.org, repoName)
}

// downloadResults collects verify-results.json from every job's artifact
// (the repo-secrets job's "octolens-verify" plus one "octolens-verify-env-N"
// per environment job) and merges them into a single result list.
func (o *Orchestrator) downloadResults(ctx context.Context, repoName string, runID int64) ([]SecretVerification, error) {
	cctx, cancel := withDeadline(ctx)
	defer cancel()
	artifacts, _, err := o.client.Actions.ListWorkflowRunArtifacts(cctx, o.org, repoName, runID,
		&github.ListOptions{PerPage: 20})
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}

	var matched []*github.Artifact
	for _, a := range artifacts.Artifacts {
		if strings.HasPrefix(a.GetName(), artifactPrefix) {
			matched = append(matched, a)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("no artifact matching %q found in run %d", artifactPrefix, runID)
	}

	var all []SecretVerification
	for _, a := range matched {
		results, err := o.downloadOneArtifact(ctx, repoName, a.GetID())
		if err != nil {
			return nil, fmt.Errorf("artifact %q: %w", a.GetName(), err)
		}
		all = append(all, results...)
	}
	return all, nil
}

func (o *Orchestrator) downloadOneArtifact(ctx context.Context, repoName string, artifactID int64) ([]SecretVerification, error) {
	// DownloadArtifact calls the transport's RoundTrip directly to follow
	// GitHub's redirect to a pre-signed URL — see the callTimeout doc comment
	// for why this specifically needs its own context deadline.
	cctx, cancel := withDeadline(ctx)
	url, _, err := o.client.Actions.DownloadArtifact(cctx, o.org, repoName, artifactID, 1)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("get artifact download URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build artifact download request: %w", err)
	}
	httpClient := &http.Client{Timeout: callTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read artifact response: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open artifact zip: %w", err)
	}

	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "verify-results.json") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open results file in zip: %w", err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("read results: %w", err)
			}

			var results []SecretVerification
			if err := json.Unmarshal(data, &results); err != nil {
				return nil, fmt.Errorf("parse results: %w", err)
			}
			return results, nil
		}
	}

	return nil, fmt.Errorf("verify-results.json not found in artifact zip")
}

func (o *Orchestrator) cleanup(ctx context.Context, repoName, branchName string) {
	cctx, cancel := withDeadline(ctx)
	defer cancel()
	_, err := o.client.Git.DeleteRef(cctx, o.org, repoName, "refs/heads/"+branchName)
	if err != nil {
		if !strings.Contains(err.Error(), "Reference does not exist") {
			log.Printf("[verify] WARNING: failed to delete branch %s on %s/%s: %v", branchName, o.org, repoName, err)
		}
		return
	}
	log.Printf("[verify] cleaned up branch %s on %s/%s", branchName, o.org, repoName)
}
