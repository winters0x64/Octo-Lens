package github

import (
	"context"
	"encoding/base64"
	"strings"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ListWorkflowPermissions fetches the default GITHUB_TOKEN permissions for each repo.
func (s *GitHubService) ListWorkflowPermissions(ctx context.Context, repos []*gh.Repository) ([]models.WorkflowPermission, error) {
	var all []models.WorkflowPermission

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		name := repo.GetName()

		perms, _, err := s.client.Repositories.GetDefaultWorkflowPermissions(ctx, s.org, name)
		if err != nil {
			// Non-fatal: repo may not have Actions enabled
			continue
		}

		risk := models.RiskLow
		defaultPerm := perms.GetDefaultWorkflowPermissions()
		if defaultPerm == "write" {
			risk = models.RiskHigh
		}

		all = append(all, models.WorkflowPermission{
			RepoName:          name,
			DefaultPermission: defaultPerm,
			CanApprovePRs:     perms.GetCanApprovePullRequestReviews(),
			Risk:              risk,
		})

		if err := s.checkRateLimit(ctx); err != nil {
			return all, err
		}
	}

	return all, nil
}

// AuditWorkflowFiles scans .github/workflows/ in each repo for permission and pinning issues.
func (s *GitHubService) AuditWorkflowFiles(ctx context.Context, repos []*gh.Repository) ([]models.WorkflowFile, error) {
	var all []models.WorkflowFile

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		name := repo.GetName()

		// List workflow directory contents
		_, dirContent, _, err := s.client.Repositories.GetContents(
			ctx, s.org, name, ".github/workflows", nil,
		)
		if err != nil {
			// No workflows directory — skip
			continue
		}

		for _, file := range dirContent {
			fname := file.GetName()
			if !strings.HasSuffix(fname, ".yml") && !strings.HasSuffix(fname, ".yaml") {
				continue
			}

			wf := s.auditSingleWorkflow(ctx, name, fname, file.GetPath())
			all = append(all, wf)
		}

		if err := s.checkRateLimit(ctx); err != nil {
			return all, err
		}
	}

	return all, nil
}

func (s *GitHubService) auditSingleWorkflow(ctx context.Context, repo, fileName, path string) models.WorkflowFile {
	wf := models.WorkflowFile{
		RepoName: repo,
		FileName: fileName,
		Path:     path,
		Risk:     models.RiskLow,
	}

	// Fetch file content
	fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.org, repo, path, nil)
	if err != nil || fileContent == nil {
		wf.Permissions = "unknown"
		return wf
	}

	content, err := decodeContent(fileContent)
	if err != nil {
		wf.Permissions = "unknown"
		return wf
	}

	// Simple YAML analysis (no full parser to avoid dependencies)
	wf.Permissions = analyzePermissions(content)
	wf.UnpinnedActions = findUnpinnedActions(content)
	wf.HasPinnedActions = len(wf.UnpinnedActions) == 0

	// Determine risk
	if wf.Permissions == "write-all" || wf.Permissions == "not set" {
		wf.Risk = models.RiskHigh
	} else if len(wf.UnpinnedActions) > 0 {
		wf.Risk = models.RiskMedium
	}

	return wf
}

func decodeContent(fc *gh.RepositoryContent) (string, error) {
	if fc.Content != nil {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(*fc.Content, "\n", ""))
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return "", nil
}

// analyzePermissions does simple text analysis of workflow YAML for top-level permissions.
func analyzePermissions(content string) string {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level permissions block
		if strings.HasPrefix(trimmed, "permissions:") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "permissions:"))
			if value == "{}" || value == "read-all" {
				return "read-all"
			}
			if value == "write-all" {
				return "write-all"
			}
			if value == "" {
				// Multi-line permissions block — generally fine (explicit)
				return "explicit"
			}
			return value
		}
	}

	return "not set"
}

// findUnpinnedActions finds uses: directives that reference tags instead of SHA commits.
func findUnpinnedActions(content string) []string {
	var unpinned []string
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- uses:") && !strings.HasPrefix(trimmed, "uses:") {
			continue
		}

		// Extract the action reference
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 2 {
			continue
		}
		ref := strings.TrimSpace(parts[1])

		// Skip local actions (./path)
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}

		// Check if pinned to SHA (40 hex chars after @)
		atIdx := strings.LastIndex(ref, "@")
		if atIdx == -1 {
			unpinned = append(unpinned, ref)
			continue
		}

		sha := ref[atIdx+1:]
		if len(sha) != 40 || !isHex(sha) {
			unpinned = append(unpinned, ref)
		}
	}

	return unpinned
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
