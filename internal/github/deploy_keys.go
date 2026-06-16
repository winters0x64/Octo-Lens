package github

import (
	"context"
	"fmt"
	"os"
	"time"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// fakeDeployKeys returns hardcoded fake deploy keys for local UI development.
// Activated by SEED_FAKE_SSO=true. Never used in production.
func fakeDeployKeys() []models.DeployKey {
	now := time.Now()
	ptr := func(t time.Time) *time.Time { return &t }

	return []models.DeployKey{
		// Read-write keys (high risk) — CI/CD machines
		{
			ID: 3001, Title: "prod-deploy-jenkins", RepoName: "scapia-backend",
			ReadOnly: false, AddedBy: "madhukar-scapia",
			CreatedAt: now.AddDate(-1, -2, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -1)),
			Risk:      models.RiskHigh,
		},
		{
			ID: 3002, Title: "github-actions-deploy", RepoName: "scapia-frontend",
			ReadOnly: false, AddedBy: "laksh-scapia",
			CreatedAt: now.AddDate(0, -8, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -3)),
			Risk:      models.RiskHigh,
		},
		{
			ID: 3003, Title: "aws-ec2-cicd", RepoName: "infra-terraform",
			ReadOnly: false, AddedBy: "aravind24k",
			CreatedAt: now.AddDate(-1, 0, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -7)),
			Risk:      models.RiskHigh,
		},
		{
			ID: 3004, Title: "buildkite-agent-prod", RepoName: "payments-service",
			ReadOnly: false, AddedBy: "sumedh-scapia",
			CreatedAt: now.AddDate(0, -5, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -2)),
			Risk:      models.RiskHigh,
		},
		// Stale read-write — no longer used
		{
			ID: 3005, Title: "old-laptop-arun", RepoName: "scapia-backend",
			ReadOnly: false, AddedBy: "arun-scapia",
			CreatedAt: now.AddDate(-2, 0, 0),
			LastUsed:  ptr(now.AddDate(-1, -3, 0)), // 15 months stale
			Risk:      models.RiskHigh,
		},
		{
			ID: 3006, Title: "ci-deploy-deprecated", RepoName: "card-service",
			ReadOnly: false, AddedBy: "",
			CreatedAt: now.AddDate(-1, -6, 0),
			LastUsed:  nil, // never used
			Risk:      models.RiskHigh,
		},
		// Read-only keys — monitoring, read CI
		{
			ID: 3007, Title: "grafana-source-sync", RepoName: "scapia-frontend",
			ReadOnly: true, AddedBy: "madhukar-scapia",
			CreatedAt: now.AddDate(0, -3, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -1)),
			Risk:      models.RiskLow,
		},
		{
			ID: 3008, Title: "read-only-ci-checker", RepoName: "payments-service",
			ReadOnly: true, AddedBy: "anuragx7-dev",
			CreatedAt: now.AddDate(0, -6, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -5)),
			Risk:      models.RiskLow,
		},
		{
			ID: 3009, Title: "sentry-release-tracker", RepoName: "card-service",
			ReadOnly: true, AddedBy: "sumedh-scapia",
			CreatedAt: now.AddDate(0, -4, -10),
			LastUsed:  ptr(now.AddDate(0, 0, -2)),
			Risk:      models.RiskLow,
		},
		{
			ID: 3010, Title: "datadog-apm-sync", RepoName: "infra-terraform",
			ReadOnly: true, AddedBy: "aravind24k",
			CreatedAt: now.AddDate(-1, 0, 0),
			LastUsed:  ptr(now.AddDate(0, -7, 0)), // stale read-only
			Risk:      models.RiskLow,
		},
		// Unknown origin — no added_by
		{
			ID: 3011, Title: "deploy-key-1", RepoName: "scapia-backend",
			ReadOnly: false, AddedBy: "",
			CreatedAt: now.AddDate(0, -10, 0),
			LastUsed:  ptr(now.AddDate(0, -2, 0)),
			Risk:      models.RiskHigh,
		},
		{
			ID: 3012, Title: "ssh-key-prod", RepoName: "notification-service",
			ReadOnly: false, AddedBy: "",
			CreatedAt: now.AddDate(-1, -1, 0),
			LastUsed:  ptr(now.AddDate(0, 0, -14)),
			Risk:      models.RiskHigh,
		},
	}
}

// DeleteDeployKey removes a deploy key from a repository.
func (s *GitHubService) DeleteDeployKey(ctx context.Context, repoName string, keyID int64) error {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return nil
	}
	_, err := s.client.Repositories.DeleteKey(ctx, s.org, repoName, keyID)
	if err != nil {
		return fmt.Errorf("deleting deploy key %d from %s: %w", keyID, repoName, err)
	}
	return nil
}

// ListAllDeployKeys enumerates deploy keys across all repositories.
func (s *GitHubService) ListAllDeployKeys(ctx context.Context, repos []*gh.Repository) ([]models.DeployKey, error) {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return fakeDeployKeys(), nil
	}
	var allKeys []models.DeployKey

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		name := repo.GetName()

		keys, err := Paginate(ctx, func(opts gh.ListOptions) ([]*gh.Key, *gh.Response, error) {
			keys, resp, err := s.client.Repositories.ListKeys(ctx, s.org, name, &opts)
			return keys, resp, err
		})
		if err != nil {
			// Non-fatal: might lack permission on some repos
			continue
		}

		for _, k := range keys {
			risk := models.RiskLow
			if !k.GetReadOnly() {
				risk = models.RiskHigh
			}

			dk := models.DeployKey{
				ID:        k.GetID(),
				Title:     k.GetTitle(),
				RepoName:  name,
				ReadOnly:  k.GetReadOnly(),
				Risk:      risk,
			}
			if k.CreatedAt != nil {
				dk.CreatedAt = k.CreatedAt.Time
			}
			if k.LastUsed != nil {
				t := k.LastUsed.Time
				dk.LastUsed = &t
			}
			if k.AddedBy != nil {
				dk.AddedBy = *k.AddedBy
			}

			allKeys = append(allKeys, dk)
		}

		if err := s.checkRateLimit(ctx); err != nil {
			return allKeys, err
		}
	}

	return allKeys, nil
}
