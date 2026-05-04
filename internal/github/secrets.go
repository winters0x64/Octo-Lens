package github

import (
	"context"
	"fmt"
	"time"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ListOrgSecrets returns all organization-level Actions secrets.
func (s *GitHubService) ListOrgSecrets(ctx context.Context) ([]models.OrgSecret, error) {
	var all []models.OrgSecret

	opts := gh.ListOptions{PerPage: 100}
	for {
		secrets, resp, err := s.client.Actions.ListOrgSecrets(ctx, s.org, &opts)
		if err != nil {
			return nil, fmt.Errorf("listing org secrets: %w", err)
		}

		for _, sec := range secrets.Secrets {
			risk := models.RiskLow
			if sec.Visibility == "all" {
				risk = models.RiskHigh
			} else if sec.Visibility == "private" {
				risk = models.RiskMedium
			}

			all = append(all, models.OrgSecret{
				Name:       sec.Name,
				Scope:      "org",
				Visibility: sec.Visibility,
				CreatedAt:  sec.CreatedAt.Time,
				UpdatedAt:  sec.UpdatedAt.Time,
				Risk:       risk,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return all, nil
}

// ListRepoSecrets returns all repository-level Actions secrets for a given repo.
func (s *GitHubService) ListRepoSecrets(ctx context.Context, repo string) ([]models.OrgSecret, error) {
	var all []models.OrgSecret

	opts := gh.ListOptions{PerPage: 100}
	for {
		secrets, resp, err := s.client.Actions.ListRepoSecrets(ctx, s.org, repo, &opts)
		if err != nil {
			return nil, fmt.Errorf("listing repo secrets for %s: %w", repo, err)
		}

		for _, sec := range secrets.Secrets {
			all = append(all, models.OrgSecret{
				Name:      sec.Name,
				Scope:     "repo",
				RepoName:  repo,
				CreatedAt: sec.CreatedAt.Time,
				UpdatedAt: sec.UpdatedAt.Time,
				Risk:      models.RiskLow,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return all, nil
}

// ListEnvironmentSecrets returns secrets for a specific environment in a repo.
func (s *GitHubService) ListEnvironmentSecrets(ctx context.Context, repoID int64, repoName, envName string) ([]models.OrgSecret, error) {
	var all []models.OrgSecret

	opts := gh.ListOptions{PerPage: 100}
	for {
		secrets, resp, err := s.client.Actions.ListEnvSecrets(ctx, int(repoID), envName, &opts)
		if err != nil {
			return nil, fmt.Errorf("listing env secrets for %s/%s: %w", repoName, envName, err)
		}

		for _, sec := range secrets.Secrets {
			all = append(all, models.OrgSecret{
				Name:      sec.Name,
				Scope:     "environment",
				RepoName:  repoName,
				EnvName:   envName,
				CreatedAt: sec.CreatedAt.Time,
				UpdatedAt: sec.UpdatedAt.Time,
				Risk:      models.RiskLow,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return all, nil
}

// ListAllSecrets gathers org-level secrets and per-repo + per-environment secrets.
func (s *GitHubService) ListAllSecrets(ctx context.Context, repos []*gh.Repository) ([]models.OrgSecret, error) {
	var allSecrets []models.OrgSecret

	// 1. Org-level secrets
	orgSecrets, err := s.ListOrgSecrets(ctx)
	if err != nil {
		return nil, err
	}
	allSecrets = append(allSecrets, orgSecrets...)

	// 2. Per-repo secrets and environment secrets
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		name := repo.GetName()

		repoSecrets, err := s.ListRepoSecrets(ctx, name)
		if err != nil {
			// Non-fatal: might lack permission on some repos
			continue
		}
		allSecrets = append(allSecrets, repoSecrets...)

		// Environment secrets
		envs, _, err := s.client.Repositories.ListEnvironments(ctx, s.org, name, &gh.EnvironmentListOptions{})
		if err != nil || envs == nil {
			continue
		}
		for _, env := range envs.Environments {
			envSecrets, err := s.ListEnvironmentSecrets(ctx, repo.GetID(), name, env.GetName())
			if err != nil {
				continue
			}
			allSecrets = append(allSecrets, envSecrets...)
		}

		// Rate limit awareness
		if err := s.checkRateLimit(ctx); err != nil {
			return allSecrets, err
		}
	}

	// Mark stale secrets (not updated in 365 days)
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	for i := range allSecrets {
		if allSecrets[i].UpdatedAt.Before(oneYearAgo) {
			if allSecrets[i].Risk == models.RiskLow {
				allSecrets[i].Risk = models.RiskMedium
			}
		}
	}

	return allSecrets, nil
}

func (s *GitHubService) checkRateLimit(ctx context.Context) error {
	limits, _, err := s.client.RateLimit.Get(ctx)
	if err != nil {
		return nil // non-fatal
	}
	if limits.Core.Remaining < 100 {
		sleepUntil := time.Until(limits.Core.Reset.Time)
		if sleepUntil > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepUntil):
			}
		}
	}
	return nil
}
