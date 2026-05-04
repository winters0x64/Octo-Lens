package github

import (
	"context"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ListAllDeployKeys enumerates deploy keys across all repositories.
func (s *GitHubService) ListAllDeployKeys(ctx context.Context, repos []*gh.Repository) ([]models.DeployKey, error) {
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
