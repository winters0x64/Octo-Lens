package github

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v68/github"
)

// ListOrgRepos returns all non-archived repositories in the organization.
func (s *GitHubService) ListOrgRepos(ctx context.Context) ([]*gh.Repository, error) {
	repos, err := Paginate(ctx, func(opts gh.ListOptions) ([]*gh.Repository, *gh.Response, error) {
		repos, resp, err := s.client.Repositories.ListByOrg(ctx, s.org, &gh.RepositoryListByOrgOptions{
			Type:        "all",
			ListOptions: opts,
		})
		return repos, resp, err
	})
	if err != nil {
		return nil, fmt.Errorf("listing org repos: %w", err)
	}
	return repos, nil
}
