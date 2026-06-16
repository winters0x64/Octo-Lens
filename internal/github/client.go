package github

import (
	"github.com/google/go-github/v68/github"
)

// GitHubService wraps the GitHub API client for organization-level queries.
type GitHubService struct {
	client    *github.Client
	appClient *github.Client // app-level JWT for suspend/unsuspend
	org       string
}

// NewGitHubService creates a new GitHubService for the given organization.
func NewGitHubService(client *github.Client, org string) *GitHubService {
	return &GitHubService{
		client: client,
		org:    org,
	}
}

// SetAppClient sets an app-level JWT client for operations that require it.
func (s *GitHubService) SetAppClient(c *github.Client) {
	s.appClient = c
}
