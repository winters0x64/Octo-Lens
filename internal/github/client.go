package github

import (
	"github.com/google/go-github/v68/github"
)

// GitHubService wraps the GitHub API client for organization-level queries.
type GitHubService struct {
	client *github.Client
	org    string
}

// NewGitHubService creates a new GitHubService for the given organization.
func NewGitHubService(client *github.Client, org string) *GitHubService {
	return &GitHubService{
		client: client,
		org:    org,
	}
}
