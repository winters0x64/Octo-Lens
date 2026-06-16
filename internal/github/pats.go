package github

import (
	"context"
	"fmt"
	"os"
	"time"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// rawPAT represents the GitHub API response for a fine-grained PAT.
type rawPAT struct {
	ID    int64 `json:"id"`
	Owner struct {
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	} `json:"owner"`
	RepositorySelection string                       `json:"repository_selection"`
	Permissions         map[string]map[string]string `json:"permissions"`
	AccessGrantedAt     time.Time                    `json:"access_granted_at"`
	TokenExpired        bool                         `json:"token_expired"`
	TokenExpiresAt      *time.Time                   `json:"token_expires_at"`
	TokenLastUsedAt     *time.Time                   `json:"token_last_used_at"`
	TokenName           string                       `json:"token_name"`
}

// rawPATRequest represents a pending PAT request.
type rawPATRequest struct {
	ID    int64 `json:"id"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	RepositorySelection string                       `json:"repository_selection"`
	Permissions         map[string]map[string]string `json:"permissions"`
	CreatedAt           time.Time                    `json:"created_at"`
	TokenExpiresAt      *time.Time                   `json:"token_expires_at"`
	TokenName           string                       `json:"token_name"`
}

// ListApprovedPATs returns all approved fine-grained PATs in the organization.
func (s *GitHubService) ListApprovedPATs(ctx context.Context) ([]models.PATInfo, error) {
	var allPATs []models.PATInfo

	opts := gh.ListOptions{PerPage: 100}
	for {
		url := fmt.Sprintf("orgs/%s/personal-access-tokens?per_page=%d&page=%d", s.org, opts.PerPage, opts.Page)
		req, err := s.client.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating PAT list request: %w", err)
		}

		var raw []rawPAT
		resp, err := s.client.Do(ctx, req, &raw)
		if err != nil {
			return nil, fmt.Errorf("listing PATs: %w", err)
		}

		for _, p := range raw {
			allPATs = append(allPATs, models.PATInfo{
				ID:                  p.ID,
				TokenName:           p.TokenName,
				OwnerLogin:          p.Owner.Login,
				OwnerAvatarURL:      p.Owner.AvatarURL,
				RepositorySelection: p.RepositorySelection,
				Permissions:         mapToPermissions(p.Permissions),
				AccessGrantedAt:     p.AccessGrantedAt,
				TokenExpiresAt:      p.TokenExpiresAt,
				TokenLastUsedAt:     p.TokenLastUsedAt,
				TokenExpired:        p.TokenExpired,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allPATs, nil
}

// ListPATRepositories returns the repositories accessible by a specific PAT.
func (s *GitHubService) ListPATRepositories(ctx context.Context, patID int64) ([]models.RepoInfo, error) {
	var allRepos []models.RepoInfo

	opts := gh.ListOptions{PerPage: 100}
	for {
		url := fmt.Sprintf("orgs/%s/personal-access-tokens/%d/repositories?per_page=%d&page=%d", s.org, patID, opts.PerPage, opts.Page)
		req, err := s.client.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating PAT repos request: %w", err)
		}

		var repos []struct {
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
		}
		resp, err := s.client.Do(ctx, req, &repos)
		if err != nil {
			return nil, fmt.Errorf("listing PAT repositories: %w", err)
		}

		for _, r := range repos {
			allRepos = append(allRepos, models.RepoInfo{
				Name:     r.Name,
				FullName: r.FullName,
				Private:  r.Private,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// fakePATRequests returns hardcoded fake pending PAT requests for local UI development.
// Activated by SEED_FAKE_SSO=true. Never used in production.
func fakePATRequests() []models.PATRequest {
	now := time.Now()
	ptr := func(t time.Time) *time.Time { return &t }
	p := func(name, level string) models.Permission {
		risk := models.RiskLow
		high := map[string]bool{"write": true, "admin": true}
		if high[level] {
			risk = models.RiskHigh
		}
		return models.Permission{Name: name, Level: level, Risk: risk}
	}

	return []models.PATRequest{
		{
			ID: 9001, TokenName: "ci-deploy-prod", OwnerLogin: "madhukar-scapia",
			RepositorySelection: "selected",
			Permissions: []models.Permission{
				p("contents", "write"), p("deployments", "write"), p("actions", "read"),
			},
			CreatedAt:      now.AddDate(0, 0, -2),
			TokenExpiresAt: ptr(now.AddDate(0, 3, 0)),
		},
		{
			ID: 9002, TokenName: "infra-automation", OwnerLogin: "aravind24k",
			RepositorySelection: "all",
			Permissions: []models.Permission{
				p("contents", "write"), p("administration", "write"),
				p("secrets", "write"), p("workflows", "write"),
			},
			CreatedAt:      now.AddDate(0, 0, -1),
			TokenExpiresAt: nil, // no expiry — suspicious
		},
		{
			ID: 9003, TokenName: "analytics-read", OwnerLogin: "sumedh-scapia",
			RepositorySelection: "selected",
			Permissions: []models.Permission{
				p("contents", "read"), p("metadata", "read"),
			},
			CreatedAt:      now.AddDate(0, 0, -3),
			TokenExpiresAt: ptr(now.AddDate(0, 1, 0)),
		},
		{
			ID: 9004, TokenName: "frontend-deploy", OwnerLogin: "laksh-scapia",
			RepositorySelection: "selected",
			Permissions: []models.Permission{
				p("contents", "write"), p("deployments", "write"), p("pages", "write"),
			},
			CreatedAt:      now.AddDate(0, 0, -4),
			TokenExpiresAt: ptr(now.AddDate(0, 2, 0)),
		},
		{
			ID: 9005, TokenName: "org-wide-admin", OwnerLogin: "farhan-scapia",
			RepositorySelection: "all",
			Permissions: []models.Permission{
				p("contents", "write"), p("administration", "write"),
				p("members", "write"), p("organization_administration", "write"),
				p("secrets", "write"), p("workflows", "write"),
			},
			CreatedAt:      now.AddDate(0, 0, 0), // just now — urgent
			TokenExpiresAt: nil,
		},
		{
			ID: 9006, TokenName: "data-pipeline-bot", OwnerLogin: "anuragx7-dev",
			RepositorySelection: "selected",
			Permissions: []models.Permission{
				p("contents", "read"), p("issues", "write"), p("pull_requests", "write"),
			},
			CreatedAt:      now.AddDate(0, 0, -5),
			TokenExpiresAt: ptr(now.AddDate(0, 6, 0)),
		},
	}
}

// ListPendingPATRequests returns pending PAT access requests for the organization.
func (s *GitHubService) ListPendingPATRequests(ctx context.Context) ([]models.PATRequest, error) {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return fakePATRequests(), nil
	}
	var allRequests []models.PATRequest

	opts := gh.ListOptions{PerPage: 100}
	for {
		url := fmt.Sprintf("orgs/%s/personal-access-token-requests?per_page=%d&page=%d", s.org, opts.PerPage, opts.Page)
		req, err := s.client.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating PAT requests request: %w", err)
		}

		var raw []rawPATRequest
		resp, err := s.client.Do(ctx, req, &raw)
		if err != nil {
			return nil, fmt.Errorf("listing PAT requests: %w", err)
		}

		for _, p := range raw {
			allRequests = append(allRequests, models.PATRequest{
				ID:                  p.ID,
				TokenName:           p.TokenName,
				OwnerLogin:          p.Owner.Login,
				RepositorySelection: p.RepositorySelection,
				Permissions:         mapToPermissions(p.Permissions),
				CreatedAt:           p.CreatedAt,
				TokenExpiresAt:      p.TokenExpiresAt,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRequests, nil
}

// ReviewPATRequest approves or denies a pending fine-grained PAT request.
// action must be "approve" or "deny". reason is optional.
func (s *GitHubService) ReviewPATRequest(ctx context.Context, patID int64, action, reason string) error {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return nil // no-op in local dev mode; fake IDs don't exist in GitHub
	}
	body := struct {
		Action string `json:"action"`
		Reason string `json:"reason,omitempty"`
	}{Action: action, Reason: reason}

	url := fmt.Sprintf("orgs/%s/personal-access-token-requests/%d", s.org, patID)
	req, err := s.client.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("creating PAT review request: %w", err)
	}

	_, err = s.client.Do(ctx, req, nil)
	if err != nil {
		return fmt.Errorf("reviewing PAT request: %w", err)
	}

	return nil
}

// RevokePAT revokes an approved fine-grained PAT's access to the organization.
func (s *GitHubService) RevokePAT(ctx context.Context, patID int64) error {
	body := struct {
		Action string `json:"action"`
	}{Action: "revoke"}

	url := fmt.Sprintf("orgs/%s/personal-access-tokens/%d", s.org, patID)
	req, err := s.client.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("creating PAT revoke request: %w", err)
	}

	_, err = s.client.Do(ctx, req, nil)
	if err != nil {
		return fmt.Errorf("revoking PAT: %w", err)
	}

	return nil
}

// mapToPermissions flattens a nested PAT permissions map (category → name → level).
func mapToPermissions(perms map[string]map[string]string) []models.Permission {
	var result []models.Permission
	for _, group := range perms {
		for name, level := range group {
			result = append(result, models.Permission{
				Name:  name,
				Level: level,
				Risk:  models.CategorizePermission(name, level),
			})
		}
	}
	return result
}

// flatMapToPermissions converts a flat name→level map (used by GitHub Apps) to permissions.
func flatMapToPermissions(perms map[string]string) []models.Permission {
	result := make([]models.Permission, 0, len(perms))
	for name, level := range perms {
		result = append(result, models.Permission{
			Name:  name,
			Level: level,
			Risk:  models.CategorizePermission(name, level),
		})
	}
	return result
}

