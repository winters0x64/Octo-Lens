package github

import (
	"context"
	"fmt"
	"time"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// rawSSOCredential represents the GitHub API response for an SSO credential authorization.
type rawSSOCredential struct {
	CredentialID              int64      `json:"credential_id"`
	Login                     string     `json:"login"`
	CredentialType            string     `json:"credential_type"`
	TokenLastEight            string     `json:"token_last_eight"`
	CredentialAuthorizedAt    time.Time  `json:"credential_authorized_at"`
	CredentialAccessedAt      *time.Time `json:"credential_accessed_at"`
	AuthorizedCredentialID    *int64     `json:"authorized_credential_id"`
	AuthorizedCredentialTitle string     `json:"authorized_credential_title"`
	AuthorizedCredentialNote  string     `json:"authorized_credential_note"`
	AuthorizedCredentialExpAt *time.Time `json:"authorized_credential_expires_at"`
	Scopes                    []string   `json:"scopes"`
	Fingerprint               string     `json:"fingerprint"`
}

// ListSSOCredentials returns all SAML SSO authorized credentials in the organization.
// This includes classic PATs, fine-grained PATs, and SSH keys that users have authorized for SSO.
// Requires the org to have SAML SSO enabled (GitHub Enterprise Cloud).
func (s *GitHubService) ListSSOCredentials(ctx context.Context) ([]models.SSOCredential, error) {
	var allCreds []models.SSOCredential

	opts := gh.ListOptions{PerPage: 100}
	for {
		url := fmt.Sprintf("orgs/%s/credential-authorizations?per_page=%d&page=%d", s.org, opts.PerPage, opts.Page)
		req, err := s.client.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating SSO credentials request: %w", err)
		}

		var raw []rawSSOCredential
		resp, err := s.client.Do(ctx, req, &raw)
		if err != nil {
			return nil, fmt.Errorf("listing SSO credentials: %w", err)
		}

		for _, c := range raw {
			allCreds = append(allCreds, models.SSOCredential{
				CredentialID:              c.CredentialID,
				Login:                     c.Login,
				CredentialType:            c.CredentialType,
				TokenLastEight:            c.TokenLastEight,
				CredentialAuthorizedAt:    c.CredentialAuthorizedAt,
				CredentialAccessedAt:      c.CredentialAccessedAt,
				AuthorizedCredentialTitle: c.AuthorizedCredentialTitle,
				AuthorizedCredentialNote:  c.AuthorizedCredentialNote,
				AuthorizedCredentialExpAt: c.AuthorizedCredentialExpAt,
				Scopes:                    c.Scopes,
				Fingerprint:              c.Fingerprint,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allCreds, nil
}
