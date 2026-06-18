package github

import (
	"context"
	"fmt"
	"os"
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

// fakeSSOCredentials returns hardcoded fake SSO credentials for local UI development.
// Activated by setting SEED_FAKE_SSO=true in the environment. Never used in production.
func fakeSSOCredentials() []models.SSOCredential {
	now := time.Now()
	ptr := func(t time.Time) *time.Time { return &t }
	allAdminScopes := []string{
		"admin:enterprise", "admin:gpg_key", "admin:org", "admin:org_hook",
		"admin:public_key", "admin:repo_hook", "admin:ssh_signing_key",
		"audit_log", "codespace", "copilot", "delete:packages", "delete_repo",
		"gist", "notifications", "project", "repo", "user", "workflow",
		"write:discussion", "write:network_configurations", "write:packages",
	}
	repoOnly := []string{"repo"}
	repoWorkflow := []string{"gist", "read:org", "read:user", "repo", "user:email", "workflow"}

	return []models.SSOCredential{
		// Full-admin classic PATs (high risk, no expiry)
		{
			CredentialID: 1001, Login: "omar-hassan", CredentialType: "personal access token",
			TokenLastEight: "V93nJ4Sr", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(0, -4, 0),
			CredentialAccessedAt:   ptr(now.AddDate(0, 0, -4)),
			AuthorizedCredentialExpAt: ptr(now.AddDate(0, 8, 0)),
		},
		{
			CredentialID: 1002, Login: "omar-hassan", CredentialType: "personal access token",
			TokenLastEight: "aF2z8Qud", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(0, -3, -14),
			CredentialAccessedAt:   ptr(now.AddDate(0, -6, 0)),
			// already expired
			AuthorizedCredentialExpAt: ptr(now.AddDate(0, -6, 0)),
		},
		{
			CredentialID: 1003, Login: "morgan-davis", CredentialType: "personal access token",
			TokenLastEight: "7d1Wpp72", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(0, -1, 0),
			// never accessed, never expires
		},
		{
			CredentialID: 1004, Login: "morgan-davis", CredentialType: "personal access token",
			TokenLastEight: "LS2yrJQn", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(0, 0, -7),
			// never accessed, never expires
		},
		{
			CredentialID: 1005, Login: "casey-wilson", CredentialType: "personal access token",
			TokenLastEight: "fB0YkZHb", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(-1, 0, 0),
			CredentialAccessedAt:   ptr(now.AddDate(0, -1, -5)),
		},
		{
			CredentialID: 1006, Login: "drew-martinez", CredentialType: "personal access token",
			TokenLastEight: "li3ois9H", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(-1, 0, 0),
			CredentialAccessedAt:   ptr(now.AddDate(0, -2, -8)),
			AuthorizedCredentialExpAt: ptr(now.AddDate(0, 1, 13)),
		},
		{
			CredentialID: 1007, Login: "jordan-smith", CredentialType: "personal access token",
			TokenLastEight: "IR2WgMGu", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(0, -2, 0),
			// never accessed, no expiry
		},
		{
			CredentialID: 1008, Login: "blake-johnson", CredentialType: "personal access token",
			TokenLastEight: "xM20Ab6J", Scopes: allAdminScopes,
			CredentialAuthorizedAt: now.AddDate(0, 0, -14),
			CredentialAccessedAt:   ptr(now.AddDate(0, 0, -6)),
			AuthorizedCredentialExpAt: ptr(now.AddDate(0, 2, 15)),
		},
		// Scoped classic PATs (medium risk)
		{
			CredentialID: 1009, Login: "sam-patel", CredentialType: "personal access token",
			TokenLastEight: "O24FOSlY", Scopes: repoWorkflow,
			CredentialAuthorizedAt: now.AddDate(-1, 0, 0),
			CredentialAccessedAt:   ptr(now.AddDate(0, 0, -4)),
		},
		{
			CredentialID: 1010, Login: "quinn-brown", CredentialType: "personal access token",
			TokenLastEight: "nu20Nx5g", Scopes: repoOnly,
			CredentialAuthorizedAt: now.AddDate(0, 0, -13),
			CredentialAccessedAt:   ptr(now.AddDate(0, 0, -2)),
			AuthorizedCredentialExpAt: ptr(now.AddDate(0, 0, 19)),
		},
		{
			CredentialID: 1011, Login: "jordan-smith", CredentialType: "personal access token",
			TokenLastEight: "cB4KjMhf", Scopes: repoOnly,
			CredentialAuthorizedAt: now.AddDate(-1, 0, 0),
			CredentialAccessedAt:   ptr(now.AddDate(0, 0, -6)),
		},
		{
			CredentialID: 1012, Login: "avery-garcia", CredentialType: "personal access token",
			TokenLastEight: "fM1zQ5rl", Scopes: repoWorkflow,
			CredentialAuthorizedAt: now.AddDate(0, -2, -13),
			CredentialAccessedAt:   ptr(now.AddDate(0, 0, 0)),
		},
		// SSH keys
		{
			CredentialID: 2001, Login: "omar-hassan", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "mac pro m4",
			Fingerprint:               "SHA256:S8Xkv+FURGhUnggmb0wSBaRBOb1opC9uwThqz3Ce8iY",
			CredentialAuthorizedAt:    now.AddDate(0, -4, -2),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -13)),
		},
		{
			CredentialID: 2002, Login: "alex-chen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "arm-builder-machine",
			Fingerprint:               "SHA256:JflOab+WLzTKgT+sH6mBmu3urtABE/53UtPlaacasBI",
			CredentialAuthorizedAt:    now.AddDate(-1, 0, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -7)),
		},
		{
			CredentialID: 2003, Login: "alex-chen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "github-prod-jumpbox",
			Fingerprint:               "SHA256:jykiq0/fT6gKndmDOIJLk1kz4JmBRGvO3JAwxJfX92w",
			CredentialAuthorizedAt:    now.AddDate(0, -1, -7),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -27)),
		},
		{
			CredentialID: 2004, Login: "kendall-moore", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "pr-review-bot",
			Fingerprint:               "SHA256:LqcJqD0o//CAPPf79iSjwkV61uNPhJP/bH4Gu7e6csM",
			CredentialAuthorizedAt:    now.AddDate(0, -3, -25),
			CredentialAccessedAt:      ptr(now.AddDate(0, -3, -11)),
		},
		{
			CredentialID: 2005, Login: "lee-chen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "AWS CI key",
			Fingerprint:               "SHA256:qzQJfWVvvYye5jN+b64ZxFDh14wS3KWpPv8EfiMxV6s",
			CredentialAuthorizedAt:    now.AddDate(-1, 0, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -5)),
		},
		{
			CredentialID: 2006, Login: "nina-vol", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "Amplify Service",
			Fingerprint:               "SHA256:342WsdEcYbsL7+BW5WEN9/qjyLMfxiQZ1FX+TLylV7k",
			CredentialAuthorizedAt:    now.AddDate(0, -5, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -5)),
		},
		{
			CredentialID: 2007, Login: "reese-taylor", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "SSH",
			Fingerprint:               "SHA256:U0MTBbS1ZCczU6YcSPJYUvVAC3bv6U0psHc7ssaqMP8",
			CredentialAuthorizedAt:    now.AddDate(0, -5, -10),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -7)),
		},
		{
			CredentialID: 2008, Login: "priya-nair", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "Orders Dashboard SSH Key",
			Fingerprint:               "SHA256:TuV0vBIWUPUYIkWkLfClXdtMKiWhQH3jv8Ekodw2PgQ",
			CredentialAuthorizedAt:    now.AddDate(0, -1, -13),
			CredentialAccessedAt:      ptr(now.AddDate(0, -1, -13)),
		},
		// More SSH keys — personal laptops
		{
			CredentialID: 2009, Login: "sam-patel", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "spitha-flutter",
			Fingerprint:               "SHA256:NN1VdoaZffJiGxXzHnYx1QRAq0o2JnCPhaFPF4IdWVs",
			CredentialAuthorizedAt:    now.AddDate(-1, 0, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -9)),
		},
		{
			CredentialID: 2010, Login: "sam-patel", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "data-pipeline-server",
			Fingerprint:               "SHA256:RcJ9S2W8nx7fu8i8KIO7O2wxtZbBC5NBuD1NAlyJjNo",
			CredentialAuthorizedAt:    now.AddDate(0, -3, -22),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -13)),
		},
		{
			CredentialID: 2011, Login: "riley-kim", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "work-laptop-m4",
			Fingerprint:               "SHA256:i2HcQRHVXAqHfXnk0DxKhvR6aiQfKVS46jNqtEY8rQo",
			CredentialAuthorizedAt:    now.AddDate(-1, 0, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, 0)),
		},
		{
			CredentialID: 2012, Login: "jamie-lee", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "Laptop Key",
			Fingerprint:               "SHA256:I6vhcZEVBrgJWK+ZabIbpFc4eP+WSt5ZqyJFbdVzcrY",
			CredentialAuthorizedAt:    now.AddDate(-1, 0, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -2)),
		},
		{
			CredentialID: 2013, Login: "jamie-lee", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "data-platform",
			Fingerprint:               "SHA256:u++YB21LnxsQmCfXnJ8aLy3+vvtmtlczrHjIQLzy9Wo",
			CredentialAuthorizedAt:    now.AddDate(0, -5, -10),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -2)),
		},
		{
			CredentialID: 2014, Login: "alex-chen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "cdp-console-prod-git-access",
			Fingerprint:               "SHA256:S9dlHiSyp+vFU78Vi93LnHk2x3o6TIwEZN18P9oz9nw",
			CredentialAuthorizedAt:    now.AddDate(0, -1, -24),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -7)),
		},
		{
			CredentialID: 2015, Login: "taylor-nguyen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "Anurag Mac",
			Fingerprint:               "SHA256:EjhZUPJpE2P3xwVfLzLT88197+coP9A5T2qd7GIHC0c",
			CredentialAuthorizedAt:    now.AddDate(0, -3, -4),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -7)),
		},
		{
			CredentialID: 2016, Login: "taylor-nguyen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "macmini",
			Fingerprint:               "SHA256:XAx7h8zrCo4mHlLmfcxBNv/vggCM4ROp1/bd0yWpVoM",
			CredentialAuthorizedAt:    now.AddDate(0, -1, -3),
			CredentialAccessedAt:      ptr(now.AddDate(0, 0, -3)),
		},
		{
			CredentialID: 2017, Login: "taylor-nguyen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "iMAC",
			Fingerprint:               "SHA256:Nlqy8pogC5mkJ1IafTamxJWFFLUv/Fl9THwmC+4PMUI",
			CredentialAuthorizedAt:    now.AddDate(0, -2, -8),
			// never accessed
		},
		// Stale / never accessed keys
		{
			CredentialID: 2018, Login: "sage-anderson", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "m1 mac prev rahin",
			Fingerprint:               "SHA256:df6fbkblxzJiDG4jjwrGQoa/vYQ30+zD9Hp6G72S96w",
			CredentialAuthorizedAt:    now.AddDate(0, -5, -8),
			CredentialAccessedAt:      ptr(now.AddDate(0, -5, -23)), // last used ~6 months ago
		},
		{
			CredentialID: 2019, Login: "robin-thomas", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "work-laptop",
			Fingerprint:               "SHA256:Z0NvuzVMroclu8aReQ1Cydt3Ju5Dnm/phPBumvNIJio",
			CredentialAuthorizedAt:    now.AddDate(0, -5, -9),
			CredentialAccessedAt:      ptr(now.AddDate(0, -3, -19)),
		},
		{
			CredentialID: 2020, Login: "hayden-jackson", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "Nisitha GitHub",
			Fingerprint:               "SHA256:NZ/GlifrxFXvtjV5vtY3HB9TF7Jh3rcKbk4PNGXE9WM",
			CredentialAuthorizedAt:    now.AddDate(0, -4, -7),
			// never accessed
		},
		{
			CredentialID: 2021, Login: "priya-nair", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "Anil Git",
			Fingerprint:               "SHA256:ll9czwbQ1QhjIKaVQyJH5EiM49k57mHVf3bARxLvb4s",
			CredentialAuthorizedAt:    now.AddDate(0, -4, -18),
			CredentialAccessedAt:      ptr(now.AddDate(0, -4, -18)),
		},
		{
			CredentialID: 2022, Login: "priya-nair", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "EC2 Git Key",
			Fingerprint:               "SHA256:Id6MWKNaMnwTe0ddFjqpSfNEW7uGKgFivmWoXALGwo8",
			CredentialAuthorizedAt:    now.AddDate(0, -3, -13),
			CredentialAccessedAt:      ptr(now.AddDate(0, -3, -13)),
		},
		// Service / CI keys
		{
			CredentialID: 2023, Login: "soura-ctrl", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "prod_changes",
			Fingerprint:               "SHA256:mENazjMyJ6HnXqOsHX+kHoSjYYJ0OXgzXxWxi7v8d6s",
			CredentialAuthorizedAt:    now.AddDate(0, -2, -8),
			CredentialAccessedAt:      ptr(now.AddDate(0, -1, -25)),
		},
		{
			CredentialID: 2024, Login: "peyton-white", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "vendor-ci-ssh",
			Fingerprint:               "SHA256:g0/ltzkVb7q4G61clCFK5eh0fuLD6HpZ76iRDsnbAbY",
			CredentialAuthorizedAt:    now.AddDate(0, -4, -5),
			// not accessed since authorized
		},
		{
			CredentialID: 2025, Login: "alex-chen", CredentialType: "SSH key",
			AuthorizedCredentialTitle: "fed-mobile-sandbox",
			Fingerprint:               "SHA256:h/aXuW5uu+aZA3X4F2mwFZzQEpxNFfWsWNyZRbfRTdc",
			CredentialAuthorizedAt:    now.AddDate(-1, 0, 0),
			CredentialAccessedAt:      ptr(now.AddDate(0, -6, -20)), // stale CI key
		},
	}
}

// RevokeSSO revokes a SAML SSO credential authorization from the organization.
// GitHub API: DELETE /orgs/{org}/credential-authorizations/{credential_id}
func (s *GitHubService) RevokeSSO(ctx context.Context, credentialID int64) error {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return nil // no-op in local dev mode
	}
	url := fmt.Sprintf("orgs/%s/credential-authorizations/%d", s.org, credentialID)
	req, err := s.client.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("creating SSO revoke request: %w", err)
	}
	_, err = s.client.Do(ctx, req, nil)
	if err != nil {
		return fmt.Errorf("revoking SSO credential: %w", err)
	}
	return nil
}

// ListSSOCredentials returns all SAML SSO authorized credentials in the organization.
// This includes classic PATs, fine-grained PATs, and SSH keys that users have authorized for SSO.
// Requires the org to have SAML SSO enabled (GitHub Enterprise Cloud).
func (s *GitHubService) ListSSOCredentials(ctx context.Context) ([]models.SSOCredential, error) {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return fakeSSOCredentials(), nil
	}
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
