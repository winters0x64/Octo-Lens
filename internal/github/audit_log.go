package github

import (
	"context"
	"fmt"
	"time"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// rawAuditEntry represents the GitHub audit log API response.
type rawAuditEntry struct {
	Action       string  `json:"action"`
	Actor        string  `json:"actor"`
	CreatedAt    float64 `json:"created_at"`  // Unix timestamp in ms
	Timestamp    float64 `json:"@timestamp"`  // Alternative timestamp
	TokenID      int64   `json:"token_id"`
	User         string  `json:"user"`
	Data         map[string]any `json:"data"`
}

// ListAuditLog fetches PAT-related audit log events.
// Only available on GitHub Enterprise Cloud.
func (s *GitHubService) ListAuditLog(ctx context.Context) ([]models.AuditLogEntry, error) {
	var allEntries []models.AuditLogEntry

	phrases := []string{
		"action:personal_access_token.create",
		"action:personal_access_token.destroy",
		"action:personal_access_token.access_granted",
		"action:personal_access_token.access_denied",
		"action:personal_access_token.access_revoked",
		"action:personal_access_token.request_created",
	}

	for _, phrase := range phrases {
		entries, err := s.fetchAuditEntries(ctx, phrase)
		if err != nil {
			// Non-fatal: audit log not available on non-Enterprise orgs
			return nil, err
		}
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

// FetchSecretCreators queries the audit log for secret creation events and
// returns a map of secret name → creator login. Keys use the format:
//   "org:SECRET_NAME"         for org-level secrets
//   "repo/REPO:SECRET_NAME"   for repo-level secrets
// Only available on GitHub Enterprise Cloud; returns empty map otherwise.
func (s *GitHubService) FetchSecretCreators(ctx context.Context) (map[string]string, error) {
	creators := make(map[string]string)

	phrases := []string{
		"action:org.actions_secret_created",
		"action:repo.actions_secret_created",
		"action:environment.create_actions_secret",
	}

	for _, phrase := range phrases {
		url := fmt.Sprintf("orgs/%s/audit-log?phrase=%s&per_page=100&include=api", s.org, phrase)
		req, err := s.client.NewRequest("GET", url, nil)
		if err != nil {
			return creators, nil // non-fatal
		}

		var raw []struct {
			Action string `json:"action"`
			Actor  string `json:"actor"`
			Repo   string `json:"repo"`
			// GitHub returns the secret name in different fields depending on scope
			SecretName    string `json:"secret_name"`
			Name          string `json:"name"`
		}
		if _, err := s.client.Do(ctx, req, &raw); err != nil {
			return creators, nil // non-fatal: audit log not on non-Enterprise orgs
		}

		for _, e := range raw {
			name := e.SecretName
			if name == "" {
				name = e.Name
			}
			if name == "" || e.Actor == "" {
				continue
			}
			var key string
			if e.Repo != "" {
				// repo is "org/repo-name"
				parts := e.Repo
				if idx := len(s.org) + 1; idx < len(parts) {
					parts = parts[idx:]
				}
				key = "repo/" + parts + ":" + name
			} else {
				key = "org:" + name
			}
			// Keep the most recent actor (first entry is newest in audit log)
			if _, exists := creators[key]; !exists {
				creators[key] = e.Actor
			}
		}
	}

	return creators, nil
}

func (s *GitHubService) fetchAuditEntries(ctx context.Context, phrase string) ([]models.AuditLogEntry, error) {
	var entries []models.AuditLogEntry

	opts := gh.ListOptions{PerPage: 100}
	url := fmt.Sprintf("orgs/%s/audit-log?phrase=%s&per_page=%d&include=api", s.org, phrase, opts.PerPage)

	req, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating audit log request: %w", err)
	}

	var raw []rawAuditEntry
	_, err = s.client.Do(ctx, req, &raw)
	if err != nil {
		return nil, fmt.Errorf("fetching audit log: %w", err)
	}

	for _, e := range raw {
		ts := e.CreatedAt
		if ts == 0 {
			ts = e.Timestamp
		}
		createdAt := time.Unix(int64(ts/1000), 0)

		entries = append(entries, models.AuditLogEntry{
			Action:    e.Action,
			Actor:     e.Actor,
			CreatedAt: createdAt,
			TokenID:   e.TokenID,
			User:      e.User,
		})
	}

	return entries, nil
}
