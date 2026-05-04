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
