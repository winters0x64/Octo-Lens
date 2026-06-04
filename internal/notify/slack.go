package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
)

// SlackNotifier sends messages to a Slack incoming webhook.
type SlackNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewSlackNotifier creates a notifier for the given webhook URL.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

type slackMessage struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

type slackBlock struct {
	Type   string      `json:"type"`
	Text   *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// SendViolations sends a Slack alert for policy violations.
func (s *SlackNotifier) SendViolations(org string, violations []policy.Violation) error {
	if len(violations) == 0 {
		return nil
	}

	var highCount, medCount, lowCount int
	for _, v := range violations {
		switch v.Severity {
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		}
	}

	header := slackBlock{
		Type: "header",
		Text: &slackText{
			Type: "plain_text",
			Text: fmt.Sprintf("PAT Monitor: %d violation(s) in %s", len(violations), org),
		},
	}

	summary := slackBlock{
		Type: "section",
		Text: &slackText{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*High:* %d | *Medium:* %d | *Low:* %d", highCount, medCount, lowCount),
		},
	}

	var details []string
	limit := 15
	if len(violations) < limit {
		limit = len(violations)
	}
	for _, v := range violations[:limit] {
		icon := ":large_yellow_circle:"
		if v.Severity == "high" {
			icon = ":red_circle:"
		} else if v.Severity == "low" {
			icon = ":white_circle:"
		}
		details = append(details, fmt.Sprintf("%s *%s* — %s\n    %s", icon, v.Resource, v.Message, v.Rule))
	}
	if len(violations) > limit {
		details = append(details, fmt.Sprintf("_...and %d more_", len(violations)-limit))
	}

	detailBlock := slackBlock{
		Type: "section",
		Text: &slackText{
			Type: "mrkdwn",
			Text: strings.Join(details, "\n"),
		},
	}

	msg := slackMessage{
		Text:   fmt.Sprintf("PAT Monitor: %d policy violation(s) in %s", len(violations), org),
		Blocks: []slackBlock{header, summary, detailBlock},
	}

	return s.send(msg)
}

// SendScanSummary sends a brief summary of the latest scan.
func (s *SlackNotifier) SendScanSummary(org string, totalPATs, activePATs, totalApps, highRiskApps int) error {
	msg := slackMessage{
		Text: fmt.Sprintf("PAT Monitor scan complete for %s: %d PATs (%d active), %d apps (%d high-risk)",
			org, totalPATs, activePATs, totalApps, highRiskApps),
	}
	return s.send(msg)
}

// SendNewCredentials fires when new PATs or apps are detected since the last scan.
func (s *SlackNotifier) SendNewCredentials(org string, newPATs []models.PATInfo, newApps []models.AppInstallation) error {
	if len(newPATs) == 0 && len(newApps) == 0 {
		return nil
	}

	var lines []string
	for _, p := range newPATs {
		expiry := "no expiry :warning:"
		if p.TokenExpiresAt != nil {
			expiry = "expires " + p.TokenExpiresAt.Format("2006-01-02")
		}
		icon := ":large_green_circle:"
		if p.RepositorySelection == "all" {
			icon = ":red_circle:"
		}
		lines = append(lines, fmt.Sprintf("%s New PAT *%s* by `%s` — %s repos, %s",
			icon, p.TokenName, p.OwnerLogin, p.RepositorySelection, expiry))
	}
	for _, a := range newApps {
		icon := ":large_green_circle:"
		if a.HighRiskCount > 0 {
			icon = ":red_circle:"
		}
		lines = append(lines, fmt.Sprintf("%s New app *%s* installed — %d high-risk perms, %s repos",
			icon, a.AppName, a.HighRiskCount, a.RepositorySelection))
	}

	header := slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":new: New credentials in %s", org)},
	}
	body := slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n")},
	}

	return s.send(slackMessage{
		Text:   fmt.Sprintf("%d new credential(s) detected in %s", len(newPATs)+len(newApps), org),
		Blocks: []slackBlock{header, body},
	})
}

// SendNewInfraCredentials fires when new secrets or deploy keys are detected.
func (s *SlackNotifier) SendNewInfraCredentials(org string, newSecrets []models.OrgSecret, newDKs []models.DeployKey) error {
	if len(newSecrets) == 0 && len(newDKs) == 0 {
		return nil
	}

	var lines []string
	for _, sec := range newSecrets {
		icon := ":large_green_circle:"
		if sec.Risk == models.RiskHigh {
			icon = ":red_circle:"
		} else if sec.Risk == models.RiskMedium {
			icon = ":large_yellow_circle:"
		}
		scope := sec.Scope
		if sec.RepoName != "" {
			scope += "/" + sec.RepoName
		}
		if sec.EnvName != "" {
			scope += "/" + sec.EnvName
		}
		lines = append(lines, fmt.Sprintf("%s New secret *%s* — scope: %s", icon, sec.Name, scope))
	}
	for _, dk := range newDKs {
		icon := ":large_green_circle:"
		access := "read-only"
		if !dk.ReadOnly {
			icon = ":red_circle:"
			access = "write"
		}
		lines = append(lines, fmt.Sprintf("%s New deploy key *%s* on `%s` — %s access", icon, dk.Title, dk.RepoName, access))
	}

	header := slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":new: New secrets/keys in %s", org)},
	}
	body := slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n")},
	}

	return s.send(slackMessage{
		Text:   fmt.Sprintf("%d new secret(s)/key(s) detected in %s", len(newSecrets)+len(newDKs), org),
		Blocks: []slackBlock{header, body},
	})
}

// SendPermissionChanges fires when PAT permissions, scope, or repo access changes.
func (s *SlackNotifier) SendPermissionChanges(org string, pats []models.PATInfo, changedFields [][]string) error {
	if len(pats) == 0 {
		return nil
	}

	var lines []string
	for i, p := range pats {
		fields := "unknown"
		if i < len(changedFields) && len(changedFields[i]) > 0 {
			fields = strings.Join(changedFields[i], ", ")
		}
		lines = append(lines, fmt.Sprintf(":pencil2: PAT *%s* by `%s` — changed: %s",
			p.TokenName, p.OwnerLogin, fields))
	}

	header := slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":pencil2: Credential changes in %s", org)},
	}
	body := slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n")},
	}

	return s.send(slackMessage{
		Text:   fmt.Sprintf("%d credential change(s) in %s", len(pats), org),
		Blocks: []slackBlock{header, body},
	})
}

func (s *SlackNotifier) send(msg slackMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal slack message: %w", err)
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack webhook POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}
