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
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Fields   []slackText `json:"fields,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
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

	var blocks []slackBlock

	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":rotating_light: %d policy violation(s) in %s", len(violations), org)},
	})

	blocks = append(blocks, slackBlock{
		Type: "section",
		Fields: []slackText{
			{Type: "mrkdwn", Text: fmt.Sprintf(":red_circle: *High:* %d", highCount)},
			{Type: "mrkdwn", Text: fmt.Sprintf(":large_yellow_circle: *Medium:* %d", medCount)},
			{Type: "mrkdwn", Text: fmt.Sprintf(":white_circle: *Low:* %d", lowCount)},
			{Type: "mrkdwn", Text: fmt.Sprintf(":clock1: *Scanned:* `%s`", time.Now().UTC().Format("15:04 UTC"))},
		},
	})

	blocks = append(blocks, slackBlock{Type: "divider"})

	limit := 10
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
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("%s *%s*\n%s\n`%s`", icon, v.Resource, v.Message, v.Rule)},
		})
	}
	if len(violations) > limit {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("_...and %d more violations_", len(violations)-limit)},
		})
	}

	blocks = append(blocks, slackBlock{Type: "divider"})
	blocks = append(blocks, slackBlock{
		Type:     "context",
		Elements: []slackText{{Type: "mrkdwn", Text: fmt.Sprintf(":shield: PAT Monitor — %s", org)}},
	})

	return s.send(slackMessage{
		Text:   fmt.Sprintf(":rotating_light: %d policy violation(s) in %s", len(violations), org),
		Blocks: blocks,
	})
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

	var blocks []slackBlock

	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":rotating_light: New credentials detected in %s", org)},
	})

	blocks = append(blocks, slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("*%d* new credential(s) found during scan at `%s`",
			len(newPATs)+len(newApps), time.Now().UTC().Format("2006-01-02 15:04 UTC"))},
	})

	for _, p := range newPATs {
		expiry := ":warning: *No expiry set*"
		if p.TokenExpiresAt != nil {
			days := int(time.Until(*p.TokenExpiresAt).Hours() / 24)
			expiry = fmt.Sprintf("Expires `%s` (%d days)", p.TokenExpiresAt.Format("2006-01-02"), days)
		}

		risk := ":large_green_circle: Low"
		if p.RepositorySelection == "all" {
			risk = ":red_circle: High — all-repo access"
		}
		for _, perm := range p.Permissions {
			if perm.Level == "admin" {
				risk = ":red_circle: High — admin permissions"
				break
			}
		}

		var permNames []string
		for _, perm := range p.Permissions {
			permNames = append(permNames, fmt.Sprintf("`%s:%s`", perm.Name, perm.Level))
		}
		permStr := "none"
		if len(permNames) > 0 {
			permStr = strings.Join(permNames, " ")
		}

		blocks = append(blocks, slackBlock{Type: "divider"})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf(":key: *New Fine-Grained PAT*\n*Token:* `%s`\n*Owner:* `%s`\n*Repo access:* %s",
				p.TokenName, p.OwnerLogin, p.RepositorySelection)},
		})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Fields: []slackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Risk:*\n%s", risk)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Expiry:*\n%s", expiry)},
			},
		})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Permissions:*\n%s", permStr)},
		})
	}

	for _, a := range newApps {
		risk := ":large_green_circle: Low"
		if a.HighRiskCount > 0 {
			risk = fmt.Sprintf(":red_circle: High — %d high-risk permissions", a.HighRiskCount)
		} else if a.MediumRiskCount > 0 {
			risk = fmt.Sprintf(":large_yellow_circle: Medium — %d medium-risk permissions", a.MediumRiskCount)
		}

		blocks = append(blocks, slackBlock{Type: "divider"})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf(":gear: *New GitHub App Installed*\n*App:* `%s`\n*Repo access:* %s",
				a.AppName, a.RepositorySelection)},
		})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Fields: []slackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Risk:*\n%s", risk)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Permissions:*\n%d high, %d medium, %d low", a.HighRiskCount, a.MediumRiskCount, a.LowRiskCount)},
			},
		})
	}

	blocks = append(blocks, slackBlock{
		Type:     "context",
		Elements: []slackText{{Type: "mrkdwn", Text: fmt.Sprintf(":shield: PAT Monitor — %s", org)}},
	})

	return s.send(slackMessage{
		Text:   fmt.Sprintf(":rotating_light: %d new credential(s) detected in %s", len(newPATs)+len(newApps), org),
		Blocks: blocks,
	})
}

// SendNewInfraCredentials fires when new secrets or deploy keys are detected.
func (s *SlackNotifier) SendNewInfraCredentials(org string, newSecrets []models.OrgSecret, newDKs []models.DeployKey) error {
	if len(newSecrets) == 0 && len(newDKs) == 0 {
		return nil
	}

	var blocks []slackBlock

	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":key: New secrets/keys in %s", org)},
	})

	blocks = append(blocks, slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("*%d* new secret(s) and *%d* new deploy key(s) found at `%s`",
			len(newSecrets), len(newDKs), time.Now().UTC().Format("2006-01-02 15:04 UTC"))},
	})

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
		blocks = append(blocks, slackBlock{Type: "divider"})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Fields: []slackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Secret:*\n`%s`", sec.Name)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Risk:*\n%s %s", icon, string(sec.Risk))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Scope:*\n`%s`", scope)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Updated:*\n`%s`", sec.UpdatedAt.Format("2006-01-02"))},
			},
		})
	}

	for _, dk := range newDKs {
		icon := ":large_green_circle:"
		access := "read-only"
		if !dk.ReadOnly {
			icon = ":red_circle:"
			access = "*write*"
		}
		blocks = append(blocks, slackBlock{Type: "divider"})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Fields: []slackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Deploy Key:*\n`%s`", dk.Title)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Repo:*\n`%s`", dk.RepoName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Access:*\n%s %s", icon, access)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Created:*\n`%s`", dk.CreatedAt.Format("2006-01-02"))},
			},
		})
	}

	blocks = append(blocks, slackBlock{Type: "divider"})
	blocks = append(blocks, slackBlock{
		Type:     "context",
		Elements: []slackText{{Type: "mrkdwn", Text: fmt.Sprintf(":shield: PAT Monitor — %s", org)}},
	})

	return s.send(slackMessage{
		Text:   fmt.Sprintf(":key: %d new secret(s)/key(s) detected in %s", len(newSecrets)+len(newDKs), org),
		Blocks: blocks,
	})
}

// SendPermissionChanges fires when PAT permissions, scope, or repo access changes.
func (s *SlackNotifier) SendPermissionChanges(org string, pats []models.PATInfo, changedFields [][]string) error {
	if len(pats) == 0 {
		return nil
	}

	var blocks []slackBlock

	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: fmt.Sprintf(":pencil2: Credential changes in %s", org)},
	})

	blocks = append(blocks, slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("*%d* credential(s) modified at `%s`",
			len(pats), time.Now().UTC().Format("2006-01-02 15:04 UTC"))},
	})

	for i, p := range pats {
		fields := "unknown"
		if i < len(changedFields) && len(changedFields[i]) > 0 {
			fields = strings.Join(changedFields[i], ", ")
		}

		blocks = append(blocks, slackBlock{Type: "divider"})
		blocks = append(blocks, slackBlock{
			Type: "section",
			Fields: []slackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Token:*\n`%s`", p.TokenName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Owner:*\n`%s`", p.OwnerLogin)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Changed:*\n%s", fields)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Repo access:*\n%s", p.RepositorySelection)},
			},
		})
	}

	blocks = append(blocks, slackBlock{Type: "divider"})
	blocks = append(blocks, slackBlock{
		Type:     "context",
		Elements: []slackText{{Type: "mrkdwn", Text: fmt.Sprintf(":shield: PAT Monitor — %s", org)}},
	})

	return s.send(slackMessage{
		Text:   fmt.Sprintf(":pencil2: %d credential change(s) in %s", len(pats), org),
		Blocks: blocks,
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
