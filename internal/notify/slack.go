package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	Type   string     `json:"type"`
	Text   *slackText `json:"text,omitempty"`
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

// SendScanSummary sends a summary of the latest scan results.
func (s *SlackNotifier) SendScanSummary(org string, totalPATs, activePATs, totalApps, highRiskApps int) error {
	msg := slackMessage{
		Text: fmt.Sprintf("PAT Monitor scan complete for %s: %d PATs (%d active), %d apps (%d high-risk)",
			org, totalPATs, activePATs, totalApps, highRiskApps),
	}
	return s.send(msg)
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
