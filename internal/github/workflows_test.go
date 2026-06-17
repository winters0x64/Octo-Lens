package github

import (
	"testing"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

const sampleWorkflow = `
name: deploy
on:
  push:
    branches: [main]
  pull_request_target:
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/ProdDeployRole
          aws-region: us-east-1
      - name: deploy
        run: ./deploy.sh
        env:
          AWS_KEY: ${{ secrets.AWS_PROD_KEY }}
          SLACK: ${{ secrets.SLACK_WEBHOOK }}
  build:
    runs-on: [self-hosted, linux]
    steps:
      - uses: ./.github/actions/local-build
`

func TestParseWorkflowStructure(t *testing.T) {
	var wf models.WorkflowFile
	wf.SecretRefs = extractSecretRefs(sampleWorkflow)
	parseWorkflowStructure(sampleWorkflow, &wf)

	// Triggers — including the dangerous pull_request_target. The bare `on`
	// key must not collapse to a boolean.
	if !contains(wf.Triggers, "push") || !contains(wf.Triggers, "pull_request_target") {
		t.Errorf("triggers = %v, want push + pull_request_target", wf.Triggers)
	}

	// OIDC id-token: write from top-level permissions.
	if !wf.IDTokenWrite {
		t.Error("IDTokenWrite = false, want true")
	}

	// Secret references resolved by name (GITHUB_TOKEN excluded).
	if !contains(wf.SecretRefs, "AWS_PROD_KEY") || !contains(wf.SecretRefs, "SLACK_WEBHOOK") {
		t.Errorf("secret refs = %v, want AWS_PROD_KEY + SLACK_WEBHOOK", wf.SecretRefs)
	}

	// OIDC role ARN extracted from configure-aws-credentials.
	if !contains(wf.OIDCRoles, "arn:aws:iam::111122223333:role/ProdDeployRole") {
		t.Errorf("oidc roles = %v, want ProdDeployRole ARN", wf.OIDCRoles)
	}

	// Environment + self-hosted runner.
	if !contains(wf.Environments, "production") {
		t.Errorf("environments = %v, want production", wf.Environments)
	}
	if !wf.SelfHosted {
		t.Error("SelfHosted = false, want true (build job uses self-hosted)")
	}

	// Action classification: pinned SHA vs tag vs local.
	var checkout, setupNode, local *models.ActionRef
	for i := range wf.Actions {
		switch wf.Actions[i].Name {
		case "checkout":
			checkout = &wf.Actions[i]
		case "setup-node":
			setupNode = &wf.Actions[i]
		}
		if wf.Actions[i].Kind == "local" {
			local = &wf.Actions[i]
		}
	}
	if checkout == nil || !checkout.Pinned || checkout.SHA == "" {
		t.Errorf("checkout should be pinned to SHA, got %+v", checkout)
	}
	if setupNode == nil || setupNode.Pinned {
		t.Errorf("setup-node@v4 should be unpinned, got %+v", setupNode)
	}
	if local == nil {
		t.Error("local action (./.github/actions/local-build) not classified as local")
	}

	// Back-compat: unpinned marketplace actions surface in UnpinnedActions,
	// but the pinned checkout must not.
	for _, a := range wf.Actions {
		if a.Name == "checkout" {
			for _, u := range deriveUnpinned(wf.Actions) {
				if u == a.Raw {
					t.Errorf("pinned checkout leaked into unpinned list")
				}
			}
		}
	}
}

func deriveUnpinned(actions []models.ActionRef) []string {
	var out []string
	for _, a := range actions {
		if !a.Pinned && (a.Kind == "marketplace" || a.Kind == "reusable_workflow") {
			out = append(out, a.Raw)
		}
	}
	return out
}

func TestParseActionRefReusableWorkflow(t *testing.T) {
	ref := parseActionRef("octo-org/shared/.github/workflows/build.yml@v1")
	if ref.Kind != "reusable_workflow" {
		t.Errorf("kind = %q, want reusable_workflow", ref.Kind)
	}
	if ref.Owner != "octo-org" {
		t.Errorf("owner = %q, want octo-org", ref.Owner)
	}
}

func TestExtractSecretRefsDynamic(t *testing.T) {
	got := extractSecretRefs(`env: { ALL: ${{ toJSON(secrets) }} }`)
	if !contains(got, "*") {
		t.Errorf("toJSON(secrets) should yield wildcard, got %v", got)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
