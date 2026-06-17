package graph

import (
	"testing"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

func testReport() *models.OrgReport {
	return &models.OrgReport{
		Secrets: []models.OrgSecret{
			{Name: "AWS_PROD_KEY", Scope: "org", Visibility: "all"},
			{Name: "NPM_TOKEN", Scope: "repo", RepoName: "payments-service"},
		},
		WorkflowFiles: []models.WorkflowFile{
			{
				RepoName: "scapia-backend", FileName: "deploy.yml", Permissions: "write-all", Risk: models.RiskHigh,
				Actions: []models.ActionRef{
					{Raw: "actions/checkout@v4", Owner: "actions", Name: "checkout", Ref: "v4", Kind: "marketplace"},
					{Raw: "aws-actions/configure-aws-credentials@v4", Owner: "aws-actions", Name: "configure-aws-credentials", Ref: "v4", Kind: "marketplace"},
				},
				SecretRefs:   []string{"AWS_PROD_KEY"},
				OIDCRoles:    []string{"arn:aws:iam::111122223333:role/ProdDeployRole"},
				Environments: []string{"production"},
				Triggers:     []string{"push"},
				IDTokenWrite: true,
			},
			{
				RepoName: "payments-service", FileName: "ci.yml", Permissions: "write-all", Risk: models.RiskHigh,
				Actions: []models.ActionRef{
					{Raw: "aws-actions/configure-aws-credentials@v4", Owner: "aws-actions", Name: "configure-aws-credentials", Ref: "v4", Kind: "marketplace"},
				},
				SecretRefs: []string{"AWS_PROD_KEY", "NPM_TOKEN"},
				Triggers:   []string{"pull_request_target"},
			},
		},
	}
}

func TestBlastRadiusSecretRotation(t *testing.T) {
	g := Build(testReport())

	// "If I rotate AWS_PROD_KEY, what breaks?" — it's an org secret referenced
	// by both workflows, so the upstream set must contain 2 workflows.
	id := "secret:org:AWS_PROD_KEY::"
	res, ok := g.BlastRadius(id)
	if !ok {
		t.Fatalf("secret node %q not found; nodes=%d", id, len(g.Nodes))
	}
	if got := res.Upstream.ByType[NodeWorkflow]; got != 2 {
		t.Errorf("AWS_PROD_KEY upstream workflows = %d, want 2", got)
	}
	if res.Upstream.ByType[NodeRepo] != 2 {
		t.Errorf("AWS_PROD_KEY upstream repos = %d, want 2", res.Upstream.ByType[NodeRepo])
	}
}

func TestBlastRadiusCompromisedAction(t *testing.T) {
	g := Build(testReport())

	// configure-aws-credentials runs in both workflows; compromising it reaches
	// their secrets (AWS_PROD_KEY org + NPM_TOKEN) and the prod OIDC role.
	res, ok := g.BlastRadius("action:aws-actions/configure-aws-credentials")
	if !ok {
		t.Fatal("action node not found")
	}
	if res.Downstream.ByType[NodeWorkflow] != 2 {
		t.Errorf("action -> workflows = %d, want 2", res.Downstream.ByType[NodeWorkflow])
	}
	if res.Downstream.ByType[NodeOIDCRole] != 1 {
		t.Errorf("action -> oidc roles = %d, want 1", res.Downstream.ByType[NodeOIDCRole])
	}
	if res.Downstream.ByType[NodeSecret] < 2 {
		t.Errorf("action -> secrets = %d, want >=2", res.Downstream.ByType[NodeSecret])
	}
}

func TestFindings(t *testing.T) {
	g := Build(testReport())
	f := g.Findings()

	// payments-service/ci.yml has pull_request_target + reaches the prod OIDC
	// role transitively? No — only scapia-backend assumes the role. But ci.yml
	// has a dangerous trigger with secret access, so it must yield a critical/
	// high fix_trigger action item.
	var fixTrigger *ActionItem
	for i := range f.Actions {
		if f.Actions[i].Kind == "fix_trigger" {
			fixTrigger = &f.Actions[i]
		}
	}
	if fixTrigger == nil {
		t.Fatalf("expected a fix_trigger action item for pull_request_target; got %d actions", len(f.Actions))
	}

	// scapia-backend/deploy.yml reaches ProdDeployRole -> at least one attack path.
	if len(f.Paths) == 0 {
		t.Fatal("expected at least one attack path to production")
	}
	// The role-reaching path should be high or critical, and carry a boundary.
	p := f.Paths[0]
	if p.Severity != "high" && p.Severity != "critical" {
		t.Errorf("top path severity = %q, want high/critical", p.Severity)
	}
	if p.Boundary == "" || len(p.Steps) < 2 {
		t.Errorf("path missing boundary/steps: %+v", p)
	}

	// Trust-gated pin_action severity:
	//   - aws-actions/configure-aws-credentials (VERIFIED) reaches an OIDC role → high
	//   - actions/checkout (FIRST-PARTY) must be LOW, never critical, even though
	//     it's unpinned and ubiquitous (this was the false-priority bug).
	var awsPin, checkoutPin *ActionItem
	for i := range f.Actions {
		if f.Actions[i].Kind != "pin_action" {
			continue
		}
		switch f.Actions[i].FocusID {
		case "action:aws-actions/configure-aws-credentials":
			awsPin = &f.Actions[i]
		case "action:actions/checkout":
			checkoutPin = &f.Actions[i]
		}
	}
	if awsPin == nil || awsPin.Severity != "high" {
		t.Errorf("verified action reaching OIDC role should be high; got %+v", awsPin)
	}
	if checkoutPin == nil || checkoutPin.Severity != "low" {
		t.Errorf("first-party actions/checkout must be low (not critical); got %+v", checkoutPin)
	}
	// And it must rank below the verified one.
	if awsPin != nil && checkoutPin != nil && checkoutPin.Score >= awsPin.Score {
		t.Errorf("first-party checkout (%d) should rank below verified aws action (%d)", checkoutPin.Score, awsPin.Score)
	}
}

func TestInventoryActions(t *testing.T) {
	inv := InventoryActions(testReport())
	// checkout (first-party) appears in 1 workflow; configure-aws-credentials
	// (verified) appears in both workflows.
	var checkout, aws *ActionInventoryItem
	for i := range inv {
		switch inv[i].Identifier {
		case "actions/checkout":
			checkout = &inv[i]
		case "aws-actions/configure-aws-credentials":
			aws = &inv[i]
		}
	}
	if aws == nil || aws.Workflows != 2 {
		t.Fatalf("aws action should be used in 2 workflows; got %+v", aws)
	}
	if aws.Trust != trustVerified {
		t.Errorf("aws-actions trust = %q, want verified", aws.Trust)
	}
	if checkout == nil || checkout.Trust != trustFirstParty {
		t.Errorf("checkout should be first_party; got %+v", checkout)
	}
	// Most-used first.
	if inv[0].Identifier != "aws-actions/configure-aws-credentials" {
		t.Errorf("inventory should be sorted by usage; first = %q", inv[0].Identifier)
	}
}

func TestAnalyticsPathsToProd(t *testing.T) {
	g := Build(testReport())
	a := g.Analytics()

	// deploy.yml -> ProdDeployRole is a path to production.
	foundRole := false
	for _, p := range a.PathsToProd {
		if p.BoundaryType == NodeOIDCRole {
			foundRole = true
		}
	}
	if !foundRole {
		t.Errorf("expected an OIDC-role path to prod, got %+v", a.PathsToProd)
	}

	// AWS_PROD_KEY is the top secret by blast radius.
	if len(a.TopSecrets) == 0 || a.TopSecrets[0].Label != "AWS_PROD_KEY" {
		t.Errorf("top secret = %+v, want AWS_PROD_KEY first", a.TopSecrets)
	}
}
