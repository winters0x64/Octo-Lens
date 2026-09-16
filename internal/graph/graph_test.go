package graph

import (
	"strings"
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
				RepoName: "acme-backend", FileName: "deploy.yml", Permissions: "write-all", Risk: models.RiskHigh,
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
	// role transitively? No — only acme-backend assumes the role. But ci.yml
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

	// acme-backend/deploy.yml reaches ProdDeployRole -> at least one attack path.
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

// TestPerWorkflowActionPinning guards the false-positive fix: action nodes are
// deduped org-wide, but pin-status must be judged per workflow. The SAME action
// is SHA-pinned in one prod-reaching workflow and tag-pinned in another; the
// pinned workflow must NOT inherit the other's "unpinned third-party" flag.
func TestPerWorkflowActionPinning(t *testing.T) {
	const sha = "1111111111111111111111111111111111111111"
	r := &models.OrgReport{
		WorkflowFiles: []models.WorkflowFile{
			{
				RepoName: "pinned-repo", FileName: "a.yml", Permissions: "read-all", Risk: models.RiskHigh,
				Actions: []models.ActionRef{
					{Raw: "aws-actions/configure-aws-credentials@" + sha, Owner: "aws-actions", Name: "configure-aws-credentials", Ref: sha, SHA: sha, Pinned: true, Kind: "marketplace"},
				},
				OIDCRoles: []string{"arn:aws:iam::111122223333:role/ProdRole"}, Triggers: []string{"workflow_dispatch"}, IDTokenWrite: true,
			},
			{
				RepoName: "unpinned-repo", FileName: "b.yml", Permissions: "read-all", Risk: models.RiskHigh,
				Actions: []models.ActionRef{
					{Raw: "aws-actions/configure-aws-credentials@v4", Owner: "aws-actions", Name: "configure-aws-credentials", Ref: "v4", Pinned: false, Kind: "marketplace"},
				},
				OIDCRoles: []string{"arn:aws:iam::111122223333:role/ProdRole"}, Triggers: []string{"workflow_dispatch"}, IDTokenWrite: true,
			},
		},
	}
	g := Build(r)
	f := g.Findings()

	pathFor := func(wfID string) *AttackPath {
		for i := range f.Paths {
			if f.Paths[i].WorkflowID == wfID {
				return &f.Paths[i]
			}
		}
		return nil
	}
	pinned := pathFor("workflow:pinned-repo/a.yml")
	unpinned := pathFor("workflow:unpinned-repo/b.yml")
	if pinned == nil || unpinned == nil {
		t.Fatalf("expected both workflow paths; pinned=%v unpinned=%v", pinned, unpinned)
	}

	hasFactor := func(p *AttackPath, want string) bool {
		for _, x := range p.Factors {
			if x == want {
				return true
			}
		}
		return false
	}
	// The SHA-pinned workflow must NOT be flagged for unpinned actions, must not
	// say "unpinned" in its why, and must not suggest pinning.
	if hasFactor(pinned, "unpinned-actions") {
		t.Errorf("pinned workflow falsely flagged unpinned-actions: %+v", pinned.Factors)
	}
	if strings.Contains(pinned.Why, "unpinned") {
		t.Errorf("pinned workflow why mentions unpinned: %q", pinned.Why)
	}
	for _, fx := range pinned.Fixes {
		if strings.Contains(fx, "Pin third-party actions") {
			t.Errorf("pinned workflow should not suggest pinning: %q", fx)
		}
	}
	// The tag-pinned workflow SHOULD still be flagged (no regression the other way).
	if !hasFactor(unpinned, "unpinned-actions") {
		t.Errorf("unpinned workflow should be flagged unpinned-actions: %+v", unpinned.Factors)
	}

	// Visual map: the focused subgraph must show the action's per-workflow status.
	checkNode := func(wfID string, wantPinned bool) {
		res, ok := g.BlastRadius(wfID)
		if !ok {
			t.Fatalf("blast radius %s not found", wfID)
		}
		found := false
		for _, n := range res.Subgraph.Nodes {
			if n.ID != "action:aws-actions/configure-aws-credentials" {
				continue
			}
			found = true
			if p, _ := n.Meta["pinned"].(bool); p != wantPinned {
				t.Errorf("%s: subgraph action pinned=%v, want %v", wfID, p, wantPinned)
			}
			if wantPinned && n.Risk == "high" {
				t.Errorf("%s: pinned action should not be high risk", wfID)
			}
			if !wantPinned && n.Risk != "high" {
				t.Errorf("%s: unpinned 3rd-party action should be high risk; got %q", wfID, n.Risk)
			}
		}
		if !found {
			t.Errorf("%s: action node missing from subgraph", wfID)
		}
	}
	checkNode("workflow:pinned-repo/a.yml", true)
	checkNode("workflow:unpinned-repo/b.yml", false)
}

// TestSelfRepoActionNotThirdParty guards that a workflow referencing its OWN
// repo's action via the full cross-repo path (e.g. org/thisRepo/.github/actions/x
// @master) is treated as first-party local code, not an unpinned third-party
// supply-chain dependency.
func TestSelfRepoActionNotThirdParty(t *testing.T) {
	r := &models.OrgReport{
		Org: "acme",
		WorkflowFiles: []models.WorkflowFile{
			{
				RepoName: "security-stage", FileName: "org-scan.yml", Permissions: "read-all", Risk: models.RiskHigh,
				Actions: []models.ActionRef{
					// own-repo action referenced cross-path on a branch — must be ignored
					{Raw: "acme/security-stage/.github/actions/send-sqs-metrics@master", Owner: "acme", Name: "security-stage/.github/actions/send-sqs-metrics", Ref: "master", Pinned: false, Kind: "marketplace"},
				},
				OIDCRoles: []string{"arn:aws:iam::111122223333:role/ProdRole"}, Triggers: []string{"workflow_dispatch"}, IDTokenWrite: true,
			},
		},
	}
	g := Build(r)

	// No action node should have been created for the self-repo reference.
	for _, n := range g.Nodes {
		if n.Type == NodeAction {
			t.Errorf("self-repo action should not appear as an action node: %s", n.ID)
		}
	}
	// And the path must not be flagged as having unpinned third-party actions.
	f := g.Findings()
	for _, p := range f.Paths {
		for _, x := range p.Factors {
			if x == "unpinned-actions" {
				t.Errorf("self-repo action wrongly flagged unpinned-actions: %+v", p.Factors)
			}
		}
	}
}

func TestClassifySecret(t *testing.T) {
	cases := []struct {
		name     string
		cat      string
		boundary bool
		crit     string
	}{
		{"AWS_ACCESS_KEY_ID", "aws_static", true, "critical"},
		{"AWS_SECRET_ACCESS_KEY_BETA", "aws_static", true, "critical"},
		{"GCP_SA_KEY", "gcp_sa", true, "critical"},
		{"EC2_SSH_KEY", "ssh_key", true, "critical"},
		{"KEYSTORE_STORE_PASSWORD", "signing", true, "critical"},
		{"NPM_TOKEN", "publish_token", true, "high"},
		{"DOCKER_PASSWORD", "publish_token", true, "high"},
		{"DATABASE_URL", "db_cred", true, "high"},
		{"MYSQL_COMMERCE_PASSWORD", "db_cred", true, "high"},
		{"VERCEL_TOKEN", "saas_hosting", true, "high"},
		{"DATABRICKS_TOKEN", "saas_api", true, "high"},
		// Non-boundaries / config:
		{"AWS_REGION", "", false, "low"},
		{"VERCEL_ORG_ID", "config", false, "low"},
		{"SLACK_BANK_BASE_CRASHES_WEBHOOK_URL", "credential", false, "medium"},
		{"NEXT_PUBLIC_ENABLE_GOOGLE_SIGNIN", "config", false, "low"},
	}
	for _, c := range cases {
		got := classifySecret(c.name)
		if got.Boundary != c.boundary {
			t.Errorf("%s: boundary=%v, want %v (class=%+v)", c.name, got.Boundary, c.boundary, got)
		}
		if c.cat != "" && got.Category != c.cat {
			t.Errorf("%s: category=%q, want %q", c.name, got.Category, c.cat)
		}
		if got.Criticality != c.crit {
			t.Errorf("%s: criticality=%q, want %q", c.name, got.Criticality, c.crit)
		}
	}
}

// TestSecretBoundaryPath: a workflow that reaches a long-lived static cloud key
// but has NO OIDC role or prod environment must still be flagged as a path to
// production, with the secret as the boundary and an OIDC-migration fix.
func TestSecretBoundaryPath(t *testing.T) {
	r := &models.OrgReport{
		Secrets: []models.OrgSecret{{Name: "AWS_ACCESS_KEY_ID", Scope: "repo", RepoName: "svc"}},
		WorkflowFiles: []models.WorkflowFile{{
			RepoName: "svc", FileName: "deploy.yml", Permissions: "read-all", Risk: models.RiskHigh,
			SecretRefs: []string{"AWS_ACCESS_KEY_ID"}, Triggers: []string{"workflow_dispatch"},
		}},
	}
	g := Build(r)
	f := g.Findings()

	var p *AttackPath
	for i := range f.Paths {
		if f.Paths[i].WorkflowID == "workflow:svc/deploy.yml" {
			p = &f.Paths[i]
		}
	}
	if p == nil {
		t.Fatal("expected an attack path for a workflow reaching a long-lived static cloud key")
	}
	if p.BoundaryType != NodeSecret {
		t.Errorf("boundary type = %q, want secret", p.BoundaryType)
	}
	hasFactor := false
	for _, x := range p.Factors {
		if x == "long-lived-secret" {
			hasFactor = true
		}
	}
	if !hasFactor {
		t.Errorf("expected long-lived-secret factor; got %+v", p.Factors)
	}
	migrate := false
	for _, fx := range p.Fixes {
		if strings.Contains(fx, "OIDC federation") {
			migrate = true
		}
	}
	if !migrate {
		t.Errorf("expected an OIDC-migration fix for a static cloud key; got %+v", p.Fixes)
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
