package graph

import "sort"

// Findings is the insight-first payload: ranked attack paths to production and
// prioritized, deduplicated remediation action items. This is the primary
// surface — the node-link graph is only a drill-down for a single finding.
type Findings struct {
	Paths   []AttackPath `json:"paths"`
	Actions []ActionItem `json:"actions"`
}

// PathStep is one hop in a readable attack chain (trigger → workflow → secret
// → boundary), rendered as a sentence in the UI.
type PathStep struct {
	Kind  string `json:"kind"`  // trigger | workflow | secret | oidc_role | environment
	Label string `json:"label"`
	Note  string `json:"note,omitempty"`
}

// AttackPath is an end-to-end route a workflow opens to a production boundary.
type AttackPath struct {
	ID           string     `json:"id"`
	Severity     string     `json:"severity"` // critical | high | medium
	Repo         string     `json:"repo"`
	Workflow     string     `json:"workflow"`
	WorkflowID   string     `json:"workflow_id"`
	Steps        []PathStep `json:"steps"`
	Boundary     string     `json:"boundary"`
	BoundaryType string     `json:"boundary_type"`
	AWSAccount   string     `json:"aws_account"`        // account ID, or "" when templated/non-AWS
	Factors      []string   `json:"factors"`
	Trigger      string     `json:"trigger"`            // the event that can initiate the path
	TriggerRisk  string     `json:"trigger_risk"`       // how/by whom it can be triggered
	Why          string     `json:"why"`
	Fix          string     `json:"fix"`                // one-line summary (kept for back-compat)
	Fixes        []string   `json:"fixes"`              // ordered, concrete action items
	Score        int        `json:"score"`
}

// ActionItem is a single prioritized remediation.
type ActionItem struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"` // pin_action | fix_trigger | rotate_secret | restrict_perms
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
	FocusID  string `json:"focus_id"` // graph node to open as the drill-down
	Score    int    `json:"score"`
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// Findings computes ranked attack paths and action items from the graph.
func (g *Graph) Findings() Findings {
	f := Findings{}
	for _, n := range g.Nodes {
		if n.Type != NodeWorkflow {
			continue
		}
		w := g.workflowFacts(n)
		if p, ok := g.buildPath(w); ok {
			f.Paths = append(f.Paths, p)
		}
		f.Actions = append(f.Actions, g.workflowActions(w)...)
	}
	f.Actions = append(f.Actions, g.actionActions()...)
	f.Actions = append(f.Actions, g.secretActions()...)

	sortPaths(f.Paths)
	f.Actions = dedupeSortActions(f.Actions)
	if len(f.Paths) > 40 {
		f.Paths = f.Paths[:40]
	}
	if len(f.Actions) > 40 {
		f.Actions = f.Actions[:40]
	}
	return f
}

// workflowFacts gathers the reachability + privilege facts for one workflow.
type wfFacts struct {
	node           *Node
	repo, file     string
	perms          string
	idToken        bool
	selfHosted     bool
	triggers       []string
	secrets        []*Node
	roles          []*Node
	prodEnvs       []*Node
	unpinnedActs   []*Node // all unpinned (incl. first-party)
	unpinnedRisky  []*Node // unpinned third-party/verified only — the real hijack risk
}

func (g *Graph) workflowFacts(n Node) wfFacts {
	w := wfFacts{node: g.byID[n.ID]}
	w.repo, _ = n.Meta["repo_name"].(string)
	w.file, _ = n.Meta["file_name"].(string)
	w.perms, _ = n.Meta["permissions"].(string)
	w.idToken, _ = n.Meta["id_token_write"].(bool)
	w.selfHosted, _ = n.Meta["self_hosted"].(bool)
	w.triggers = toStringSlice(n.Meta["triggers"])

	w.secrets = g.outOfType(n.ID, NodeSecret)
	w.roles = g.outOfType(n.ID, NodeOIDCRole)
	for _, e := range g.outOfType(n.ID, NodeEnv) {
		if e.Risk == "high" { // prod-like
			w.prodEnvs = append(w.prodEnvs, e)
		}
	}
	for _, a := range g.inOfType(n.ID, NodeAction) {
		if pinned, _ := a.Meta["pinned"].(bool); !pinned {
			w.unpinnedActs = append(w.unpinnedActs, a)
			if owner, _ := a.Meta["owner"].(string); actionTrust(owner) != trustFirstParty {
				w.unpinnedRisky = append(w.unpinnedRisky, a) // hijack risk is real only off the trusted namespaces
			}
		}
	}
	return w
}

// Publisher trust tiers. The unpinned-action threat is tag-hijacking by a third
// party, so trust gates severity: GitHub's own namespaces can't be hijacked the
// way an arbitrary marketplace action can.
const (
	trustFirstParty = "first_party" // actions/*, github/* — GitHub-maintained
	trustVerified   = "verified"    // widely-used, well-known publishers
	trustThirdParty = "third_party" // everyone else — the real supply-chain risk
)

var firstPartyOrgs = map[string]bool{"actions": true, "github": true}

var verifiedOrgs = map[string]bool{
	"aws-actions": true, "azure": true, "google-github-actions": true,
	"docker": true, "hashicorp": true, "gradle": true, "golangci": true,
	"sigstore": true, "pypa": true, "denoland": true, "pnpm": true, "oven-sh": true,
}

func actionTrust(owner string) string {
	switch {
	case firstPartyOrgs[owner]:
		return trustFirstParty
	case verifiedOrgs[owner]:
		return trustVerified
	default:
		return trustThirdParty
	}
}

func trustLabel(t string) string {
	switch t {
	case trustFirstParty:
		return "First-party (GitHub-maintained)"
	case trustVerified:
		return "Verified publisher"
	default:
		return "Third-party"
	}
}

// buildPath emits an attack path when the workflow reaches a production
// boundary (an OIDC role or a prod-like environment).
func (g *Graph) buildPath(w wfFacts) (AttackPath, bool) {
	if len(w.roles) == 0 && len(w.prodEnvs) == 0 {
		return AttackPath{}, false
	}

	trig, dangerous := worstTrigger(w.triggers)
	var factors []string
	if dangerous {
		factors = append(factors, "untrusted-trigger")
	}
	if w.perms == "write-all" {
		factors = append(factors, "write-all")
	}
	if len(w.unpinnedRisky) > 0 {
		factors = append(factors, "unpinned-actions")
	}
	if w.selfHosted {
		factors = append(factors, "self-hosted")
	}
	if w.idToken {
		factors = append(factors, "id-token")
	}

	// Severity: untrusted trigger reaching prod is the classic pwn-request -> critical.
	sev := "high"
	if dangerous {
		sev = "critical"
	} else if w.perms != "write-all" && len(w.unpinnedRisky) == 0 && onlyManual(w.triggers) {
		sev = "medium"
	}

	boundary, btype := "", ""
	if len(w.roles) > 0 {
		boundary, btype = w.roles[0].Label, NodeOIDCRole
	} else {
		boundary, btype = w.prodEnvs[0].Label, NodeEnv
	}

	steps := []PathStep{{Kind: "trigger", Label: trig, Note: triggerNote(dangerous)}}
	wfNote := w.perms
	if len(w.unpinnedRisky) > 0 {
		wfNote = appendNote(wfNote, itoa(int64(len(w.unpinnedRisky)))+" unpinned 3rd-party")
	}
	steps = append(steps, PathStep{Kind: "workflow", Label: w.repo + " / " + w.node.Label, Note: wfNote})
	if len(w.secrets) > 0 {
		steps = append(steps, PathStep{Kind: "secret", Label: secretsLabel(w.secrets), Note: ""})
	}
	steps = append(steps, PathStep{Kind: btype, Label: boundary})

	// When the boundary is an OIDC role, extend the path to the AWS account.
	account := ""
	if btype == NodeOIDCRole && len(w.roles) > 0 {
		arn, _ := w.roles[0].Meta["arn"].(string)
		acct, known := AWSAccountFromARN(arn)
		if known {
			account = acct
			steps = append(steps, PathStep{Kind: "aws_account", Label: acct, Note: "AWS account"})
		} else {
			steps = append(steps, PathStep{Kind: "aws_account", Label: "unknown", Note: "templated — resolved at runtime"})
		}
	}

	return AttackPath{
		ID:         "path:" + w.node.ID,
		Severity:   sev,
		Repo:       w.repo,
		Workflow:   w.node.Label,
		WorkflowID: w.node.ID,
		Steps:      steps,
		Boundary:   boundary, BoundaryType: btype,
		AWSAccount: account,
		Factors: factors,
		Trigger:     trig,
		TriggerRisk: triggerExposure(trig),
		Why:     pathWhy(dangerous, trig, w),
		Fix:     pathFix(dangerous, w),
		Fixes:   pathFixes(dangerous, w),
		Score:   sevRank[sev]*1000 + len(w.secrets)*10 + len(w.roles)*20 + len(w.unpinnedRisky),
	}, true
}

// workflowActions emits trigger / permission action items for one workflow.
func (g *Graph) workflowActions(w wfFacts) []ActionItem {
	var out []ActionItem
	_, dangerous := worstTrigger(w.triggers)
	hasAccess := len(w.secrets) > 0 || len(w.roles) > 0

	if dangerous && hasAccess {
		sev := "high"
		if len(w.roles) > 0 {
			sev = "critical"
		}
		trig, _ := worstTrigger(w.triggers)
		out = append(out, ActionItem{
			ID: "act:trigger:" + w.node.ID, Severity: sev, Kind: "fix_trigger",
			Title:   "Guard " + trig + " in " + w.repo + " / " + w.node.Label,
			Detail:  "Untrusted trigger with access to " + plural(len(w.secrets), "secret", "secrets") + reachSuffix(w.roles),
			Fix:     "Remove pull_request_target or move secret/deploy steps to a separate workflow gated by a protected environment.",
			FocusID: w.node.ID, Score: sevRank[sev]*1000 + len(w.secrets)*10,
		})
	}

	if w.perms == "write-all" && hasAccess {
		sev := "medium"
		if len(w.roles) > 0 {
			sev = "high"
		}
		out = append(out, ActionItem{
			ID: "act:perms:" + w.node.ID, Severity: sev, Kind: "restrict_perms",
			Title:   "Restrict GITHUB_TOKEN in " + w.repo + " / " + w.node.Label,
			Detail:  "Default token is write-all with " + plural(len(w.secrets), "secret", "secrets") + reachSuffix(w.roles) + " in reach",
			Fix:     "Add a least-privilege permissions: block (e.g. contents: read) at the top of the workflow.",
			FocusID: w.node.ID, Score: sevRank[sev]*1000 + len(w.secrets)*5,
		})
	}
	return out
}

// actionActions emits "pin this action" items for unpinned actions. Severity is
// gated by PUBLISHER TRUST, not reach: an unpinned third-party action is a real
// tag-hijack risk, whereas an unpinned first-party (actions/*, github/*) action
// is hardening hygiene — surfacing it as critical just because it's ubiquitous
// is noise. Reach only escalates within a trust tier.
func (g *Graph) actionActions() []ActionItem {
	var out []ActionItem
	for _, n := range g.Nodes {
		if n.Type != NodeAction {
			continue
		}
		if pinned, _ := n.Meta["pinned"].(bool); pinned {
			continue
		}
		owner, _ := n.Meta["owner"].(string)
		trust := actionTrust(owner)
		wf := g.reachableTypeCount(n.ID, NodeWorkflow)
		if wf == 0 {
			continue
		}
		secrets := g.reachableTypeCount(n.ID, NodeSecret)
		roles := g.reachableTypeCount(n.ID, NodeOIDCRole)

		var sev, detail string
		switch trust {
		case trustFirstParty:
			// Hijack of GitHub's own namespace is not a realistic supply-chain
			// vector — keep it low and DON'T quote the (ubiquity-driven) reach.
			sev = "low"
			detail = trustLabel(trust) + " · unpinned · used in " + plural(wf, "workflow", "workflows") + " · pin as defense-in-depth"
		case trustVerified:
			sev = "medium"
			if roles > 0 {
				sev = "high"
			}
			detail = trustLabel(trust) + " · unpinned · used in " + plural(wf, "workflow", "workflows") + " · reaches " + plural(secrets, "secret", "secrets") + ", " + plural(roles, "OIDC role", "OIDC roles")
		default: // third party — the real risk
			sev = "high"
			if roles > 0 {
				sev = "critical"
			} else if secrets == 0 && wf < 5 {
				sev = "medium"
			}
			detail = trustLabel(trust) + " · unpinned · used in " + plural(wf, "workflow", "workflows") + " · reaches " + plural(secrets, "secret", "secrets") + ", " + plural(roles, "OIDC role", "OIDC roles")
		}

		// Trust dominates ordering; reach only breaks ties within a tier.
		trustWeight := map[string]int{trustThirdParty: 300, trustVerified: 150, trustFirstParty: 0}[trust]
		out = append(out, ActionItem{
			ID: "act:pin:" + n.ID, Severity: sev, Kind: "pin_action",
			Title:   "Pin " + n.Label,
			Detail:  detail,
			Fix:     "Pin to a full commit SHA (e.g. uses: owner/action@<40-char-sha>) instead of a tag.",
			FocusID: n.ID, Score: sevRank[sev]*1000 + trustWeight + wf + secrets*2 + roles*5,
		})
	}
	return out
}

// secretActions emits "rotate / scope this secret" items for high-blast-radius
// or org-wide secrets.
func (g *Graph) secretActions() []ActionItem {
	var out []ActionItem
	for _, n := range g.Nodes {
		if n.Type != NodeSecret {
			continue
		}
		wf := g.upstreamTypeCount(n.ID, NodeWorkflow)
		if wf == 0 {
			continue
		}
		repos := g.upstreamTypeCount(n.ID, NodeRepo)
		scope, _ := n.Meta["scope"].(string)
		vis, _ := n.Meta["visibility"].(string)
		orgWide := scope == "org" && vis == "all"

		sev := ""
		if orgWide || wf >= 20 {
			sev = "high"
		} else if wf >= 5 {
			sev = "medium"
		} else {
			continue
		}
		detail := "Used by " + plural(wf, "workflow", "workflows") + " across " + plural(repos, "repo", "repos")
		if orgWide {
			detail += " · org-wide visibility=all"
		}
		out = append(out, ActionItem{
			ID: "act:rotate:" + n.ID, Severity: sev, Kind: "rotate_secret",
			Title:   "Rotate / scope " + n.Label,
			Detail:  detail,
			Fix:     "Rotate the value and narrow scope (environment-scoped secret, or restrict org visibility from 'all' to selected repos).",
			FocusID: n.ID, Score: sevRank[sev]*1000 + wf,
		})
	}
	return out
}

// --- helpers ----------------------------------------------------------------

func (g *Graph) outOfType(id, typ string) []*Node {
	var out []*Node
	for _, nid := range g.out[id] {
		if n := g.byID[nid]; n != nil && n.Type == typ {
			out = append(out, n)
		}
	}
	return out
}

func (g *Graph) inOfType(id, typ string) []*Node {
	var out []*Node
	for _, nid := range g.in[id] {
		if n := g.byID[nid]; n != nil && n.Type == typ {
			out = append(out, n)
		}
	}
	return out
}

// worstTrigger returns the most exploitable trigger present and whether it
// accepts untrusted input.
func worstTrigger(triggers []string) (string, bool) {
	for _, t := range triggers {
		if isDangerousTrigger(t) {
			return t, true
		}
	}
	for _, t := range triggers {
		if t == "push" || t == "pull_request" {
			return t, false
		}
	}
	if len(triggers) > 0 {
		return triggers[0], false
	}
	return "on", false
}

func onlyManual(triggers []string) bool {
	if len(triggers) == 0 {
		return false
	}
	for _, t := range triggers {
		if t != "workflow_dispatch" && t != "schedule" {
			return false
		}
	}
	return true
}

func triggerNote(dangerous bool) string {
	if dangerous {
		return "untrusted input"
	}
	return ""
}

func secretsLabel(secrets []*Node) string {
	if len(secrets) == 1 {
		return secrets[0].Label
	}
	return secrets[0].Label + " +" + itoa(int64(len(secrets)-1))
}

func reachSuffix(roles []*Node) string {
	if len(roles) > 0 {
		return " and " + plural(len(roles), "OIDC role", "OIDC roles")
	}
	return ""
}

func appendNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + " · " + b
}

func pathWhy(dangerous bool, trig string, w wfFacts) string {
	if dangerous {
		return "A " + trig + " trigger runs attacker-controllable code with access to production credentials — the classic 'pwn request'. Code from a fork can exfiltrate the secret or assume the cloud role."
	}
	if w.perms == "write-all" || len(w.unpinnedRisky) > 0 {
		return "This workflow reaches a production boundary and is weakly isolated (" + factorsPhrase(w) + "), so a compromised build step can pivot to production."
	}
	return "This workflow can assume a production cloud role / deploy to a production environment."
}

// triggerExposure describes how (and by whom) the workflow's trigger can be
// initiated — i.e. the realistic entry vector for the path.
func triggerExposure(trig string) string {
	switch trig {
	case "pull_request_target":
		return "Runs automatically on pull requests — including from forks — with access to repository secrets. Any outside contributor can initiate it by opening a PR."
	case "pull_request":
		return "Runs on pull requests; if it checks out and executes PR code while secrets are in scope, a fork PR can initiate it."
	case "workflow_run":
		return "Runs after another workflow completes and can inherit a privileged context kicked off by a less-trusted event."
	case "issue_comment":
		return "Triggered by issue/PR comments — an attacker can initiate it with a crafted comment."
	case "push":
		return "Runs on every push — initiated by anyone who can commit to the repo, or by a compromised contributor/branch."
	case "schedule":
		return "Runs unattended on a cron schedule — a compromised action or dependency executes automatically, with no human in the loop."
	case "workflow_dispatch":
		return "Manually triggered (UI or API) — requires someone with workflow-run permission, or a token with the actions scope, to start it."
	default:
		return "Initiated by the '" + trig + "' event."
	}
}

// pathFixes returns ordered, concrete remediation steps for one attack path.
func pathFixes(dangerous bool, w wfFacts) []string {
	var f []string
	if dangerous {
		f = append(f, "Remove the untrusted trigger (e.g. pull_request_target), or move the privileged deploy/secret steps into a separate workflow gated by a protected environment with required reviewers — and never check out untrusted code while secrets or the cloud role are in scope.")
	}
	if len(w.unpinnedRisky) > 0 {
		f = append(f, "Pin third-party actions to full commit SHAs (let Dependabot keep them updated) so a moved tag can't inject code into this job.")
	}
	if w.perms == "write-all" {
		f = append(f, "Set least-privilege GITHUB_TOKEN permissions (e.g. permissions: { contents: read }) at the workflow or job level.")
	}
	if w.selfHosted {
		f = append(f, "Avoid a self-hosted runner for this workflow, or isolate/ephemeralize it — a compromised job can persist on a shared runner.")
	}
	if len(w.roles) > 0 {
		f = append(f, "Scope the IAM role's trust policy to this exact repo and branch (the token.actions.githubusercontent.com:sub condition), and least-privilege the role's AWS permissions.")
	}
	if len(w.secrets) > 0 {
		f = append(f, "Move the referenced secrets to a protected environment and rotate any that are over-exposed; pass only the specific secrets this job needs.")
	}
	if len(f) == 0 {
		f = append(f, "Require environment approvals before this workflow can assume the production role.")
	}
	return f
}

func pathFix(dangerous bool, w wfFacts) string {
	if dangerous {
		return "Drop pull_request_target (or split untrusted CI from privileged deploy), and gate deploy steps behind a protected environment with required reviewers."
	}
	var parts string
	if len(w.unpinnedRisky) > 0 {
		parts = "pin third-party actions to SHAs"
	}
	if w.perms == "write-all" {
		parts = appendNote(parts, "set least-privilege token permissions")
	}
	if parts == "" {
		parts = "require environment approvals before assuming the role"
	}
	return "Reduce exposure: " + parts + "."
}

func factorsPhrase(w wfFacts) string {
	var p string
	if w.perms == "write-all" {
		p = "write-all token"
	}
	if len(w.unpinnedRisky) > 0 {
		p = appendNote(p, "unpinned third-party actions")
	}
	if w.selfHosted {
		p = appendNote(p, "self-hosted runner")
	}
	if p == "" {
		p = "broad access"
	}
	return p
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		var out []string
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func sortPaths(p []AttackPath) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].Score != p[j].Score {
			return p[i].Score > p[j].Score
		}
		return p[i].ID < p[j].ID
	})
}

func dedupeSortActions(a []ActionItem) []ActionItem {
	seen := map[string]bool{}
	out := a[:0]
	for _, it := range a {
		if seen[it.ID] {
			continue
		}
		seen[it.ID] = true
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}
