package graph

import "sort"

// Analytics holds the ranked, headline findings for the dashboard — the
// "buyable" answers: largest blast radius, paths to production, risky
// third-party actions, and stale secrets.
type Analytics struct {
	TopSecrets      []Ranked `json:"top_secrets"`       // secrets by # dependent workflows/repos
	PrivilegedFlows []Ranked `json:"privileged_flows"`  // most-privileged workflows
	RiskyActions    []Ranked `json:"risky_actions"`     // 3rd-party actions by reach
	PathsToProd     []Path   `json:"paths_to_prod"`     // workflow -> oidc role / prod env
}

// Ranked is one row in a ranked list.
type Ranked struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Detail string   `json:"detail"`
	Score  int      `json:"score"`
	Risk   string   `json:"risk"`
	Tags   []string `json:"tags,omitempty"`
}

// Path is an attack path that reaches a production boundary.
type Path struct {
	WorkflowID    string   `json:"workflow_id"`
	WorkflowLabel string   `json:"workflow_label"`
	Repo          string   `json:"repo"`
	Boundary      string   `json:"boundary"`      // role ARN or prod env name
	BoundaryType  string   `json:"boundary_type"` // "oidc_role" | "environment"
	Via           []string `json:"via"`           // notable risk factors on the path
	Risk          string   `json:"risk"`
}

const topN = 15

// Analytics computes the ranked findings over the graph.
func (g *Graph) Analytics() Analytics {
	return Analytics{
		TopSecrets:      g.topSecrets(),
		PrivilegedFlows: g.privilegedFlows(),
		RiskyActions:    g.riskyActions(),
		PathsToProd:     g.pathsToProd(),
	}
}

// topSecrets ranks secrets by how many workflows and repos depend on them —
// the answer to "which secret, if rotated, breaks the most?".
func (g *Graph) topSecrets() []Ranked {
	var out []Ranked
	for _, n := range g.Nodes {
		if n.Type != NodeSecret {
			continue
		}
		wf := g.upstreamTypeCount(n.ID, NodeWorkflow)
		repos := g.upstreamTypeCount(n.ID, NodeRepo)
		if wf == 0 {
			continue
		}
		scope, _ := n.Meta["scope"].(string)
		out = append(out, Ranked{
			ID: n.ID, Label: n.Label, Risk: n.Risk, Score: wf,
			Detail: plural(wf, "workflow", "workflows") + " · " + plural(repos, "repo", "repos"),
			Tags:   []string{scope},
		})
	}
	return trim(out)
}

// privilegedFlows ranks workflows by accumulated privilege: write permissions,
// secrets reachable, OIDC roles, dangerous triggers, self-hosted runners.
func (g *Graph) privilegedFlows() []Ranked {
	var out []Ranked
	for _, n := range g.Nodes {
		if n.Type != NodeWorkflow {
			continue
		}
		secrets := g.reachableTypeCount(n.ID, NodeSecret)
		roles := g.reachableTypeCount(n.ID, NodeOIDCRole)
		score := secrets*2 + roles*5
		var tags []string

		if perm, _ := n.Meta["permissions"].(string); perm == "write-all" {
			score += 5
			tags = append(tags, "write-all")
		}
		if idt, _ := n.Meta["id_token_write"].(bool); idt {
			score += 3
			tags = append(tags, "id-token")
		}
		if sh, _ := n.Meta["self_hosted"].(bool); sh {
			score += 3
			tags = append(tags, "self-hosted")
		}
		if hasDangerousTrigger(n) {
			score += 5
			tags = append(tags, "risky-trigger")
		}
		if score == 0 {
			continue
		}
		repo, _ := n.Meta["repo_name"].(string)
		out = append(out, Ranked{
			ID: n.ID, Label: repo + " / " + n.Label, Risk: n.Risk, Score: score,
			Detail: plural(secrets, "secret", "secrets") + " · " + plural(roles, "OIDC role", "OIDC roles"),
			Tags:   tags,
		})
	}
	return trim(out)
}

// riskyActions ranks third-party actions by reach: how many workflows they run
// in and how many secrets/roles those workflows can touch. Unpinned actions are
// the supply-chain hijack risk.
func (g *Graph) riskyActions() []Ranked {
	var out []Ranked
	for _, n := range g.Nodes {
		if n.Type != NodeAction {
			continue
		}
		wf := g.reachableTypeCount(n.ID, NodeWorkflow)
		secrets := g.reachableTypeCount(n.ID, NodeSecret)
		roles := g.reachableTypeCount(n.ID, NodeOIDCRole)
		if wf == 0 {
			continue
		}
		// Reach-weighted; unpinned actions score higher (hijackable).
		score := wf + secrets*2 + roles*5
		var tags []string
		if pinned, _ := n.Meta["pinned"].(bool); !pinned {
			score += 10
			tags = append(tags, "unpinned")
		} else {
			tags = append(tags, "pinned")
		}
		if kind, _ := n.Meta["kind"].(string); kind == "reusable_workflow" {
			tags = append(tags, "reusable")
		}
		out = append(out, Ranked{
			ID: n.ID, Label: n.Label, Risk: n.Risk, Score: score,
			Detail: plural(wf, "workflow", "workflows") + " · " + plural(secrets, "secret", "secrets") + " · " + plural(roles, "OIDC role", "OIDC roles"),
			Tags:   tags,
		})
	}
	return trim(out)
}

// pathsToProd surfaces workflows that reach a production boundary (an OIDC role
// or a prod-like environment), annotated with the risk factors on the path.
func (g *Graph) pathsToProd() []Path {
	var out []Path
	for _, n := range g.Nodes {
		if n.Type != NodeWorkflow {
			continue
		}
		repo, _ := n.Meta["repo_name"].(string)
		via := pathRiskFactors(n)

		for _, dst := range g.out[n.ID] {
			t := g.byID[dst]
			if t == nil {
				continue
			}
			switch t.Type {
			case NodeOIDCRole:
				out = append(out, Path{
					WorkflowID: n.ID, WorkflowLabel: n.Label, Repo: repo,
					Boundary: arnOf(*t), BoundaryType: NodeOIDCRole, Via: via, Risk: "high",
				})
			case NodeEnv:
				if t.Risk == "high" { // prod-like
					out = append(out, Path{
						WorkflowID: n.ID, WorkflowLabel: n.Label, Repo: repo,
						Boundary: t.Label, BoundaryType: NodeEnv, Via: via, Risk: riskOfPath(via),
					})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Via) != len(out[j].Via) {
			return len(out[i].Via) > len(out[j].Via)
		}
		return out[i].WorkflowLabel < out[j].WorkflowLabel
	})
	return out
}

// --- helpers ----------------------------------------------------------------

func hasDangerousTrigger(n Node) bool {
	triggers, _ := n.Meta["triggers"].([]string)
	if triggers == nil {
		// Meta survives a JSON round-trip as []any in some paths.
		if raw, ok := n.Meta["triggers"].([]any); ok {
			for _, t := range raw {
				if s, ok := t.(string); ok && isDangerousTrigger(s) {
					return true
				}
			}
			return false
		}
	}
	for _, t := range triggers {
		if isDangerousTrigger(t) {
			return true
		}
	}
	return false
}

func isDangerousTrigger(t string) bool {
	switch t {
	case "pull_request_target", "workflow_run", "issue_comment":
		return true
	}
	return false
}

func pathRiskFactors(n Node) []string {
	var via []string
	if perm, _ := n.Meta["permissions"].(string); perm == "write-all" {
		via = append(via, "write-all")
	}
	if hasDangerousTrigger(n) {
		via = append(via, "risky-trigger")
	}
	if sh, _ := n.Meta["self_hosted"].(bool); sh {
		via = append(via, "self-hosted")
	}
	if n.Risk == "high" || n.Risk == "medium" {
		via = append(via, "unpinned-actions")
	}
	return via
}

func riskOfPath(via []string) string {
	if len(via) >= 2 {
		return "high"
	}
	if len(via) == 1 {
		return "medium"
	}
	return "low"
}

func arnOf(n Node) string {
	if arn, ok := n.Meta["arn"].(string); ok {
		return arn
	}
	return n.Label
}

func trim(rows []Ranked) []Ranked {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].Label < rows[j].Label
	})
	if len(rows) > topN {
		rows = rows[:topN]
	}
	return rows
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(int64(n)) + " " + many
}
