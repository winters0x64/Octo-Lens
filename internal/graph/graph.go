// Package graph builds a directed CI/CD reachability graph from an org scan and
// answers blast-radius questions over it.
//
// Edges point in the direction of impact propagation: an edge A -> B means
// "controlling or compromising A lets you reach/affect B". With that
// convention, the blast radius of a compromised component is its forward
// reachable set, and "if I rotate this secret, what breaks?" is the reverse
// reachable set (everything that points at it).
package graph

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/verify"
)

// arnAccountRe extracts the 12-digit AWS account ID from a role ARN.
var arnAccountRe = regexp.MustCompile(`arn:aws:iam::(\d{12}):`)

// AWSAccountFromARN returns the account ID embedded in a role ARN, and whether
// it was a literal (vs a runtime-templated value like ${{ env.ACCOUNT }}).
func AWSAccountFromARN(arn string) (string, bool) {
	m := arnAccountRe.FindStringSubmatch(arn)
	if len(m) == 2 {
		return m[1], true
	}
	return "", false
}

// Node and edge type constants. Node types align with the dashboard legend.
const (
	NodePAT        = "pat"
	NodeApp        = "app"
	NodeSSO        = "sso"
	NodeDeployKey  = "deploy_key"
	NodeAllRepos   = "all_repos"
	NodeRepo       = "repo"
	NodeWorkflow   = "workflow"
	NodeAction     = "action"
	NodeSecret     = "secret"
	NodeEnv        = "environment"
	NodeOIDCRole   = "oidc_role"
	NodeAWSAccount = "aws_account"

	EdgeControls    = "controls"          // principal/repo -> repo/workflow
	EdgeIncludes    = "includes"          // all_repos -> repo
	EdgeCanHijack   = "can_hijack"        // action -> workflow
	EdgeReadsSecret = "references_secret" // workflow -> secret
	EdgeAssumesRole = "assumes_role"      // workflow -> oidc_role
	EdgeInAccount   = "in_account"        // oidc_role -> aws_account
	EdgeDeploysTo   = "deploys_to_env"    // workflow -> environment
)

// Node is a single graph vertex rendered by the dashboard.
type Node struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Label string         `json:"label"`
	Risk  string         `json:"risk"` // "high" | "medium" | "low" | "none"
	Meta  map[string]any `json:"meta,omitempty"`
}

// Edge is a directed, typed relationship.
type Edge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	Label  string `json:"label"`
	// Pinned is meaningful only on can_hijack edges: whether THIS usage of the
	// action (in this specific workflow) is pinned to a commit SHA. The action
	// NODE is deduped org-wide, so pin-status must live on the usage, not the node.
	Pinned bool `json:"pinned,omitempty"`
}

// Graph holds nodes, edges, and adjacency indexes for traversal.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`

	byID    map[string]*Node
	out     map[string][]string // node id -> downstream node ids
	in      map[string][]string // node id -> upstream node ids
	edgeIdx map[string]int      // "src|dst|type" -> index into Edges (built after sort)
}

// Build constructs the reachability graph from an org report.
func Build(r *models.OrgReport) *Graph {
	b := &builder{
		g: &Graph{
			byID: map[string]*Node{},
			out:  map[string][]string{},
			in:   map[string][]string{},
		},
		edgeSeen:  map[string]bool{},
		edgeIndex: map[string]int{},
	}

	repos := collectRepos(r)
	for repo := range repos {
		b.addNode(repoID(repo), NodeRepo, shortRepo(repo), "none", map[string]any{"repo_name": repo})
	}

	b.addPrincipals(r, len(repos))
	b.indexSecrets(r)
	b.addWorkflows(r)
	b.computeRepoRisk(repos)

	// Materialize the node slice from the stable heap nodes in insertion order.
	b.g.Nodes = make([]Node, 0, len(b.order))
	for _, id := range b.order {
		b.g.Nodes = append(b.g.Nodes, *b.g.byID[id])
	}
	b.g.sortDeterministic()
	b.g.buildEdgeIdx()
	return b.g
}

// buildEdgeIdx indexes edges by "src|dst|type" for O(1) lookup. Built after
// sortDeterministic so the stored indices stay valid.
func (g *Graph) buildEdgeIdx() {
	g.edgeIdx = make(map[string]int, len(g.Edges))
	for i := range g.Edges {
		e := g.Edges[i]
		g.edgeIdx[e.Source+"|"+e.Target+"|"+e.Type] = i
	}
}

// edgePinned reports whether the edge (src->dst of the given type) is marked
// pinned. For can_hijack edges this is the per-workflow pin status of the action.
func (g *Graph) edgePinned(src, dst, typ string) bool {
	if i, ok := g.edgeIdx[src+"|"+dst+"|"+typ]; ok {
		return g.Edges[i].Pinned
	}
	return false
}

type builder struct {
	g         *Graph
	order     []string // node ids in insertion order
	edgeSeen  map[string]bool
	edgeIndex map[string]int // edge key -> index into g.Edges (for in-place updates)

	// secret lookup indexes for resolving workflow -> secret edges
	orgSecrets  map[string]string            // name -> node id
	repoSecrets map[string]map[string]string // repo -> name -> node id
	envSecrets  map[string]map[string]string // repo|env -> name -> node id
}

// --- node / edge primitives -------------------------------------------------

func (b *builder) addNode(id, typ, label, risk string, meta map[string]any) {
	if _, ok := b.g.byID[id]; ok {
		return
	}
	if meta == nil {
		meta = map[string]any{}
	}
	b.g.byID[id] = &Node{ID: id, Type: typ, Label: label, Risk: risk, Meta: meta}
	b.order = append(b.order, id)
}

func (b *builder) hasNode(id string) bool { _, ok := b.g.byID[id]; return ok }

func (b *builder) addEdge(src, dst, typ, label string) {
	b.addEdgePinned(src, dst, typ, label, false)
}

// addEdgePinned is addEdge plus a per-usage pinned flag (used by can_hijack edges
// so pin-status lives on the usage, not the org-wide-deduped action node).
func (b *builder) addEdgePinned(src, dst, typ, label string, pinned bool) {
	if src == dst || !b.hasNode(src) || !b.hasNode(dst) {
		return
	}
	key := src + "|" + dst + "|" + typ
	if b.edgeSeen[key] {
		// Same usage edge already recorded. If this occurrence is unpinned, it
		// makes the whole usage hijackable — let unpinned win over a prior pinned.
		if !pinned {
			if i, ok := b.edgeIndex[key]; ok {
				b.g.Edges[i].Pinned = false
			}
		}
		return
	}
	b.edgeSeen[key] = true
	b.edgeIndex[key] = len(b.g.Edges)
	b.g.Edges = append(b.g.Edges, Edge{ID: key, Source: src, Target: dst, Type: typ, Label: label, Pinned: pinned})
	b.g.out[src] = append(b.g.out[src], dst)
	b.g.in[dst] = append(b.g.in[dst], src)
}

// --- principals -------------------------------------------------------------

func (b *builder) addPrincipals(r *models.OrgReport, repoCount int) {
	allReposAdded := false
	ensureAllRepos := func() {
		if !allReposAdded {
			b.addNode(NodeAllRepos, NodeAllRepos, "All repositories", "high",
				map[string]any{"total": repoCount, "avatar": orgAvatarFromApps(r.Apps)})
			// all_repos reaches every repo
			for _, id := range b.order {
				if n := b.g.byID[id]; n.Type == NodeRepo {
					b.addEdge(NodeAllRepos, id, EdgeIncludes, "")
				}
			}
			allReposAdded = true
		}
	}

	for _, p := range r.PATs {
		id := "pat:" + itoa(p.ID)
		risk := "medium"
		if p.RepositorySelection == "all" {
			risk = "high"
		}
		b.addNode(id, NodePAT, p.TokenName, risk, map[string]any{
			"owner": p.OwnerLogin, "repository_selection": p.RepositorySelection,
			"avatar": p.OwnerAvatarURL,
		})
		if p.RepositorySelection == "all" {
			ensureAllRepos()
			b.addEdge(id, NodeAllRepos, EdgeControls, "all repos")
		}
	}

	for _, a := range r.Apps {
		id := "app:" + itoa(a.ID)
		risk := "low"
		if a.HighRiskCount > 0 {
			risk = "high"
		} else if a.MediumRiskCount > 0 {
			risk = "medium"
		}
		b.addNode(id, NodeApp, a.AppName, risk, map[string]any{
			"repository_selection": a.RepositorySelection, "suspended": a.Suspended,
			"avatar": a.AvatarURL,
		})
		if a.RepositorySelection == "all" {
			ensureAllRepos()
			b.addEdge(id, NodeAllRepos, EdgeControls, "all repos")
		}
	}

	for _, dk := range r.DeployKeys {
		id := "dk:" + itoa(dk.ID)
		risk := "low"
		if !dk.ReadOnly {
			risk = "high"
		}
		b.addNode(id, NodeDeployKey, dk.Title, risk, map[string]any{
			"repo_name": dk.RepoName, "read_only": dk.ReadOnly,
		})
		if dk.RepoName != "" {
			b.addNode(repoID(dk.RepoName), NodeRepo, shortRepo(dk.RepoName), "none",
				map[string]any{"repo_name": dk.RepoName})
			if !dk.ReadOnly {
				b.addEdge(id, repoID(dk.RepoName), EdgeControls, "write")
			}
		}
	}
}

// --- secrets ----------------------------------------------------------------

func (b *builder) indexSecrets(r *models.OrgReport) {
	b.orgSecrets = map[string]string{}
	b.repoSecrets = map[string]map[string]string{}
	b.envSecrets = map[string]map[string]string{}

	for _, s := range r.Secrets {
		id := secretID(s)
		cls := classifySecret(s.Name)
		risk := secretNodeRisk(s, cls)

		meta := map[string]any{
			"scope": s.Scope, "visibility": s.Visibility,
			"repo_name": s.RepoName, "env_name": s.EnvName,
			"updated_at": s.UpdatedAt,
			"category":   cls.Category, "provider": cls.Provider, "target": cls.Target,
			"criticality": cls.Criticality, "boundary": cls.Boundary, "long_lived": cls.LongLived,
		}

		// When verification data is available, override heuristic classification
		// with evidence-based values.
		if s.Verified {
			meta["verified"] = true
			meta["valid"] = s.Valid
			meta["verify_provider"] = s.VerifyProvider
			meta["verify_identity"] = s.VerifyIdentity
			meta["verify_permissions"] = s.VerifyPerms
			meta["verify_error"] = s.VerifyError
			meta["verify_recognized"] = s.VerifyRecognized
			if s.VerifiedAt != nil {
				meta["verified_at"] = s.VerifiedAt
			}

			switch {
			case !s.VerifyRecognized:
				// The value didn't match any credential format we check for —
				// Valid is false by convention here, but that's NOT evidence
				// the secret is dead (an SSH key, webhook URL, or non-secret
				// config value we don't pattern-match could still be live and
				// dangerous). Leave the name-based heuristic classification
				// alone rather than misreading "unrecognized" as "confirmed
				// dead" — same principle as TierUnknown below.
			case !s.Valid:
				risk = "low"
				cls.Boundary = false
				meta["boundary"] = false
				meta["criticality"] = "low"
			case s.VerifyProvider != "":
				meta["provider"] = verifiedProviderLabel(s.VerifyProvider)
				if s.VerifyIdentity != "" {
					meta["target"] = s.VerifyIdentity
				}
				// A real permission tier — what the credential can actually DO,
				// evaluated against the live provider — is ground truth and
				// should override the name-based criticality/risk heuristic
				// above. "unknown" (couldn't determine the credential's actual
				// scope) deliberately leaves the heuristic alone rather than
				// guessing either direction.
				if s.VerifyPermissionTier != "" && s.VerifyPermissionTier != verify.TierUnknown {
					meta["verify_permission_tier"] = s.VerifyPermissionTier
					meta["verify_permission_reasons"] = s.VerifyPermissionReasons
					switch s.VerifyPermissionTier {
					case verify.TierCritical:
						meta["criticality"] = "critical"
						risk = "high"
					case verify.TierHigh:
						meta["criticality"] = "high"
						risk = "high"
					case verify.TierMedium:
						meta["criticality"] = "medium"
						risk = "medium"
					case verify.TierLow:
						meta["criticality"] = "low"
						risk = "low"
					}
				}
			}
		}

		b.addNode(id, NodeSecret, s.Name, risk, meta)
		switch s.Scope {
		case "org":
			b.orgSecrets[s.Name] = id
		case "repo":
			if b.repoSecrets[s.RepoName] == nil {
				b.repoSecrets[s.RepoName] = map[string]string{}
			}
			b.repoSecrets[s.RepoName][s.Name] = id
		case "environment":
			k := s.RepoName + "|" + s.EnvName
			if b.envSecrets[k] == nil {
				b.envSecrets[k] = map[string]string{}
			}
			b.envSecrets[k][s.Name] = id
		}
	}
}

// resolveSecret maps a workflow's secret reference (by name, in repo, with the
// workflow's environments) to the most specific inventoried secret node. When
// the secret was referenced but not inventoried, a "referenced" placeholder is
// created so the dependency is still visible. Returns the matched node ids.
func (b *builder) resolveSecret(name, repo string, envs []string) []string {
	if name == "*" {
		var ids []string
		for _, id := range b.repoSecrets[repo] {
			ids = append(ids, id)
		}
		for _, id := range b.orgSecrets {
			ids = append(ids, id)
		}
		for _, env := range envs {
			for _, id := range b.envSecrets[repo+"|"+env] {
				ids = append(ids, id)
			}
		}
		return ids
	}

	for _, env := range envs {
		if id, ok := b.envSecrets[repo+"|"+env][name]; ok {
			return []string{id}
		}
	}
	if id, ok := b.repoSecrets[repo][name]; ok {
		return []string{id}
	}
	if id, ok := b.orgSecrets[name]; ok {
		return []string{id}
	}

	// Referenced but not inventoried — placeholder keyed by name.
	id := "secret:referenced:" + name
	b.addNode(id, NodeSecret, name, "medium", map[string]any{
		"scope": "referenced", "repo_name": repo,
	})
	return []string{id}
}

// --- workflows --------------------------------------------------------------

func (b *builder) addWorkflows(r *models.OrgReport) {
	for _, wf := range r.WorkflowFiles {
		wid := workflowID(wf.RepoName, wf.FileName)
		label := strings.TrimSuffix(strings.TrimSuffix(wf.FileName, ".yml"), ".yaml")
		b.addNode(wid, NodeWorkflow, label, string(wf.Risk), map[string]any{
			"repo_name": wf.RepoName, "file_name": wf.FileName,
			"permissions": wf.Permissions, "id_token_write": wf.IDTokenWrite,
			"triggers": wf.Triggers, "self_hosted": wf.SelfHosted,
		})

		rid := repoID(wf.RepoName)
		b.addNode(rid, NodeRepo, shortRepo(wf.RepoName), "none", map[string]any{"repo_name": wf.RepoName})
		b.addEdge(rid, wid, EdgeControls, "owns")

		// actions (deduped org-wide by owner/name); compromise -> impacts workflow
		actions := wf.Actions
		if len(actions) == 0 {
			for _, raw := range wf.UnpinnedActions { // back-compat for old cached data
				actions = append(actions, models.ActionRef{Raw: raw, Pinned: false, Kind: "marketplace"})
			}
		}
		for _, a := range actions {
			// Skip local (./), docker, and same-repo cross-path references. A
			// `uses: <org>/<thisRepo>/.github/actions/x@ref` is the workflow's OWN
			// repo code (equivalent to ./x) — first-party, not a third-party
			// dependency — so it must not be treated as a supply-chain entry point.
			if a.Kind == "local" || a.Kind == "docker" || isSelfRepoAction(a, r.Org, wf.RepoName) {
				continue
			}
			aid := actionID(a)
			if aid == "" {
				continue
			}
			b.upsertAction(aid, a)
			b.addEdgePinned(aid, wid, EdgeCanHijack, hijackLabel(a), a.Pinned)
		}

		// secrets the workflow can read
		for _, name := range wf.SecretRefs {
			for _, sid := range b.resolveSecret(name, wf.RepoName, wf.Environments) {
				b.addEdge(wid, sid, EdgeReadsSecret, "")
			}
		}

		// environments
		for _, env := range wf.Environments {
			eid := "env:" + wf.RepoName + "/" + env
			risk := "low"
			if isProdLike(env) {
				risk = "high"
			}
			b.addNode(eid, NodeEnv, env, risk, map[string]any{"repo_name": wf.RepoName})
			b.addEdge(wid, eid, EdgeDeploysTo, "")
		}

		// OIDC roles → the AWS account they live in (the production target).
		for _, role := range wf.OIDCRoles {
			oid := "oidc:" + role
			acct, known := AWSAccountFromARN(role)
			b.addNode(oid, NodeOIDCRole, roleLabel(role), "high", map[string]any{"arn": role, "account_id": acct, "account_known": known})
			b.addEdge(wid, oid, EdgeAssumesRole, "")

			var aid, alabel string
			if known {
				aid, alabel = "aws:"+acct, acct
			} else {
				aid, alabel = "aws:unknown", "unknown (templated)"
			}
			b.addNode(aid, NodeAWSAccount, alabel, "high", map[string]any{"account_id": acct, "known": known})
			b.addEdge(oid, aid, EdgeInAccount, "")
		}
	}
}

// upsertAction creates or upgrades an action node. An action node's risk is
// "high" if any usage across the org is unpinned (tag/branch ref), since a
// single unpinned reference is hijackable.
func (b *builder) upsertAction(id string, a models.ActionRef) {
	risk := "low"
	if !a.Pinned {
		risk = "high"
	}
	if existing, ok := b.g.byID[id]; ok {
		if risk == "high" {
			existing.Risk = "high"
		}
		if u, _ := existing.Meta["uses"].(int); true {
			existing.Meta["uses"] = u + 1
		}
		return
	}
	b.addNode(id, NodeAction, a.Owner+"/"+a.Name, risk, map[string]any{
		"owner": a.Owner, "name": a.Name, "kind": a.Kind,
		"pinned": a.Pinned, "uses": 1,
	})
}

// computeRepoRisk derives each repo's risk from the worst-risk workflow it owns.
func (b *builder) computeRepoRisk(repos map[string]bool) {
	rank := map[string]int{"high": 3, "medium": 2, "low": 1, "none": 0}
	for _, id := range b.order {
		n := b.g.byID[id]
		if n.Type != NodeRepo {
			continue
		}
		worst := "none"
		for _, dst := range b.g.out[id] {
			if t := b.g.byID[dst]; t != nil && t.Type == NodeWorkflow {
				if rank[t.Risk] > rank[worst] {
					worst = t.Risk
				}
			}
		}
		n.Risk = worst
	}
}

// --- helpers ----------------------------------------------------------------

func collectRepos(r *models.OrgReport) map[string]bool {
	repos := map[string]bool{}
	add := func(name string) {
		if name != "" {
			repos[name] = true
		}
	}
	for _, wf := range r.WorkflowFiles {
		add(wf.RepoName)
	}
	for _, wp := range r.WorkflowPerms {
		add(wp.RepoName)
	}
	for _, s := range r.Secrets {
		add(s.RepoName)
	}
	for _, dk := range r.DeployKeys {
		add(dk.RepoName)
	}
	return repos
}

// isSelfRepoAction reports whether a cross-repo action reference actually points
// at the workflow's OWN repository — e.g. a workflow in acme/security-stage
// using `acme/security-stage/.github/actions/x@master`. That's the same repo's
// code (equivalent to a local ./x action), first-party, not a third-party
// dependency — so it shouldn't count as a supply-chain / hijack entry point.
func isSelfRepoAction(a models.ActionRef, org, repo string) bool {
	if org == "" || repo == "" || a.Owner == "" {
		return false
	}
	seg := a.Name // owner stripped already; first segment is the repo
	if i := strings.Index(seg, "/"); i != -1 {
		seg = seg[:i]
	}
	return strings.EqualFold(a.Owner, org) && strings.EqualFold(seg, repo)
}

// orgAvatarFromApps returns the org's avatar URL, taken from any installed
// app's account (the org the apps are installed on). Sourcing it from the
// persisted app records means it survives a cache reload, unlike a transient
// report-level field.
func orgAvatarFromApps(apps []models.AppInstallation) string {
	for _, a := range apps {
		if a.OrgAvatarURL != "" {
			return a.OrgAvatarURL
		}
	}
	return ""
}

func verifiedProviderLabel(provider string) string {
	switch provider {
	case "aws":
		return "AWS (verified)"
	case "github":
		return "GitHub token (verified)"
	case "gcp":
		return "GCP (verified)"
	case "slack":
		return "Slack (verified)"
	case "stripe":
		return "Stripe (verified)"
	case "generic":
		return "Credential (verified present)"
	default:
		return provider + " (verified)"
	}
}

func isProdLike(env string) bool {
	e := strings.ToLower(env)
	return strings.Contains(e, "prod") || strings.Contains(e, "production") || strings.Contains(e, "release")
}

func secretRisk(s models.OrgSecret) string {
	if s.Scope == "org" && s.Visibility == "all" {
		return "high"
	}
	if s.Scope == "org" {
		return "medium"
	}
	return "low"
}

func hijackLabel(a models.ActionRef) string {
	if a.Pinned {
		return "uses (pinned)"
	}
	return "hijackable"
}

func roleLabel(role string) string {
	if i := strings.LastIndex(role, "/"); i != -1 && i < len(role)-1 {
		return role[i+1:]
	}
	if i := strings.LastIndex(role, ":"); i != -1 && i < len(role)-1 {
		return role[i+1:]
	}
	return role
}

func shortRepo(full string) string {
	if i := strings.LastIndex(full, "/"); i != -1 {
		return full[i+1:]
	}
	return full
}

func repoID(name string) string           { return "repo:" + name }
func workflowID(repo, file string) string { return "workflow:" + repo + "/" + file }

func actionID(a models.ActionRef) string {
	if a.Owner == "" && a.Name == "" {
		return ""
	}
	return "action:" + a.Owner + "/" + a.Name
}

func secretID(s models.OrgSecret) string {
	return "secret:" + s.Scope + ":" + s.Name + ":" + s.RepoName + ":" + s.EnvName
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// NodeRef is a slim node descriptor for the search index (no meta/edges).
type NodeRef struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	Risk  string `json:"risk"`
}

// NodeIndex returns slim descriptors for searchable nodes — everything except
// the bulky repo tier and the synthetic all_repos hub, which aren't useful
// search targets on their own.
func (g *Graph) NodeIndex() []NodeRef {
	out := make([]NodeRef, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		if n.Type == NodeRepo || n.Type == NodeAllRepos {
			continue
		}
		out = append(out, NodeRef{ID: n.ID, Type: n.Type, Label: n.Label, Risk: n.Risk})
	}
	return out
}

// sortDeterministic gives stable node/edge ordering across requests.
func (g *Graph) sortDeterministic() {
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool { return g.Edges[i].ID < g.Edges[j].ID })
}
