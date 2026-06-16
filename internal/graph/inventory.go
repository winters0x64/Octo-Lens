package graph

import (
	"sort"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ActionInventoryItem is one row of the org-wide GitHub Actions inventory: a
// distinct action (owner/name) with the versions in use and how widely it is
// used.
type ActionInventoryItem struct {
	Identifier string   `json:"identifier"` // owner/name
	Kind       string   `json:"kind"`       // marketplace | reusable_workflow
	Trust      string   `json:"trust"`      // first_party | verified | third_party
	TrustLabel string   `json:"trust_label"`
	Versions   []string `json:"versions"`   // distinct refs in use (tags/branches/SHAs)
	AllPinned  bool     `json:"all_pinned"` // every usage pinned to a commit SHA
	Workflows  int      `json:"workflows"`  // distinct workflow files referencing it
	Repos      int      `json:"repos"`      // distinct repositories referencing it
	Uses       int      `json:"uses"`       // total references across the org
}

type actionAgg struct {
	owner, name, kind string
	versions          map[string]bool
	repos             map[string]bool
	files             map[string]bool
	uses, pinned      int
}

// InventoryActions aggregates every `uses:` reference across all workflow files
// into a deduped inventory. Local (./…) and Docker actions are skipped — they
// have no owner/version to inventory.
func InventoryActions(r *models.OrgReport) []ActionInventoryItem {
	m := map[string]*actionAgg{}

	for _, wf := range r.WorkflowFiles {
		for _, a := range wf.Actions {
			if a.Owner == "" || a.Kind == "local" || a.Kind == "docker" {
				continue
			}
			id := a.Owner + "/" + a.Name
			g := m[id]
			if g == nil {
				g = &actionAgg{owner: a.Owner, name: a.Name, kind: a.Kind,
					versions: map[string]bool{}, repos: map[string]bool{}, files: map[string]bool{}}
				m[id] = g
			}
			ref := a.Ref
			if ref == "" {
				ref = "(unspecified)"
			}
			g.versions[ref] = true
			g.repos[wf.RepoName] = true
			g.files[wf.RepoName+"/"+wf.FileName] = true
			g.uses++
			if a.Pinned {
				g.pinned++
			}
		}
	}

	out := make([]ActionInventoryItem, 0, len(m))
	for id, g := range m {
		trust := actionTrust(g.owner)
		out = append(out, ActionInventoryItem{
			Identifier: id,
			Kind:       g.kind,
			Trust:      trust,
			TrustLabel: trustLabel(trust),
			Versions:   sortedKeys(g.versions),
			AllPinned:  g.pinned == g.uses,
			Workflows:  len(g.files),
			Repos:      len(g.repos),
			Uses:       g.uses,
		})
	}

	// Most-used first; ties broken alphabetically for stable output.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workflows != out[j].Workflows {
			return out[i].Workflows > out[j].Workflows
		}
		return out[i].Identifier < out[j].Identifier
	})
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
