package web

import (
	"net/http"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ScanDiff holds the delta between two consecutive scans.
type ScanDiff struct {
	HasPrev        bool                     `json:"has_prev"`
	ScannedAt      time.Time                `json:"scanned_at"`
	PrevScannedAt  *time.Time               `json:"prev_scanned_at,omitempty"`
	NewPATs        []models.PATInfo         `json:"new_pats"`
	RemovedPATs    []models.PATInfo         `json:"removed_pats"`
	ChangedPATs    []PATDiff                `json:"changed_pats"`
	NewApps        []models.AppInstallation `json:"new_apps"`
	RemovedApps    []models.AppInstallation `json:"removed_apps"`
	NewSecrets     []models.OrgSecret       `json:"new_secrets"`
	RemovedSecrets []models.OrgSecret       `json:"removed_secrets"`
	NewDeployKeys  []models.DeployKey       `json:"new_deploy_keys"`
	TotalChanges   int                      `json:"total_changes"`
}

// PATDiff holds a changed PAT and the list of fields that changed.
type PATDiff struct {
	PAT    models.PATInfo `json:"pat"`
	Fields []string       `json:"changed_fields"`
}

func computeDiff(prev, curr *models.OrgReport) ScanDiff {
	d := ScanDiff{HasPrev: prev != nil, ScannedAt: curr.ScannedAt}
	if prev == nil {
		return d
	}
	t := prev.ScannedAt
	d.PrevScannedAt = &t

	// PATs — keyed by ID
	prevPATs := make(map[int64]models.PATInfo, len(prev.PATs))
	for _, p := range prev.PATs {
		prevPATs[p.ID] = p
	}
	currPATIDs := make(map[int64]bool, len(curr.PATs))
	for _, p := range curr.PATs {
		currPATIDs[p.ID] = true
		if old, exists := prevPATs[p.ID]; !exists {
			d.NewPATs = append(d.NewPATs, p)
		} else {
			var changed []string
			if old.RepositorySelection != p.RepositorySelection {
				changed = append(changed, "repository_selection")
			}
			if !diffPermsEqual(old.Permissions, p.Permissions) {
				changed = append(changed, "permissions")
			}
			if old.TokenExpired != p.TokenExpired {
				changed = append(changed, "status")
			}
			if len(changed) > 0 {
				d.ChangedPATs = append(d.ChangedPATs, PATDiff{PAT: p, Fields: changed})
			}
		}
	}
	for _, p := range prev.PATs {
		if !currPATIDs[p.ID] {
			d.RemovedPATs = append(d.RemovedPATs, p)
		}
	}

	// Apps — keyed by ID
	prevApps := make(map[int64]models.AppInstallation, len(prev.Apps))
	for _, a := range prev.Apps {
		prevApps[a.ID] = a
	}
	currAppIDs := make(map[int64]bool, len(curr.Apps))
	for _, a := range curr.Apps {
		currAppIDs[a.ID] = true
		if _, exists := prevApps[a.ID]; !exists {
			d.NewApps = append(d.NewApps, a)
		}
	}
	for _, a := range prev.Apps {
		if !currAppIDs[a.ID] {
			d.RemovedApps = append(d.RemovedApps, a)
		}
	}

	// Secrets — keyed by scope+name+repo
	prevSecrets := make(map[string]bool, len(prev.Secrets))
	for _, s := range prev.Secrets {
		prevSecrets[s.Scope+"|"+s.Name+"|"+s.RepoName] = true
	}
	currSecrets := make(map[string]bool, len(curr.Secrets))
	for _, s := range curr.Secrets {
		key := s.Scope + "|" + s.Name + "|" + s.RepoName
		currSecrets[key] = true
		if !prevSecrets[key] {
			d.NewSecrets = append(d.NewSecrets, s)
		}
	}
	for _, s := range prev.Secrets {
		if !currSecrets[s.Scope+"|"+s.Name+"|"+s.RepoName] {
			d.RemovedSecrets = append(d.RemovedSecrets, s)
		}
	}

	// Deploy keys — keyed by ID
	prevDKs := make(map[int64]bool, len(prev.DeployKeys))
	for _, dk := range prev.DeployKeys {
		prevDKs[dk.ID] = true
	}
	for _, dk := range curr.DeployKeys {
		if !prevDKs[dk.ID] {
			d.NewDeployKeys = append(d.NewDeployKeys, dk)
		}
	}

	d.TotalChanges = len(d.NewPATs) + len(d.RemovedPATs) + len(d.ChangedPATs) +
		len(d.NewApps) + len(d.RemovedApps) +
		len(d.NewSecrets) + len(d.RemovedSecrets) +
		len(d.NewDeployKeys)

	return d
}

func diffPermsEqual(a, b []models.Permission) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]string, len(a))
	for _, p := range a {
		set[p.Name] = p.Level
	}
	for _, p := range b {
		if set[p.Name] != p.Level {
			return false
		}
	}
	return true
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	curr := s.report
	prev := s.prevReport
	s.mu.RUnlock()

	if curr == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, computeDiff(prev, curr))
}
