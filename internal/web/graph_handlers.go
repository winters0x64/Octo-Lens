package web

import (
	"net/http"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/graph"
)

// currentGraph returns the reachability graph for the latest scan, building and
// memoizing it on first use per scan. The report pointer is immutable once
// swapped in by runScan, so the graph is built without holding s.mu.
func (s *Server) currentGraph() (*graph.Graph, bool) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		return nil, false
	}

	s.graphMu.Lock()
	defer s.graphMu.Unlock()
	if s.graphCache != nil && s.graphCacheTS.Equal(report.ScannedAt) {
		return s.graphCache, true
	}
	g := graph.Build(report)
	s.graphCache = g
	s.graphCacheTS = report.ScannedAt
	return g, true
}

// handleAttackGraph returns the full reachability graph (nodes + edges) for the
// Explore view.
func (s *Server) handleAttackGraph(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g)
}

// handleAttackGraphNodes returns slim node descriptors for the search index,
// without the full edge set — keeps the focus-first UI from fetching the whole
// graph just to populate search.
func (s *Server) handleAttackGraphNodes(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g.NodeIndex())
}

// handleAttackAnalytics returns the ranked findings: largest blast radius,
// most-privileged workflows, risky third-party actions, and paths to prod.
func (s *Server) handleAttackAnalytics(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g.Analytics())
}

// handleAttackFindings returns the insight-first payload: ranked attack paths
// to production and prioritized remediation action items.
func (s *Server) handleAttackFindings(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g.Findings())
}

// handleActionsInventory returns the org-wide inventory of GitHub Actions and
// the versions in use.
func (s *Server) handleActionsInventory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, graph.InventoryActions(report))
}

// handleBlastRadius answers "what does this node reach, and what reaches it?"
// for the node given by ?id=<nodeID>.
func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"missing id query parameter"}`, http.StatusBadRequest)
		return
	}
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	res, found := g.BlastRadius(id)
	if !found {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, res)
}
