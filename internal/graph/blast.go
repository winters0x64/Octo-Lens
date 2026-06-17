package graph

import "sort"

// Reach is the set of nodes reachable in one direction, grouped for display.
type Reach struct {
	Nodes    []Node         `json:"nodes"`     // all reachable nodes (excluding the origin)
	ByType   map[string]int `json:"by_type"`   // count per node type
	EdgeIDs  []string       `json:"edge_ids"`  // edges traversed (for subgraph highlight)
}

// BlastResult answers "what does this node reach, and what reaches it?"
//
//   - Downstream (forward closure): what a compromise of this node can affect.
//     For an action/principal/workflow this is the blast radius of a compromise.
//   - Upstream (reverse closure): what depends on this node. For a secret this
//     answers "if I rotate it, what breaks?".
type BlastResult struct {
	Origin     Node     `json:"origin"`
	Downstream Reach    `json:"downstream"`
	Upstream   Reach    `json:"upstream"`
	Summary    []Stat   `json:"summary"`
	Subgraph   Subgraph `json:"subgraph"` // self-contained: origin + reachable nodes + connecting edges
}

// Subgraph is a standalone, renderable slice of the graph.
type Subgraph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Stat is a single headline number for the blast-radius summary panel.
type Stat struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

// BlastRadius computes the forward and reverse reachable sets from a node.
func (g *Graph) BlastRadius(nodeID string) (*BlastResult, bool) {
	origin, ok := g.byID[nodeID]
	if !ok {
		return nil, false
	}
	res := &BlastResult{Origin: *origin}
	res.Downstream = g.traverse(nodeID, g.out)
	res.Upstream = g.traverse(nodeID, g.in)
	res.Summary = g.summarize(origin, res)
	res.Subgraph = g.subgraph(nodeID, res)
	return res, true
}

// subgraph assembles the standalone slice spanning the origin and everything in
// its forward and reverse reachable sets, plus all edges between those nodes.
func (g *Graph) subgraph(originID string, res *BlastResult) Subgraph {
	inSet := map[string]bool{originID: true}
	for _, n := range res.Downstream.Nodes {
		inSet[n.ID] = true
	}
	for _, n := range res.Upstream.Nodes {
		inSet[n.ID] = true
	}
	var sg Subgraph
	if n := g.byID[originID]; n != nil {
		sg.Nodes = append(sg.Nodes, *n)
	}
	sg.Nodes = append(sg.Nodes, res.Downstream.Nodes...)
	sg.Nodes = append(sg.Nodes, res.Upstream.Nodes...)
	for _, e := range g.Edges {
		if inSet[e.Source] && inSet[e.Target] {
			sg.Edges = append(sg.Edges, e)
		}
	}
	return sg
}

// traverse runs BFS from start over the given adjacency map, collecting reached
// nodes (excluding start) and the edges within the reached component (for
// subgraph highlighting). It is direction-agnostic: pass g.out for downstream,
// g.in for upstream.
func (g *Graph) traverse(start string, adj map[string][]string) Reach {
	seen := map[string]bool{start: true}
	queue := []string{start}
	r := Reach{ByType: map[string]int{}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
			if n := g.byID[next]; n != nil {
				r.Nodes = append(r.Nodes, *n)
				r.ByType[n.Type]++
			}
		}
	}

	// Highlight every edge whose endpoints are both in the reached component
	// (including the origin) — works for both traversal directions.
	for _, e := range g.Edges {
		if seen[e.Source] && seen[e.Target] {
			r.EdgeIDs = append(r.EdgeIDs, e.ID)
		}
	}
	sort.Slice(r.Nodes, func(i, j int) bool {
		if r.Nodes[i].Type != r.Nodes[j].Type {
			return r.Nodes[i].Type < r.Nodes[j].Type
		}
		return r.Nodes[i].Label < r.Nodes[j].Label
	})
	sort.Strings(r.EdgeIDs)
	return r
}

// reachableTypeCount returns how many nodes of a given type are forward
// reachable from start — used by analytics.
func (g *Graph) reachableTypeCount(start, typ string) int {
	seen := map[string]bool{start: true}
	queue := []string{start}
	count := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range g.out[cur] {
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
			if n := g.byID[next]; n != nil && n.Type == typ {
				count++
			}
		}
	}
	return count
}

// upstreamTypeCount returns how many nodes of a given type can reach start.
func (g *Graph) upstreamTypeCount(start, typ string) int {
	seen := map[string]bool{start: true}
	queue := []string{start}
	count := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, prev := range g.in[cur] {
			if seen[prev] {
				continue
			}
			seen[prev] = true
			queue = append(queue, prev)
			if n := g.byID[prev]; n != nil && n.Type == typ {
				count++
			}
		}
	}
	return count
}

func (g *Graph) summarize(origin *Node, res *BlastResult) []Stat {
	switch origin.Type {
	case NodeSecret:
		return []Stat{
			{Label: "Workflows using this secret", Value: res.Upstream.ByType[NodeWorkflow]},
			{Label: "Repositories affected", Value: res.Upstream.ByType[NodeRepo]},
			{Label: "Principals with reach", Value: res.Upstream.ByType[NodePAT] + res.Upstream.ByType[NodeApp] + res.Upstream.ByType[NodeDeployKey]},
		}
	case NodeAction:
		return []Stat{
			{Label: "Workflows impacted", Value: res.Downstream.ByType[NodeWorkflow]},
			{Label: "Secrets reachable", Value: res.Downstream.ByType[NodeSecret]},
			{Label: "OIDC roles reachable", Value: res.Downstream.ByType[NodeOIDCRole]},
		}
	default:
		return []Stat{
			{Label: "Repositories reachable", Value: res.Downstream.ByType[NodeRepo]},
			{Label: "Workflows reachable", Value: res.Downstream.ByType[NodeWorkflow]},
			{Label: "Secrets reachable", Value: res.Downstream.ByType[NodeSecret]},
			{Label: "OIDC roles reachable", Value: res.Downstream.ByType[NodeOIDCRole]},
		}
	}
}
