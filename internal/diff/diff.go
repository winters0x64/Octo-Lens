// Package diff is the pure-function layer that converts (existing DB rows,
// fresh scan results) into (current-row updates, event log entries).
//
// It depends only on the model types and the policy engine — no Postgres,
// no networking — so the logic can be exercised by table-driven unit tests
// without touching a database.
package diff

import (
	"sort"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// Op describes what should happen to the current-state row for an entity.
type Op int

const (
	OpInsert      Op = iota // not in DB before
	OpUpdate                // in DB; status or watched field changed
	OpTouch                 // in DB; only last_seen_at needs bumping (no event)
	OpMarkRemoved           // in DB; gone from the latest scan
)

// Event is one row to append to the events table.
type Event struct {
	Kind             string
	OldStatus        string
	NewStatus        string
	ChangedFields    []string
	Snapshot         any
	PolicyViolations []string
}

// permKey is a stable identity for a Permission used when diffing the slice.
type permKey struct{ name, level string }

func permSet(perms []models.Permission) map[permKey]bool {
	m := make(map[permKey]bool, len(perms))
	for _, p := range perms {
		m[permKey{p.Name, p.Level}] = true
	}
	return m
}

// permsEqual compares two permission slices ignoring order.
func permsEqual(a, b []models.Permission) bool {
	if len(a) != len(b) {
		return false
	}
	return mapsEqual(permSet(a), permSet(b))
}

func mapsEqual(a, b map[permKey]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// stringSliceEqual compares two slices ignoring order.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// timesEqual compares two *time.Time pointers, treating nil==nil as equal.
func timesEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
}
