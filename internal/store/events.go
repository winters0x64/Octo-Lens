package store

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	EventEntityPAT           = "pat"
	EventEntityPATRequest    = "pat_request"
	EventEntitySSOCredential = "sso_credential"

	EventKindCreated      = "created"
	EventKindStatusChange = "status_change"
	EventKindFieldChange  = "field_change"
	EventKindRemoved      = "removed"
)

// EventWrite is one row to append. Snapshot must be JSON-encodable.
type EventWrite struct {
	EntityType       string
	EntityID         string
	Kind             string
	OldStatus        string
	NewStatus        string
	ChangedFields    []string
	Snapshot         any
	PolicyViolations []string
}

// Event is the read shape, JSONB columns kept as raw to let callers decide.
type Event struct {
	ID               int64
	ScanRunID        int64
	OccurredAt       time.Time
	EntityType       string
	EntityID         string
	Kind             string
	OldStatus        *string
	NewStatus        *string
	ChangedFields    []string
	Snapshot         json.RawMessage
	PolicyViolations json.RawMessage
}

// BatchInsertEvents writes events in a single round-trip via pgx.CopyFrom.
// All rows share the same scan_run_id and occurred_at so callers don't pass them per-event.
func BatchInsertEvents(ctx context.Context, tx pgx.Tx, scanRunID int64, occurredAt time.Time, events []EventWrite) error {
	if len(events) == 0 {
		return nil
	}

	rows := make([][]any, len(events))
	for i, e := range events {
		snap, err := json.Marshal(e.Snapshot)
		if err != nil {
			return err
		}
		viol, err := json.Marshal(orEmpty(e.PolicyViolations))
		if err != nil {
			return err
		}
		var oldStatus, newStatus any
		if e.OldStatus != "" {
			oldStatus = e.OldStatus
		}
		if e.NewStatus != "" {
			newStatus = e.NewStatus
		}
		changed := e.ChangedFields
		if changed == nil {
			changed = []string{}
		}
		rows[i] = []any{
			scanRunID, occurredAt, e.EntityType, e.EntityID, e.Kind,
			oldStatus, newStatus, changed, snap, viol,
		}
	}

	_, err := tx.CopyFrom(ctx,
		pgx.Identifier{"events"},
		[]string{
			"scan_run_id", "occurred_at", "entity_type", "entity_id", "event_kind",
			"old_status", "new_status", "changed_fields", "snapshot", "policy_violations",
		},
		pgx.CopyFromRows(rows),
	)
	return err
}

// ListEventsByEntity returns events for a single entity, newest first.
func ListEventsByEntity(ctx context.Context, q Querier, entityType, entityID string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	const sqlSelect = `
SELECT id, scan_run_id, occurred_at, entity_type, entity_id, event_kind,
       old_status, new_status, changed_fields, snapshot, policy_violations
FROM events
WHERE entity_type = $1 AND entity_id = $2
ORDER BY occurred_at DESC
LIMIT $3`
	rows, err := q.Query(ctx, sqlSelect, entityType, entityID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// EventFilter narrows the event feed.
type EventFilter struct {
	Since      *time.Time
	EntityType string
	Kind       string
	Limit      int
}

// ListEvents returns events matching the filter, newest first.
func ListEvents(ctx context.Context, q Querier, f EventFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	sqlStr := `
SELECT id, scan_run_id, occurred_at, entity_type, entity_id, event_kind,
       old_status, new_status, changed_fields, snapshot, policy_violations
FROM events
WHERE 1=1`
	args := []any{}
	if f.Since != nil {
		args = append(args, *f.Since)
		sqlStr += " AND occurred_at >= $" + strconv.Itoa(len(args))
	}
	if f.EntityType != "" {
		args = append(args, f.EntityType)
		sqlStr += " AND entity_type = $" + strconv.Itoa(len(args))
	}
	if f.Kind != "" {
		args = append(args, f.Kind)
		sqlStr += " AND event_kind = $" + strconv.Itoa(len(args))
	}
	args = append(args, f.Limit)
	sqlStr += " ORDER BY occurred_at DESC LIMIT $" + strconv.Itoa(len(args))

	rows, err := q.Query(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows pgx.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.ScanRunID, &e.OccurredAt, &e.EntityType, &e.EntityID, &e.Kind,
			&e.OldStatus, &e.NewStatus, &e.ChangedFields, &e.Snapshot, &e.PolicyViolations,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

