package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
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

// Event is the read shape, JSON columns kept as raw to let callers decide.
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

// BatchInsertEvents writes events one row at a time within the transaction.
// All rows share the same scan_run_id and occurred_at so callers don't pass them per-event.
func BatchInsertEvents(ctx context.Context, tx *sql.Tx, scanRunID int64, occurredAt time.Time, events []EventWrite) error {
	if len(events) == 0 {
		return nil
	}

	const sqlInsert = `
INSERT INTO events (
    scan_run_id, occurred_at, entity_type, entity_id, event_kind,
    old_status, new_status, changed_fields, snapshot, policy_violations
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	for _, e := range events {
		snap, err := json.Marshal(e.Snapshot)
		if err != nil {
			return err
		}
		viol, err := json.Marshal(orEmpty(e.PolicyViolations))
		if err != nil {
			return err
		}

		changed := orEmpty(e.ChangedFields)
		changedJSON, err := json.Marshal(changed)
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

		if _, err := tx.ExecContext(ctx, sqlInsert,
			scanRunID, occurredAt, e.EntityType, e.EntityID, e.Kind,
			oldStatus, newStatus, string(changedJSON), string(snap), string(viol),
		); err != nil {
			return err
		}
	}
	return nil
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
WHERE entity_type = ? AND entity_id = ?
ORDER BY occurred_at DESC
LIMIT ?`
	rows, err := q.QueryContext(ctx, sqlSelect, entityType, entityID, limit)
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
		sqlStr += " AND occurred_at >= ?"
	}
	if f.EntityType != "" {
		args = append(args, f.EntityType)
		sqlStr += " AND entity_type = ?"
	}
	if f.Kind != "" {
		args = append(args, f.Kind)
		sqlStr += " AND event_kind = ?"
	}
	args = append(args, f.Limit)
	sqlStr += " ORDER BY occurred_at DESC LIMIT ?"

	rows, err := q.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		var oldStatus, newStatus sql.NullString
		var changedFieldsJSON []byte
		var snapshotJSON []byte
		var policyViolationsJSON []byte

		if err := rows.Scan(
			&e.ID, &e.ScanRunID, &e.OccurredAt, &e.EntityType, &e.EntityID, &e.Kind,
			&oldStatus, &newStatus, &changedFieldsJSON, &snapshotJSON, &policyViolationsJSON,
		); err != nil {
			return nil, err
		}

		if oldStatus.Valid {
			s := oldStatus.String
			e.OldStatus = &s
		}
		if newStatus.Valid {
			s := newStatus.String
			e.NewStatus = &s
		}

		if err := json.Unmarshal(changedFieldsJSON, &e.ChangedFields); err != nil {
			e.ChangedFields = []string{}
		}
		e.Snapshot = json.RawMessage(snapshotJSON)
		e.PolicyViolations = json.RawMessage(policyViolationsJSON)

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
