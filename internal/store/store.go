// Package store persists scan results and an append-only event log to MySQL.
//
// The schema follows a hybrid current+events pattern: each entity has a row
// reflecting its current state (active/expired/removed) plus a row in `events`
// for every status flip and watched-field change. Snapshots are stored as TEXT
// (JSON-encoded) so point-in-time queries do not require replaying the event stream.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
)

type Store struct {
	db *sql.DB
}

func New(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("empty DATABASE_URL")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening mysql connection: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging mysql: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() {
	s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

// RunMigrations applies the embedded goose migrations against the same
// database the pool is connected to. Safe to call repeatedly.
func (s *Store) RunMigrations(ctx context.Context) error {
	if err := goose.SetDialect("mysql"); err != nil {
		return fmt.Errorf("goose set dialect: %w", err)
	}
	goose.SetBaseFS(migrationsFS)
	if err := goose.UpContext(ctx, s.db, "migrations"); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// Tx runs fn inside a transaction. Commits if fn returns nil; rolls back otherwise.
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning tx: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing tx: %w", err)
	}
	return nil
}

// marshalStringSlice serialises a string slice to a JSON string for storage in a TEXT column.
// MySQL has no native array type; we store arrays as '["a","b"]' text.
func marshalStringSlice(ss []string) (string, error) {
	if ss == nil {
		ss = []string{}
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Querier is the subset of database/sql methods the per-entity helpers need.
// Both *sql.DB and *sql.Tx satisfy this, so query helpers work
// inside or outside transactions.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
