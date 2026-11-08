package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/lixenwraith/identity/internal/pg"
	"github.com/lixenwraith/identity/schema"
)

// Migrate applies the embedded migrations the database lacks, in one
// transaction under an advisory lock, so two migrators serialize and a failed
// upgrade leaves the previous version whole. It issues no DDL when the schema
// is current, so a runtime role without the right to alter it can start.
func (s *PG) Migrate(ctx context.Context) (from, to int, err error) {
	list, err := schema.Migrations()
	if err != nil {
		return 0, 0, err
	}
	to = list[len(list)-1].Version
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLockKey); err != nil {
		return 0, 0, err
	}
	if from, err = schemaVersion(ctx, tx); err != nil {
		return 0, 0, err
	}
	if from > to {
		return from, to, fmt.Errorf("%w: database at version %d, binary at %d", ErrSchema, from, to)
	}
	for _, m := range list[from:] {
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return from, to, fmt.Errorf("store: migration %03d_%s: %w", m.Version, m.Name, err)
		}
	}
	if got, err := schemaVersion(ctx, tx); err != nil || got != to {
		return from, to, fmt.Errorf("%w: version %d recorded after migrating to %d", ErrSchema, got, to)
	}
	return from, to, tx.Commit(ctx)
}

// CheckSchema holds the database to the version the binary was built for,
// without touching it: the service's gate at start.
func (s *PG) CheckSchema(ctx context.Context) error {
	list, err := schema.Migrations()
	if err != nil {
		return err
	}
	got, err := schemaVersion(ctx, s.db)
	if err != nil {
		return err
	}
	if want := list[len(list)-1].Version; got != want {
		return fmt.Errorf("%w: database at version %d, binary at %d", ErrSchema, got, want)
	}
	return nil
}

// schemaVersion is 0 for a database the first migration has not reached.
func schemaVersion(ctx context.Context, q querier) (int, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('schema_version') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var version int
	err := q.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&version)
	if errors.Is(err, pg.ErrNoRows) {
		return 0, nil
	}
	return version, err
}
