// Package storetest opens the store a test runs against: PostgreSQL when the
// environment names one (dbtest), reset and migrated, and otherwise a file in
// the test's temporary directory, so every handler and command test runs
// without a database and against one in CI.
package storetest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lixenwraith/identity/internal/dbtest"
	"github.com/lixenwraith/identity/internal/store"
)

// Target is the store under test and the flags that name it to the command
// line, so a command opens the same one.
type Target struct {
	Store store.Store
	Flags []string
	PG    bool
	path  string
}

func Open(t testing.TB) Target {
	t.Helper()
	if os.Getenv(dbtest.URLVar) != "" {
		pool := dbtest.Pool(t)
		dbtest.Reset(t, pool)
		st := store.NewPG(pool)
		if _, _, err := st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		return Target{Store: st, PG: true, Flags: []string{"-db-url", os.Getenv(dbtest.URLVar),
			"-db-password-file", os.Getenv(dbtest.PasswordFileVar), "-db-ca-file", os.Getenv(dbtest.CAVar)}}
	}
	path := filepath.Join(t.TempDir(), "store.json")
	target := Target{Flags: []string{"-store-file", path}, path: path}
	target.Store = target.open(t)
	return target
}

// Reopen gives a command the file: a file store is held by whoever has it
// open, so the test's own handle closes first and comes back after.
func (target *Target) Reopen(t testing.TB, during func()) {
	t.Helper()
	if target.PG {
		during()
		return
	}
	_ = target.Store.(*store.File).Close()
	during()
	target.Store = target.open(t)
}

func (target Target) open(t testing.TB) store.Store {
	t.Helper()
	f, err := store.OpenFile(target.path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
