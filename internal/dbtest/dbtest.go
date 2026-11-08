// Package dbtest opens the PostgreSQL a test environment names, or skips the
// test without one: IDENTITY_TEST_DB_URL in the service's own URL form,
// IDENTITY_TEST_DB_CA the certificate the server is verified against and
// IDENTITY_TEST_DB_PASSWORD_FILE the role's password, as the service reads it.
package dbtest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/lixenwraith/identity/internal/pg"
)

const (
	URLVar          = "IDENTITY_TEST_DB_URL"
	CAVar           = "IDENTITY_TEST_DB_CA"
	PasswordFileVar = "IDENTITY_TEST_DB_PASSWORD_FILE"
)

// Pool connects to the test database and holds it for this test alone: the
// packages' tests run as parallel processes on one database, so each test
// takes a lock on a file in the temporary directory until it ends.
func Pool(t testing.TB) *pg.Pool {
	t.Helper()
	raw := os.Getenv(URLVar)
	if raw == "" {
		t.Skipf("%s is not set; a database test needs PostgreSQL", URLVar)
	}
	cfg, err := pg.ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	password, err := os.ReadFile(os.Getenv(PasswordFileVar))
	if err != nil {
		t.Fatalf("%s: %v", PasswordFileVar, err)
	}
	cfg.Password = string(bytes.TrimRight(password, "\r\n"))
	var ca []byte
	if path := os.Getenv(CAVar); path != "" {
		if ca, err = os.ReadFile(path); err != nil {
			t.Fatalf("%s: %v", CAVar, err)
		}
	}
	if cfg.TLS, err = pg.TLSConfig(ca, cfg.Host); err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 3
	lock(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pg.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// Reset drops the service's tables, so the test migrates a fresh schema and
// finds nothing another test left.
func Reset(t testing.TB, pool *pg.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS sign_ins, verifiers, accounts, schema_version`); err != nil {
		t.Fatal(err)
	}
}

func lock(t testing.TB) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "identity-test-db.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	})
}
