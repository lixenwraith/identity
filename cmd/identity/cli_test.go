package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/lixenwraith/identity/internal/dbtest"
	"github.com/lixenwraith/identity/internal/store"
)

// The operator's commands run over the store with the service's own flags,
// the password from standard input when it is not a terminal.
func TestTheOperatorCommandsRunOverTheStore(t *testing.T) {
	pool := dbtest.Pool(t)
	dbtest.Reset(t, pool)
	ctx := context.Background()
	flags := []string{"-db-url", os.Getenv(dbtest.URLVar), "-db-password-file", os.Getenv(dbtest.PasswordFileVar),
		"-db-ca-file", os.Getenv(dbtest.CAVar), "-kdf-memory", "8192", "-kdf-time", "1", "-kdf-threads", "1"}
	run := func(stdin string, args ...string) (string, error) {
		t.Helper()
		var out bytes.Buffer
		err := cli(ctx, append(args, flags...), strings.NewReader(stdin), &out, &out)
		return out.String(), err
	}
	if out, err := run("", "account", "list"); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("a command before the migration: %q, %v", out, err)
	}
	if out, err := run("", "migrate"); err != nil || !strings.Contains(out, "from version 0 to 1") {
		t.Fatalf("migrate: %q, %v", out, err)
	}
	if out, err := run("", "migrate"); err != nil || !strings.Contains(out, "nothing to apply") {
		t.Fatalf("a second migrate: %q, %v", out, err)
	}
	if _, err := run("", "account", "add", "alice"); err == nil {
		t.Fatal("an account was added without a password")
	}
	if _, err := run("short\n", "account", "add", "alice"); err == nil {
		t.Fatal("an account was added with a weak password")
	}
	if out, err := run("a-long-example-password\n", "account", "add", "Alice"); err != nil || !strings.Contains(out, " alice;") {
		t.Fatalf("add: %q, %v", out, err)
	}
	if _, err := run("a-long-example-password\n", "account", "add", "alice"); !errors.Is(err, store.ErrNameTaken) {
		t.Fatalf("a second add: %v", err)
	}
	if out, err := run("", "account", "list"); err != nil || !strings.Contains(out, "alice") || !strings.Contains(out, "enabled") {
		t.Fatalf("list: %q, %v", out, err)
	}
	if out, err := run("", "account", "disable", "alice"); err != nil || !strings.Contains(out, "disabled alice") {
		t.Fatalf("disable: %q, %v", out, err)
	}
	if out, err := run("", "account", "list"); err != nil || !strings.Contains(out, "disabled 2") {
		t.Fatalf("list of a disabled account: %q, %v", out, err)
	}
	if out, err := run("", "account", "enable", "alice"); err != nil || !strings.Contains(out, "enabled alice") {
		t.Fatalf("enable: %q, %v", out, err)
	}
	st := store.New(pool)
	a, err := st.AccountByName(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	before, err := st.Verifiers(ctx)
	if err != nil || len(before) != 1 || before[0].ArgonMemory != 8192 || before[0].ArgonThreads != 1 {
		t.Fatalf("the verifier the CLI derived: %+v, %v", before, err)
	}
	now := store.Now()
	if err := st.CreateSignIn(ctx, store.SignIn{ID: store.NewID(), AccountID: a.ID, TokenHash: store.HashToken("t"), Device: "laptop",
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(store.SignInLifetime)}); err != nil {
		t.Fatal(err)
	}
	if out, err := run("another-long-password\n", "account", "reset", "alice"); err != nil || !strings.Contains(out, "1 sign-ins deleted") {
		t.Fatalf("reset: %q, %v", out, err)
	}
	if after, err := st.Verifiers(ctx); err != nil || len(after) != 1 || bytes.Equal(after[0].StoredKey, before[0].StoredKey) {
		t.Fatalf("the verifier after the reset: %+v, %v", after, err)
	}
	if out, err := run("", "account", "delete", "alice"); err != nil || !strings.Contains(out, "deleted") {
		t.Fatalf("delete: %q, %v", out, err)
	}
	if _, err := run("", "account", "delete", "alice"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second delete: %v", err)
	}
	for _, args := range [][]string{{"account"}, {"account", "bogus", "alice"}, {"account", "disable"}, {"account", "add", "7up"}} {
		if _, err := run("", args...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	var out bytes.Buffer
	if err := cli(ctx, []string{"migrate", "-h"}, strings.NewReader(""), &out, &out); !errors.Is(err, flag.ErrHelp) || !strings.Contains(out.String(), "identity account") {
		t.Fatalf("-h: %v, %q", err, out.String())
	}
}
