package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the file adds to the shared behaviour: the store outlives the process,
// one writer holds it, a reader takes it beside the writer, and a file the
// binary does not know is refused.
func TestAFileStoreIsHeldByOneWriterAndOutlivesIt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.json")
	f, err := OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v, %v", info, err)
	}
	if _, err := OpenFile(path, false); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second writer: %v", err)
	}
	a, err := f.CreateAccount(ctx, "alice", VerifierOf("", credential(t, "alice")), 0)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if list, err := reader.Accounts(ctx); err != nil || len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("the reader's accounts: %+v, %v", list, err)
	}
	if err := reader.SetDisabled(ctx, a.ID, true); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("a read-only change: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = OpenFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, err := f.AccountByName(ctx, "alice"); err != nil || got.ID != a.ID || !got.CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("after a reopen: %+v, %v", got, err)
	}
	if from, to, err := f.Migrate(ctx); err != nil || from != FileVersion || to != FileVersion {
		t.Fatalf("Migrate = %d, %d, %v", from, to, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 2 {
		t.Fatalf("the directory holds more than the store and its lock: %v", entries)
	}

	newer := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(newer, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(newer, false); !errors.Is(err, ErrSchema) {
		t.Fatalf("a newer file: %v", err)
	}
	torn := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(torn, []byte(`{"version":1,"accounts":[{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(torn, false); err == nil || !strings.Contains(err.Error(), "not a store file") {
		t.Fatalf("a torn file: %v", err)
	}
	if _, err := OpenFile("relative/store.json", false); err == nil {
		t.Fatal("a relative path was accepted")
	}
}
