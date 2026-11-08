package store

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/lixenwraith/identity/internal/pg"

	"github.com/lixenwraith/auth"
)

func TestANameHasOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"Alice": "alice", " bob_7 ": "bob_7", "x-y": "x-y",
		"a123456789012345678901234567890b": "a123456789012345678901234567890b",
	} {
		got, err := NormalizeName(in)
		if err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "7up", "_a", "-a", "a b", "a,b", "a=b", "é", "a123456789012345678901234567890bc"} {
		if _, err := NormalizeName(in); !errors.Is(err, ErrInvalidName) {
			t.Errorf("NormalizeName(%q) accepted", in)
		}
	}
}

func TestAVerifierIsTheCredentialWithoutItsPassword(t *testing.T) {
	cred, err := auth.NewCredential("alice", "a-long-example-password", auth.WithMemory(8*1024), auth.WithTime(1))
	if err != nil {
		t.Fatal(err)
	}
	v := VerifierOf("00000000-0000-4000-8000-000000000000", cred)
	back := v.Credential()
	if back.Username != "alice" || !bytes.Equal(back.StoredKey, cred.StoredKey) || !bytes.Equal(back.ServerKey, cred.ServerKey) ||
		!bytes.Equal(back.Salt, cred.Salt) || back.ArgonMemory != cred.ArgonMemory || back.ArgonTime != cred.ArgonTime ||
		back.ArgonThreads != cred.ArgonThreads {
		t.Fatalf("round trip lost a field: %+v", back)
	}
	if err := back.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAnIDIsACanonicalUUID(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]bool)
	for range 64 {
		id := NewID()
		if !pattern.MatchString(id) || seen[id] {
			t.Fatalf("NewID() = %q", id)
		}
		seen[id] = true
	}
	if len(HashToken("x")) != 32 {
		t.Fatal("HashToken is not a SHA-256")
	}
}

// Every statement reaches the pool, and the pool's refusal reaches the caller
// unchanged: the store adds no retry and hides no error.
func TestTheStoreReportsThePoolsRefusal(t *testing.T) {
	s := New(nil)
	ctx := context.Background()
	if _, _, err := s.Migrate(ctx); !errors.Is(err, pg.ErrNotImplemented) {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.CheckSchema(ctx); !errors.Is(err, pg.ErrNotImplemented) {
		t.Fatalf("CheckSchema: %v", err)
	}
	if _, err := s.CreateAccount(ctx, "alice", Verifier{}, 0); !errors.Is(err, pg.ErrNotImplemented) {
		t.Fatalf("CreateAccount: %v", err)
	}
	if _, err := s.CreateAccount(ctx, "7up", Verifier{}, 0); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("CreateAccount with a bad name: %v", err)
	}
	if _, _, err := s.SignInByToken(ctx, HashToken("x")); !errors.Is(err, pg.ErrNotImplemented) {
		t.Fatalf("SignInByToken: %v", err)
	}
	if err := s.DeleteSignIn(ctx, NewID(), NewID()); !errors.Is(err, pg.ErrNotImplemented) {
		t.Fatalf("DeleteSignIn: %v", err)
	}
}
