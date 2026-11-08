package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/lixenwraith/identity/internal/dbtest"

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
	cred := credential(t, "alice")
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

func credential(t *testing.T, name string) *auth.Credential {
	t.Helper()
	cred, err := auth.NewCredential(name, "a-long-example-password", auth.WithMemory(8*1024), auth.WithTime(1))
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// backends runs a test over each store at hand: the file always, PostgreSQL
// when the environment names one, so the two keep one behaviour.
func backends(t *testing.T, run func(t *testing.T, s Store, ctx context.Context)) {
	t.Helper()
	t.Run("file", func(t *testing.T) {
		f, err := OpenFile(filepath.Join(t.TempDir(), "store.json"), false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		run(t, f, context.Background())
	})
	t.Run("pg", func(t *testing.T) {
		if os.Getenv(dbtest.URLVar) == "" {
			t.Skipf("%s is not set", dbtest.URLVar)
		}
		pool := dbtest.Pool(t)
		dbtest.Reset(t, pool)
		s := NewPG(pool)
		ctx := context.Background()
		if _, _, err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		run(t, s, ctx)
	})
}

func TestMigrateBringsADatabaseToTheBinarysVersionOnce(t *testing.T) {
	pool := dbtest.Pool(t)
	dbtest.Reset(t, pool)
	s := NewPG(pool)
	ctx := context.Background()
	if err := s.CheckSchema(ctx); !errors.Is(err, ErrSchema) {
		t.Fatalf("an empty database passed the schema check: %v", err)
	}
	if from, to, err := s.Migrate(ctx); err != nil || from != 0 || to != 1 {
		t.Fatalf("Migrate = %d, %d, %v", from, to, err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if from, to, err := s.Migrate(ctx); err != nil || from != 1 || to != 1 {
		t.Fatalf("a second Migrate = %d, %d, %v", from, to, err)
	}
}

func TestAnAccountHasOneNameAndOneVerifierUnderTheCap(t *testing.T) {
	backends(t, testAccounts)
}

func testAccounts(t *testing.T, s Store, ctx context.Context) {
	cred := credential(t, "alice")
	a, err := s.CreateAccount(ctx, "Alice", VerifierOf("", cred), 0)
	if err != nil || a.Name != "alice" || a.ID == "" || a.DisabledAt != nil {
		t.Fatalf("CreateAccount = %+v, %v", a, err)
	}
	if _, err := s.CreateAccount(ctx, "ALICE", VerifierOf("", cred), 0); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a second spelling: %v", err)
	}
	if _, err := s.CreateAccount(ctx, "bob", VerifierOf("", credential(t, "bob")), 1); !errors.Is(err, ErrAccountsFull) {
		t.Fatalf("past the cap: %v", err)
	}
	if got, err := s.AccountByName(ctx, " Alice "); err != nil || got.ID != a.ID || !got.CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("AccountByName = %+v, %v", got, err)
	}
	if _, err := s.AccountByName(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown name: %v", err)
	}
	list, err := s.Verifiers(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("Verifiers = %+v, %v", list, err)
	}
	v := list[0]
	if v.AccountID != a.ID || v.Name != "alice" || !bytes.Equal(v.Salt, cred.Salt) || !bytes.Equal(v.StoredKey, cred.StoredKey) ||
		!bytes.Equal(v.ServerKey, cred.ServerKey) || v.ArgonMemory != cred.ArgonMemory || v.ArgonTime != cred.ArgonTime ||
		v.ArgonThreads != cred.ArgonThreads {
		t.Fatalf("the verifier read back differs: %+v", v)
	}
	if err := s.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, err := s.AccountByID(ctx, a.ID); err != nil || got.DisabledAt == nil {
		t.Fatalf("a disabled account: %+v, %v", got, err)
	}
	if list, err := s.Verifiers(ctx); err != nil || len(list) != 0 {
		t.Fatalf("a disabled account's verifier is loaded: %+v, %v", list, err)
	}
	if err := s.SetDisabled(ctx, a.ID, false); err != nil {
		t.Fatal(err)
	}
	reset := credential(t, "alice")
	if err := s.SetVerifier(ctx, VerifierOf(a.ID, reset)); err != nil {
		t.Fatal(err)
	}
	if list, err := s.Verifiers(ctx); err != nil || len(list) != 1 || !bytes.Equal(list[0].StoredKey, reset.StoredKey) {
		t.Fatalf("the reset verifier: %+v, %v", list, err)
	}
	if all, err := s.Accounts(ctx); err != nil || len(all) != 1 || all[0].DisabledAt != nil {
		t.Fatalf("Accounts = %+v, %v", all, err)
	}
	if err := s.DeleteAccount(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAccount(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second delete: %v", err)
	}
	if list, err := s.Verifiers(ctx); err != nil || len(list) != 0 {
		t.Fatalf("the verifier outlived its account: %+v, %v", list, err)
	}
}

func TestASignInLivesUntilRevokedExpiredOrDisabled(t *testing.T) {
	backends(t, testSignIns)
}

func testSignIns(t *testing.T, s Store, ctx context.Context) {
	a, err := s.CreateAccount(ctx, "alice", VerifierOf("", credential(t, "alice")), 0)
	if err != nil {
		t.Fatal(err)
	}
	now := Now()
	live := SignIn{ID: NewID(), AccountID: a.ID, TokenHash: HashToken("live"), Device: "laptop",
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(SignInLifetime)}
	stale := SignIn{ID: NewID(), AccountID: a.ID, TokenHash: HashToken("stale"), Device: "phone",
		CreatedAt: now.Add(-2 * SignInLifetime), LastSeenAt: now.Add(-2 * SignInLifetime), ExpiresAt: now.Add(-SignInLifetime)}
	for _, in := range []SignIn{live, stale} {
		if err := s.CreateSignIn(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	in, acct, err := s.SignInByToken(ctx, HashToken("live"))
	if err != nil || in.ID != live.ID || in.Device != "laptop" || !in.ExpiresAt.Equal(live.ExpiresAt) ||
		!in.CreatedAt.Equal(now) || acct.ID != a.ID || acct.Name != "alice" {
		t.Fatalf("SignInByToken = %+v, %+v, %v", in, acct, err)
	}
	if _, _, err := s.SignInByToken(ctx, HashToken("stale")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired sign-in: %v", err)
	}
	if list, err := s.SignIns(ctx, a.ID); err != nil || len(list) != 1 || list[0].ID != live.ID || !bytes.Equal(list[0].TokenHash, live.TokenHash) {
		t.Fatalf("SignIns = %+v, %v", list, err)
	}
	later := now.Add(20 * 24 * time.Hour)
	if err := s.RenewSignIn(ctx, live.ID, later); err != nil {
		t.Fatal(err)
	}
	if in, _, err := s.SignInByToken(ctx, HashToken("live")); err != nil || !in.LastSeenAt.Equal(later) || !in.ExpiresAt.Equal(later.Add(SignInLifetime)) {
		t.Fatalf("after renewal: %+v, %v", in, err)
	}
	if err := s.DeleteSignIn(ctx, NewID(), live.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account's revocation: %v", err)
	}
	if err := s.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SignInByToken(ctx, HashToken("live")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a disabled account's sign-in: %v", err)
	}
	if err := s.SetDisabled(ctx, a.ID, false); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteExpiredSignIns(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpiredSignIns = %d, %v", n, err)
	}
	if err := s.DeleteSignInByToken(ctx, HashToken("live")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSignInByToken(ctx, HashToken("live")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second logout: %v", err)
	}
	if err := s.CreateSignIn(ctx, live); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteSignIns(ctx, a.ID); err != nil || n != 1 {
		t.Fatalf("DeleteSignIns = %d, %v", n, err)
	}
}
