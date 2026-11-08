package introspect

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/identity/internal/store"
	"github.com/lixenwraith/identity/internal/storetest"

	"github.com/lixenwraith/auth"
)

func ask(t *testing.T, h *Handler, method, path, body string) (int, []byte, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), rec.Header()
}

func refused(t *testing.T, h *Handler, method, path, body string) (int, string, http.Header) {
	t.Helper()
	status, raw, header := ask(t, h, method, path, body)
	var answer struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Error.Code == "" {
		t.Fatalf("not the error form: %s", raw)
	}
	return status, answer.Error.Code, header
}

func TestTheOneQuestionIsAPostOfAToken(t *testing.T) {
	h := New(nil, nil)
	if status, code, header := refused(t, h, http.MethodGet, Path, ""); status != http.StatusMethodNotAllowed || code != "method_not_allowed" || header.Get("Allow") != "POST" {
		t.Fatalf("GET: %d %s, Allow %q", status, code, header.Get("Allow"))
	}
	if status, code, _ := refused(t, h, http.MethodPost, "/other", `{"token":"abc"}`); status != http.StatusNotFound || code != "not_found" {
		t.Fatalf("other path: %d %s", status, code)
	}
	for _, body := range []string{`{}`, `{"token":""}`, `{"token":"a","extra":1}`, `nope`} {
		if status, code, _ := refused(t, h, http.MethodPost, Path, body); status != http.StatusBadRequest || code != "malformed_request" {
			t.Errorf("%q: %d %s", body, status, code)
		}
	}
	big := `{"token":"` + strings.Repeat("a", MaxBody) + `"}`
	if status, code, _ := refused(t, h, http.MethodPost, Path, big); status != http.StatusRequestEntityTooLarge || code != "request_too_large" {
		t.Fatalf("oversized: %d %s", status, code)
	}
}

// A live sign-in of an enabled account names it, renewed once past half its
// life; an unknown, expired or revoked token, or a disabled account, names
// none, and never with an error status.
func TestATokenNamesALiveEnabledAccountOrNone(t *testing.T) {
	st := storetest.Open(t).Store
	ctx := context.Background()
	h := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cred, err := auth.NewCredential("alice", "a-long-example-password", auth.WithMemory(8*1024), auth.WithTime(1))
	if err != nil {
		t.Fatal(err)
	}
	alice, err := st.CreateAccount(ctx, "alice", store.VerifierOf("", cred), 0)
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	signIn := func(token string, lastSeen time.Time) store.SignIn {
		in := store.SignIn{ID: store.NewID(), AccountID: alice.ID, TokenHash: store.HashToken(token), Device: "laptop",
			CreatedAt: lastSeen, LastSeenAt: lastSeen, ExpiresAt: lastSeen.Add(store.SignInLifetime)}
		if err := st.CreateSignIn(ctx, in); err != nil {
			t.Fatal(err)
		}
		return in
	}
	signIn("fresh", now)
	aged := signIn("aged", now.Add(-16*24*time.Hour))
	signIn("expired", now.Add(-31*24*time.Hour))
	answer := func(token string) (Response, string) {
		t.Helper()
		status, raw, _ := ask(t, h, http.MethodPost, Path, `{"token":"`+token+`"}`)
		if status != http.StatusOK {
			t.Fatalf("token %q: %d %s", token, status, raw)
		}
		var resp Response
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		return resp, string(raw)
	}
	if resp, raw := answer("fresh"); resp.Account == nil || resp.Account.ID != alice.ID || resp.Account.Name != "alice" || resp.Renewed || strings.Contains(raw, "renewed") {
		t.Fatalf("a fresh sign-in: %s", raw)
	}
	if resp, raw := answer("aged"); resp.Account == nil || !resp.Renewed {
		t.Fatalf("a sign-in past half its life: %s", raw)
	}
	if in, _, err := st.SignInByToken(ctx, store.HashToken("aged")); err != nil || in.ExpiresAt.Before(now.Add(store.SignInLifetime-time.Minute)) || in.LastSeenAt.Before(now.Add(-time.Minute)) {
		t.Fatalf("the renewed row: %+v, %v", in, err)
	}
	if resp, raw := answer("aged"); resp.Account == nil || resp.Renewed {
		t.Fatalf("a sign-in just renewed: %s", raw)
	}
	for _, token := range []string{"expired", "unknown", `\u0000`} {
		if _, raw := answer(token); raw != "{\"account\":null}\n" {
			t.Errorf("token %q: %s", token, raw)
		}
	}
	if err := st.SetDisabled(ctx, alice.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, raw := answer("fresh"); raw != "{\"account\":null}\n" {
		t.Fatalf("a disabled account's sign-in: %s", raw)
	}
	if err := st.DeleteSignIn(ctx, alice.ID, aged.ID); err != nil {
		t.Fatal(err)
	}
	if _, raw := answer("aged"); raw != "{\"account\":null}\n" {
		t.Fatalf("a revoked sign-in: %s", raw)
	}
}
