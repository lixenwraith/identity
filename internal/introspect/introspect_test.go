package introspect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ask(t *testing.T, method, path, body string) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	New(nil, nil).ServeHTTP(rec, req)
	var answer struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil || answer.Error.Code == "" {
		t.Fatalf("not the error form: %s", rec.Body.String())
	}
	return rec.Code, answer.Error.Code, rec.Header()
}

func TestTheOneQuestionIsAPostOfAToken(t *testing.T) {
	if status, code, _ := ask(t, http.MethodPost, Path, `{"token":"abc"}`); status != http.StatusNotImplemented || code != "not_implemented" {
		t.Fatalf("%d %s", status, code)
	}
	if status, code, h := ask(t, http.MethodGet, Path, ""); status != http.StatusMethodNotAllowed || code != "method_not_allowed" || h.Get("Allow") != "POST" {
		t.Fatalf("GET: %d %s, Allow %q", status, code, h.Get("Allow"))
	}
	if status, code, _ := ask(t, http.MethodPost, "/other", `{"token":"abc"}`); status != http.StatusNotFound || code != "not_found" {
		t.Fatalf("other path: %d %s", status, code)
	}
	for _, body := range []string{`{}`, `{"token":""}`, `{"token":"a","extra":1}`, `nope`} {
		if status, code, _ := ask(t, http.MethodPost, Path, body); status != http.StatusBadRequest || code != "malformed_request" {
			t.Errorf("%q: %d %s", body, status, code)
		}
	}
	big := `{"token":"` + strings.Repeat("a", MaxBody) + `"}`
	if status, code, _ := ask(t, http.MethodPost, Path, big); status != http.StatusRequestEntityTooLarge || code != "request_too_large" {
		t.Fatalf("oversized: %d %s", status, code)
	}
}
