package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(t *testing.T, method, path, contentType, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	New(Options{}).ServeHTTP(rec, req)
	return rec.Result()
}

// refusal reads the one error form and fails on any other shape.
func refusal(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type %q", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("a refusal may be cached")
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &body); err != nil || body.Error.Code == "" || body.Error.Message == "" {
		t.Fatalf("not the error form: %s", data)
	}
	return resp.StatusCode, body.Error.Code
}

func TestARefusalIsTheRoutersErrorForm(t *testing.T) {
	status, code := refusal(t, serve(t, http.MethodGet, "/vif/api/auth/nothing", "", ""))
	if status != http.StatusNotFound || code != "not_found" {
		t.Fatalf("%d %s", status, code)
	}
	if status, _ := refusal(t, serve(t, http.MethodGet, "/", "", "")); status != http.StatusNotFound {
		t.Fatalf("outside the prefix: %d", status)
	}
}

func TestAWrongMethodNamesTheAllowedOnes(t *testing.T) {
	resp := serve(t, http.MethodGet, Prefix+"register", "", "")
	status, code := refusal(t, resp)
	if status != http.StatusMethodNotAllowed || code != "method_not_allowed" || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("%d %s, Allow %q", status, code, resp.Header.Get("Allow"))
	}
}

func TestABodyMustBeJSON(t *testing.T) {
	status, code := refusal(t, serve(t, http.MethodPost, Prefix+"login", "text/plain", `{}`))
	if status != http.StatusUnsupportedMediaType || code != "content_type" {
		t.Fatalf("%d %s", status, code)
	}
	if status, _ := refusal(t, serve(t, http.MethodPost, Prefix+"login", "application/json; charset=utf-8", `{}`)); status == http.StatusUnsupportedMediaType {
		t.Fatal("a JSON media type with a charset was refused")
	}
}

func TestABodyIsBoundedBeforeDecoding(t *testing.T) {
	big := `{"name":"` + strings.Repeat("a", MaxBody) + `"}`
	status, code := refusal(t, serve(t, http.MethodPost, Prefix+"register", "application/json", big))
	if status != http.StatusRequestEntityTooLarge || code != "request_too_large" {
		t.Fatalf("%d %s", status, code)
	}
}

func TestAMalformedBodyIsRefused(t *testing.T) {
	for _, body := range []string{`{`, `{"name":"a","extra":1}`, `{"name":"a"} {}`, `[]`} {
		status, code := refusal(t, serve(t, http.MethodPost, Prefix+"register", "application/json", body))
		if status != http.StatusBadRequest || code != "malformed_request" {
			t.Errorf("%q: %d %s", body, status, code)
		}
	}
	for _, body := range []string{`{}`, `{"client_first":{"username":"a","client_nonce":"n"},"proof":{"full_nonce":"n","client_proof":"p"}}`} {
		if status, _ := refusal(t, serve(t, http.MethodPost, Prefix+"login", "application/json", body)); status != http.StatusBadRequest {
			t.Errorf("login %q: %d", body, status)
		}
	}
}

func TestEveryRouteIsReachedAndNotImplemented(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, Prefix + "register", `{"name":"alice","credential":{}}`},
		{http.MethodPost, Prefix + "login", `{"client_first":{"username":"alice","client_nonce":"n"}}`},
		{http.MethodPost, Prefix + "login", `{"proof":{"full_nonce":"n","client_proof":"p"},"device":"laptop","session":"cookie"}`},
		{http.MethodPost, Prefix + "logout", ""},
		{http.MethodGet, Prefix + "me", ""},
		{http.MethodDelete, Prefix + "sign-ins/0d4a2c1e-5b3f-4c8d-9e1a-2b3c4d5e6f70", ""},
	} {
		status, code := refusal(t, serve(t, tc.method, tc.path, "application/json", tc.body))
		if status != http.StatusNotImplemented || code != "not_implemented" {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, status, code)
		}
	}
	if status, _ := refusal(t, serve(t, http.MethodDelete, Prefix+"sign-ins/not-an-id", "", "")); status != http.StatusNotFound {
		t.Fatalf("a malformed sign-in id: %d", status)
	}
}

func TestTheForwardedAddressIsBelievedFromLoopbackAlone(t *testing.T) {
	h := New(Options{ClientAddressHeader: "X-Real-IP"})
	req := httptest.NewRequest(http.MethodGet, Prefix+"me", nil)
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.RemoteAddr = "127.0.0.1:40000"
	if got := h.clientAddr(req); got != "203.0.113.7" {
		t.Fatalf("from loopback: %q", got)
	}
	req.RemoteAddr = "198.51.100.2:40000"
	if got := h.clientAddr(req); got != "198.51.100.2" {
		t.Fatalf("from elsewhere: %q", got)
	}
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Real-IP", "not an address")
	if got := h.clientAddr(req); got != "127.0.0.1" {
		t.Fatalf("malformed header: %q", got)
	}
	if got := New(Options{}).clientAddr(req); got != "127.0.0.1" {
		t.Fatalf("no header configured: %q", got)
	}
}

func TestASignInCookieStaysWithTheAPI(t *testing.T) {
	c := signInCookie("t", 3600)
	if c.Name != SignInCookie || c.Path != CookiePath || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie %+v", c)
	}
	if len(NewToken()) != 43 || NewToken() == NewToken() {
		t.Fatal("a token is 32 random bytes in the bearer alphabet")
	}
}
