package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/identity/internal/config"
	"github.com/lixenwraith/identity/internal/dbtest"
	"github.com/lixenwraith/identity/internal/store"

	"github.com/lixenwraith/auth"
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
	for _, body := range []string{
		`{}`,
		`{"client_first":{"username":"a","client_nonce":"n"},"proof":{"full_nonce":"n","client_proof":"p"}}`,
		`{"client_first":{"username":"a","client_nonce":"n"},"device":"laptop"}`,
		`{"proof":{"full_nonce":"n","client_proof":"p"}}`,
		`{"proof":{"full_nonce":"n","client_proof":"p"},"device":"` + strings.Repeat("d", store.MaxDevice+1) + `"}`,
		`{"proof":{"full_nonce":"n","client_proof":"p"},"device":"laptop","session":"jar"}`,
	} {
		if status, _ := refusal(t, serve(t, http.MethodPost, Prefix+"login", "application/json", body)); status != http.StatusBadRequest {
			t.Errorf("login %q: %d", body, status)
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

// A budget spends burst attempts, refills them over its period, refunds one
// that did not count, keys IPv6 by its /64 and fails closed when full.
func TestABudgetSpendsRefillsAndRefunds(t *testing.T) {
	b := newBudget(5, time.Minute)
	now := time.Now()
	for i := range 5 {
		if wait := b.take("203.0.113.1", now); wait != 0 {
			t.Fatalf("attempt %d refused for %v", i+1, wait)
		}
	}
	if wait := b.take("203.0.113.1", now); wait <= 0 || wait > 12*time.Second {
		t.Fatalf("the sixth attempt waits %v, want about 12s", wait)
	}
	if wait := b.take("203.0.113.2", now); wait != 0 {
		t.Fatalf("another address was refused for %v", wait)
	}
	b.refund("203.0.113.1")
	if wait := b.take("203.0.113.1", now); wait != 0 {
		t.Fatalf("a refunded attempt was refused for %v", wait)
	}
	if wait := b.take("203.0.113.1", now.Add(13*time.Second)); wait != 0 {
		t.Fatalf("a refilled attempt was refused for %v", wait)
	}
	for range 5 {
		b.take("2001:db8:1:2::1", now)
	}
	if wait := b.take("2001:db8:1:2:ffff::9", now); wait == 0 {
		t.Fatal("an address in the same /64 has its own budget")
	}
	if wait := b.take("2001:db8:1:3::1", now); wait != 0 {
		t.Fatalf("another /64 was refused for %v", wait)
	}
	full := newBudget(1, time.Minute)
	for i := range maxBudgetClients {
		full.take("client-"+strconv.Itoa(i), now)
	}
	if wait := full.take("203.0.113.9", now); wait == 0 {
		t.Fatal("a full table admitted a new address")
	}
}

// Every test credential is derived under this profile, cheap enough to run
// often; the handler holds registrations to it as it would to the default.
var testKDF = config.KDF{Memory: 8 * 1024, Time: 1, Threads: auth.DefaultArgonThreads}

const password = "a-long-example-password"

func credential(t *testing.T, name string) *auth.Credential {
	t.Helper()
	cred, err := auth.NewCredential(name, password, auth.WithMemory(testKDF.Memory), auth.WithTime(testKDF.Time))
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// service is the handler on a fresh database with a SCRAM server of its own,
// and the client side of its routes.
type service struct {
	t     *testing.T
	h     *Handler
	store *store.Store
}

func newService(t *testing.T, maxAccounts int) *service {
	t.Helper()
	pool := dbtest.Pool(t)
	dbtest.Reset(t, pool)
	st := store.New(pool)
	if _, _, err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	scram := auth.NewScramServer()
	t.Cleanup(scram.Stop)
	h := New(Options{
		Store: st, Scram: scram, KDF: testKDF, MaxAccounts: maxAccounts, ClientAddressHeader: "X-Real-IP",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &service{t: t, h: h, store: st}
}

// call sends one request as the router would: from loopback, with the player's
// address in the header, the body as JSON, and the token as a bearer or a cookie.
func (s *service) call(method, path string, body any, addr, bearer, cookie string) *http.Response {
	s.t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, payload)
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Real-IP", addr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SignInCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec.Result()
}

func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %d answer: %v", resp.StatusCode, err)
	}
}

func (s *service) register(name, addr string) RegisterResponse {
	s.t.Helper()
	resp := s.call(http.MethodPost, Prefix+"register", map[string]any{"name": name, "credential": credential(s.t, name).Export()}, addr, "", "")
	if resp.StatusCode != http.StatusCreated {
		status, code := refusal(s.t, resp)
		s.t.Fatalf("register %q: %d %s", name, status, code)
	}
	var out RegisterResponse
	decode(s.t, resp, &out)
	return out
}

// signIn runs the two steps as the game does and returns the proof's answer,
// so a caller reads the token, the cookie or the refusal.
func (s *service) signIn(name, pw, device, session, addr string) (*auth.ScramClient, *http.Response) {
	s.t.Helper()
	client := auth.NewScramClient(name, pw, auth.WithMinArgonCost(testKDF.Time, testKDF.Memory))
	first, err := client.StartAuthentication()
	if err != nil {
		s.t.Fatal(err)
	}
	resp := s.call(http.MethodPost, Prefix+"login", map[string]any{"client_first": first}, addr, "", "")
	if resp.StatusCode != http.StatusOK {
		return client, resp
	}
	var challenge LoginResponse
	decode(s.t, resp, &challenge)
	if challenge.Challenge == nil {
		s.t.Fatal("no challenge")
	}
	proof, err := client.ProcessServerFirstMessage(*challenge.Challenge)
	if err != nil {
		s.t.Fatal(err)
	}
	step := map[string]any{"proof": proof, "device": device}
	if session != "" {
		step["session"] = session
	}
	return client, s.call(http.MethodPost, Prefix+"login", step, addr, "", "")
}

func (s *service) token(name, device, addr string) string {
	s.t.Helper()
	client, resp := s.signIn(name, password, device, "", addr)
	if resp.StatusCode != http.StatusOK {
		status, code := refusal(s.t, resp)
		s.t.Fatalf("sign in %q: %d %s", name, status, code)
	}
	var final LoginResponse
	decode(s.t, resp, &final)
	if final.Final == nil || client.VerifyServerFinalMessage(*final.Final) != nil || final.Token == "" {
		s.t.Fatalf("the sign-in's answer: %+v", final)
	}
	return final.Token
}

func TestRegistrationTakesTheOneProfileAndTheNameOnce(t *testing.T) {
	s := newService(t, 2)
	resp := s.call(http.MethodPost, Prefix+"register", map[string]any{"name": " Alice ", "credential": credential(t, "alice").Export()}, "203.0.113.1", "", "")
	if resp.StatusCode != http.StatusCreated {
		status, code := refusal(t, resp)
		t.Fatalf("register: %d %s", status, code)
	}
	var alice RegisterResponse
	decode(t, resp, &alice)
	if alice.Name != "alice" || alice.ID == "" {
		t.Fatalf("registered %+v", alice)
	}
	if a, err := s.store.AccountByID(context.Background(), alice.ID); err != nil || a.Name != "alice" {
		t.Fatalf("the account in the store: %+v, %v", a, err)
	}
	refusals := []struct {
		body         map[string]any
		status       int
		code         string
		registration string
	}{
		{map[string]any{"name": "alice", "credential": credential(t, "alice").Export()}, http.StatusConflict, "name_taken", "the same name"},
		{map[string]any{"name": "7up", "credential": credential(t, "7up").Export()}, http.StatusBadRequest, "invalid_name", "a bad name"},
		{map[string]any{"name": "Carol", "credential": credential(t, "Carol").Export()}, http.StatusBadRequest, "invalid_credential", "a credential for the name in another spelling"},
		{map[string]any{"name": "carol", "credential": map[string]any{"username": "carol"}}, http.StatusBadRequest, "invalid_credential", "a credential missing its keys"},
		{map[string]any{"name": "carol", "credential": withField(credential(t, "carol").Export(), "extra", 1)}, http.StatusBadRequest, "invalid_credential", "a credential with a field the shape does not name"},
		{map[string]any{"name": "carol", "credential": withField(credential(t, "carol").Export(), "stored_key", "AAAA")}, http.StatusBadRequest, "invalid_credential", "a malformed key"},
		{map[string]any{"name": "carol"}, http.StatusBadRequest, "invalid_credential", "no credential"},
	}
	other, err := auth.NewCredential("carol", password, auth.WithMemory(16*1024), auth.WithTime(1))
	if err != nil {
		t.Fatal(err)
	}
	refusals = append(refusals, struct {
		body         map[string]any
		status       int
		code         string
		registration string
	}{map[string]any{"name": "carol", "credential": other.Export()}, http.StatusBadRequest, "invalid_credential", "another KDF profile"})
	for _, tc := range refusals {
		status, code := refusal(t, s.call(http.MethodPost, Prefix+"register", tc.body, "203.0.113.2", "", ""))
		if status != tc.status || code != tc.code {
			t.Errorf("%s: %d %s, want %d %s", tc.registration, status, code, tc.status, tc.code)
		}
	}
	s.register("bob", "203.0.113.3")
	if status, code := refusal(t, s.call(http.MethodPost, Prefix+"register",
		map[string]any{"name": "carol", "credential": credential(t, "carol").Export()}, "203.0.113.3", "", "")); status != http.StatusServiceUnavailable || code != "accounts_full" {
		t.Fatalf("past the cap: %d %s", status, code)
	}
}

func withField(m map[string]any, key string, value any) map[string]any {
	m[key] = value
	return m
}

func TestASignInIsTwoStepsEndingInATokenOrACookie(t *testing.T) {
	s := newService(t, 0)
	s.register("alice", "203.0.113.1")
	client, resp := s.signIn("alice", password, "laptop", "", "203.0.113.1")
	if resp.StatusCode != http.StatusOK {
		status, code := refusal(t, resp)
		t.Fatalf("the proof: %d %s", status, code)
	}
	var final LoginResponse
	decode(t, resp, &final)
	if final.Final == nil || final.Final.Username != "alice" || final.Challenge != nil || final.Token == "" ||
		final.ExpiresIn != int64(store.SignInLifetime/time.Second) || len(resp.Cookies()) != 0 {
		t.Fatalf("a bearer sign-in answered %+v with cookies %v", final, resp.Cookies())
	}
	if err := client.VerifyServerFinalMessage(*final.Final); err != nil {
		t.Fatalf("the server's signature: %v", err)
	}
	_, resp = s.signIn("alice", password, "browser", "cookie", "203.0.113.1")
	if resp.StatusCode != http.StatusOK {
		status, code := refusal(t, resp)
		t.Fatalf("the cookie proof: %d %s", status, code)
	}
	var page LoginResponse
	decode(t, resp, &page)
	cookies := resp.Cookies()
	if page.Token != "" || page.Final == nil || len(cookies) != 1 || cookies[0].Name != SignInCookie || cookies[0].Value == "" ||
		!cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != CookiePath ||
		cookies[0].MaxAge != int(store.SignInLifetime/time.Second) {
		t.Fatalf("a cookie sign-in answered %+v with cookies %+v", page, cookies)
	}
	for _, tc := range []struct{ bearer, cookie, current string }{{final.Token, "", "laptop"}, {"", cookies[0].Value, "browser"}} {
		resp := s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", tc.bearer, tc.cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("me: %d", resp.StatusCode)
		}
		var me MeResponse
		decode(t, resp, &me)
		if me.Name != "alice" || len(me.SignIns) != 2 {
			t.Fatalf("me = %+v", me)
		}
		for _, in := range me.SignIns {
			if in.Current != (in.Device == tc.current) || in.ID == "" || in.ExpiresAt.Sub(in.CreatedAt) != store.SignInLifetime || in.CreatedAt.Location() != time.UTC {
				t.Fatalf("sign-in %+v as %s", in, tc.current)
			}
		}
	}
	if status, code := refusal(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", "", "")); status != http.StatusUnauthorized || code != "unauthorized" {
		t.Fatalf("no sign-in: %d %s", status, code)
	}
	if status, _ := refusal(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", NewToken(), "")); status != http.StatusUnauthorized {
		t.Fatalf("an unknown token: %d", status)
	}
	if status, _ := refusal(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", "", NewToken())); status != http.StatusUnauthorized {
		t.Fatalf("an unknown cookie: %d", status)
	}
}

// A wrong password, an unknown name, a disabled account, an abandoned exchange
// and a replayed proof are one refusal, and a device name is required.
func TestAFailedProofIsOneRefusalWhateverTheCause(t *testing.T) {
	s := newService(t, 0)
	s.register("alice", "203.0.113.1")
	bob := s.register("bob", "203.0.113.1")
	if err := s.store.SetDisabled(context.Background(), bob.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, pw, why string }{
		{"alice", "not-the-password", "a wrong password"},
		{"nobody", password, "an unknown name"},
		{"Alice", password, "another spelling"},
		{"bob", password, "a disabled account"},
	} {
		_, resp := s.signIn(tc.name, tc.pw, "laptop", "", "203.0.113.1")
		if status, code := refusal(t, resp); status != http.StatusUnauthorized || code != "unauthorized" {
			t.Errorf("%s: %d %s", tc.why, status, code)
		}
	}
	client := auth.NewScramClient("alice", password, auth.WithMinArgonCost(testKDF.Time, testKDF.Memory))
	first, _ := client.StartAuthentication()
	var challenge LoginResponse
	decode(t, s.call(http.MethodPost, Prefix+"login", map[string]any{"client_first": first}, "203.0.113.1", "", ""), &challenge)
	proof, err := client.ProcessServerFirstMessage(*challenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := refusal(t, s.call(http.MethodPost, Prefix+"login", map[string]any{"proof": proof}, "203.0.113.1", "", "")); status != http.StatusBadRequest {
		t.Fatalf("a proof without a device: %d", status)
	}
	if resp := s.call(http.MethodPost, Prefix+"login", map[string]any{"proof": proof, "device": "laptop"}, "203.0.113.1", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("the proof after a malformed attempt: %d", resp.StatusCode)
	}
	if status, _ := refusal(t, s.call(http.MethodPost, Prefix+"login", map[string]any{"proof": proof, "device": "laptop"}, "203.0.113.1", "", "")); status != http.StatusUnauthorized {
		t.Fatalf("a replayed proof: %d", status)
	}
	// An exchange whose proof never comes is abandoned after the handshake
	// timeout and its nonce is unknown to the SCRAM server from then on.
	was := handshakeTimeout
	handshakeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = was })
	first, _ = client.StartAuthentication()
	decode(t, s.call(http.MethodPost, Prefix+"login", map[string]any{"client_first": first}, "203.0.113.1", "", ""), &challenge)
	if proof, err = client.ProcessServerFirstMessage(*challenge.Challenge); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	s.h.mu.Lock()
	held := len(s.h.exchanges)
	s.h.mu.Unlock()
	if held != 0 {
		t.Fatalf("%d exchanges held after the timeout", held)
	}
	if status, _ := refusal(t, s.call(http.MethodPost, Prefix+"login", map[string]any{"proof": proof, "device": "laptop"}, "203.0.113.1", "", "")); status != http.StatusUnauthorized {
		t.Fatalf("a proof for an abandoned exchange: %d", status)
	}
}

func TestLogoutAndRevocationEndASignIn(t *testing.T) {
	s := newService(t, 0)
	alice := s.register("alice", "203.0.113.1")
	s.register("bob", "203.0.113.1")
	laptop := s.token("alice", "laptop", "203.0.113.1")
	phone := s.token("alice", "phone", "203.0.113.1")
	bobs := s.token("bob", "laptop", "203.0.113.1")
	var me MeResponse
	decode(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", laptop, ""), &me)
	ids := map[string]string{}
	for _, in := range me.SignIns {
		ids[in.Device] = in.ID
	}
	var bobsMe MeResponse
	decode(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", bobs, ""), &bobsMe)

	resp := s.call(http.MethodPost, Prefix+"logout", nil, "203.0.113.1", phone, "")
	if resp.StatusCode != http.StatusNoContent || len(resp.Cookies()) != 1 || resp.Cookies()[0].MaxAge >= 0 || resp.Cookies()[0].Value != "" {
		t.Fatalf("logout: %d, cookies %+v", resp.StatusCode, resp.Cookies())
	}
	if status, _ := refusal(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", phone, "")); status != http.StatusUnauthorized {
		t.Fatalf("a signed-out token: %d", status)
	}
	if status, _ := refusal(t, s.call(http.MethodPost, Prefix+"logout", nil, "203.0.113.1", phone, "")); status != http.StatusUnauthorized {
		t.Fatalf("a second logout: %d", status)
	}
	if status, code := refusal(t, s.call(http.MethodDelete, Prefix+"sign-ins/"+bobsMe.SignIns[0].ID, nil, "203.0.113.1", laptop, "")); status != http.StatusNotFound || code != "not_found" {
		t.Fatalf("another account's sign-in: %d %s", status, code)
	}
	if status, _ := refusal(t, s.call(http.MethodDelete, Prefix+"sign-ins/"+store.NewID(), nil, "203.0.113.1", laptop, "")); status != http.StatusNotFound {
		t.Fatalf("an unknown sign-in: %d", status)
	}
	if status, _ := refusal(t, s.call(http.MethodDelete, Prefix+"sign-ins/"+ids["laptop"], nil, "203.0.113.1", "", "")); status != http.StatusUnauthorized {
		t.Fatalf("a revocation without a sign-in: %d", status)
	}
	if resp := s.call(http.MethodDelete, Prefix+"sign-ins/"+ids["laptop"], nil, "203.0.113.1", laptop, ""); resp.StatusCode != http.StatusNoContent || len(resp.Cookies()) != 1 {
		t.Fatalf("revoking the current sign-in: %d, cookies %+v", resp.StatusCode, resp.Cookies())
	}
	if status, _ := refusal(t, s.call(http.MethodGet, Prefix+"me", nil, "203.0.113.1", laptop, "")); status != http.StatusUnauthorized {
		t.Fatalf("a revoked token: %d", status)
	}
	if list, err := s.store.SignIns(context.Background(), alice.ID); err != nil || len(list) != 0 {
		t.Fatalf("alice's sign-ins: %+v, %v", list, err)
	}
}

func TestBudgetsRefuseAnAddressWithRetryAfter(t *testing.T) {
	s := newService(t, 0)
	for i := range RegistrationsAMinute {
		s.register("user"+string(rune('a'+i)), "203.0.113.1")
	}
	resp := s.call(http.MethodPost, Prefix+"register", map[string]any{"name": "late", "credential": credential(t, "late").Export()}, "203.0.113.1", "", "")
	if status, code := refusal(t, resp); status != http.StatusTooManyRequests || code != "too_many_attempts" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("the sixth registration: %d %s, Retry-After %q", status, code, resp.Header.Get("Retry-After"))
	}
	s.register("late", "203.0.113.2")
	for i := range SignInsAMinute {
		if _, resp := s.signIn("usera", "wrong", "laptop", "", "203.0.113.3"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i+1, resp.StatusCode)
		}
	}
	if _, resp := s.signIn("usera", password, "laptop", "", "203.0.113.3"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the eleventh sign-in: %d", resp.StatusCode)
	}
	for i := range SignInsAMinute + 2 {
		if _, resp := s.signIn("usera", password, "laptop", "", "203.0.113.4"); resp.StatusCode != http.StatusOK {
			t.Fatalf("successful sign-in %d was not refunded: %d", i+1, resp.StatusCode)
		}
	}
	token := s.token("userb", "laptop", "203.0.113.5")
	for range DeletionsAMinute {
		s.call(http.MethodDelete, Prefix+"sign-ins/"+store.NewID(), nil, "203.0.113.5", token, "")
	}
	if status, _ := refusal(t, s.call(http.MethodDelete, Prefix+"sign-ins/"+store.NewID(), nil, "203.0.113.5", token, "")); status != http.StatusTooManyRequests {
		t.Fatalf("the sixth deletion: %d", status)
	}
}
