// Package api answers /vif/api/auth/, the account routes the router forwards
// byte for byte: registration with a derived credential, sign-in in two SCRAM
// steps, logout, an account's view of itself and its sign-ins, and a sign-in's
// revocation. Every body is bounded before it is decoded, every refusal is one
// JSON form, and no credential reaches a log.
package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lixenwraith/identity/internal/config"
	"github.com/lixenwraith/identity/internal/store"

	"github.com/lixenwraith/auth"
)

const (
	// Prefix is the path the router forwards; the service answers nothing outside it.
	Prefix = "/vif/api/auth/"
	// MaxBody bounds every request body before decoding: a credential export
	// and a SCRAM step are a few hundred bytes each.
	MaxBody = 4096
	// SignInCookie carries a page's token, scoped to /vif/ so the router sees
	// it on the /vif/ws/ upgrade and the /vif/api/auth/ routes, and nothing
	// outside /vif/ does.
	SignInCookie = "vif_sign_in"
	CookiePath   = "/vif/"
	// ExchangeTimeout bounds one request's read and write; a SCRAM step is one
	// round trip and a slow reader holds nothing else.
	ExchangeTimeout = 10 * time.Second

	// The budgets per client address and minute, chess's bounds: a sign-in
	// that succeeds is refunded, so they count guesses and not players.
	RegistrationsAMinute = 5
	SignInsAMinute       = 10
	DeletionsAMinute     = 5
)

// handshakeTimeout is how long a challenged client has for its proof before
// the exchange is abandoned: the SCRAM server's own, shortened by a test.
var handshakeTimeout = auth.ScramHandshakeTimeout

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Options is what the handler needs beside the request: the store, the SCRAM
// server loaded with every verifier, and the deployment's policy.
type Options struct {
	Store               store.Store
	Scram               *auth.ScramServer
	KDF                 config.KDF
	MaxAccounts         int
	ClientAddressHeader string
	Logger              *slog.Logger
}

type Handler struct {
	opts          Options
	registrations *budget
	signIns       *budget
	deletions     *budget
	mu            sync.Mutex
	exchanges     map[string]*exchange
}

// exchange is a sign-in between its challenge and its proof: the address it
// was charged to, and the timer that abandons it when no proof comes.
type exchange struct {
	addr  string
	timer *time.Timer
}

func New(opts Options) *Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Handler{
		opts:          opts,
		registrations: newBudget(RegistrationsAMinute, time.Minute),
		signIns:       newBudget(SignInsAMinute, time.Minute),
		deletions:     newBudget(DeletionsAMinute, time.Minute),
		exchanges:     make(map[string]*exchange),
	}
}

// Refusal is a request's answer when it is not the resource: the status and
// the one error form, the router's own, so a page reads both services alike.
type Refusal struct {
	Status  int
	Code    string
	Message string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("%d %s: %s", r.Status, r.Code, r.Message)
}

var (
	errUnauthorized = &Refusal{http.StatusUnauthorized, "unauthorized", "The request carries no live sign-in"}
	errBusy         = &Refusal{http.StatusServiceUnavailable, "busy", "The service cannot answer now"}
)

type route struct {
	path    string
	prefix  bool
	methods []string
	body    bool
	serve   func(*Handler, http.ResponseWriter, *http.Request) *Refusal
}

// routes is the whole public surface, one row a resource; a path outside it is
// a 404 in the same form as every other refusal.
var routes = []route{
	{path: Prefix + "register", methods: []string{http.MethodPost}, body: true, serve: (*Handler).register},
	{path: Prefix + "login", methods: []string{http.MethodPost}, body: true, serve: (*Handler).login},
	{path: Prefix + "logout", methods: []string{http.MethodPost}, serve: (*Handler).logout},
	{path: Prefix + "me", methods: []string{http.MethodGet}, serve: (*Handler).me},
	{path: Prefix + "sign-ins/", prefix: true, methods: []string{http.MethodDelete}, serve: (*Handler).deleteSignIn},
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(ExchangeTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(ExchangeTimeout))
	refusal := h.dispatch(w, r)
	if refusal == nil {
		return
	}
	WriteRefusal(w, refusal)
	h.opts.Logger.Debug("refused", "method", r.Method, "path", r.URL.Path, "status", refusal.Status,
		"code", refusal.Code, "client", h.clientAddr(r))
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) *Refusal {
	for _, rt := range routes {
		if rt.path != r.URL.Path && !(rt.prefix && strings.HasPrefix(r.URL.Path, rt.path)) {
			continue
		}
		if !slices.Contains(rt.methods, r.Method) {
			w.Header().Set("Allow", strings.Join(rt.methods, ", "))
			return &Refusal{http.StatusMethodNotAllowed, "method_not_allowed", "The method is not allowed on this route"}
		}
		if rt.body {
			if refusal := checkJSONBody(r); refusal != nil {
				return refusal
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		return rt.serve(h, w, r)
	}
	return &Refusal{http.StatusNotFound, "not_found", "No such route"}
}

// checkJSONBody refuses a body that is not declared JSON: a cross-origin page
// cannot send one without a preflight nobody answers.
func checkJSONBody(r *http.Request) *Refusal {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		return &Refusal{http.StatusUnsupportedMediaType, "content_type", "Send the body as application/json"}
	}
	return nil
}

// ReadJSON decodes one bounded body into v, refusing an oversized body,
// malformed JSON, a field the shape does not name and anything after it.
func ReadJSON(r *http.Request, v any) *Refusal {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &Refusal{http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("The body exceeds %d bytes", tooLarge.Limit)}
		}
		return &Refusal{http.StatusBadRequest, "malformed_request", "The body is not the JSON this route takes"}
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return &Refusal{http.StatusBadRequest, "malformed_request", "The body holds more than one document"}
	}
	return nil
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteRefusal(w http.ResponseWriter, r *Refusal) {
	type fields struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	WriteJSON(w, r.Status, struct {
		Error fields `json:"error"`
	}{fields{r.Code, r.Message}})
}

// clientAddr is the address budgets count: the one the router forwards in the
// header, believed only when the peer is loopback, since the router is the one
// caller there and anything else wrote the header itself.
func (h *Handler) clientAddr(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if h.opts.ClientAddressHeader == "" {
		return peer
	}
	ip := net.ParseIP(peer)
	if ip == nil || !ip.IsLoopback() {
		return peer
	}
	forwarded := strings.TrimSpace(r.Header.Get(h.opts.ClientAddressHeader))
	if net.ParseIP(forwarded) == nil {
		return peer
	}
	return forwarded
}

// RegisterRequest carries a name and the credential the device derived under
// the deployment's KDF profile (auth.Credential.Export); the service runs no KDF.
type RegisterRequest struct {
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

type RegisterResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// LoginRequest is either SCRAM step: the client first alone, or the proof with
// the device's name and, for a page, session "cookie".
type LoginRequest struct {
	ClientFirst *auth.ClientFirstRequest `json:"client_first,omitempty"`
	Proof       *auth.ClientFinalRequest `json:"proof,omitempty"`
	Device      string                   `json:"device,omitempty"`
	Session     string                   `json:"session,omitempty"`
}

// LoginResponse answers the step: the challenge, or the server final with the
// sign-in as a bearer token, or in a cookie for a page that asked for one.
type LoginResponse struct {
	Challenge *auth.ServerFirstMessage `json:"challenge,omitempty"`
	Final     *auth.ServerFinalMessage `json:"final,omitempty"`
	Token     string                   `json:"token,omitempty"`
	ExpiresIn int64                    `json:"expires_in,omitempty"`
}

type MeResponse struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	SignIns []SignInView `json:"sign_ins"`
}

type SignInView struct {
	ID         string    `json:"id"`
	Device     string    `json:"device"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) *Refusal {
	var req RegisterRequest
	if refusal := ReadJSON(r, &req); refusal != nil {
		return refusal
	}
	name, err := store.NormalizeName(req.Name)
	if err != nil {
		return &Refusal{http.StatusBadRequest, "invalid_name", "A name is 1 to 32 of a-z, 0-9, _ and -, starting with a letter"}
	}
	cred, refusal := h.credential(req.Credential, name)
	if refusal != nil {
		return refusal
	}
	if refusal := h.charge(w, h.registrations, h.clientAddr(r)); refusal != nil {
		return refusal
	}
	a, err := h.opts.Store.CreateAccount(r.Context(), name, store.VerifierOf("", cred), h.opts.MaxAccounts)
	switch {
	case errors.Is(err, store.ErrNameTaken):
		return &Refusal{http.StatusConflict, "name_taken", "The name is taken"}
	case errors.Is(err, store.ErrAccountsFull):
		return &Refusal{http.StatusServiceUnavailable, "accounts_full", "No account can be created now"}
	case err != nil:
		return h.busy("create account", err)
	}
	if err := h.opts.Scram.AddCredential(cred); err != nil {
		return h.busy("load credential", err)
	}
	WriteJSON(w, http.StatusCreated, RegisterResponse{ID: a.ID, Name: a.Name})
	return nil
}

// credential imports what the device derived and holds it to the one profile
// and to its name: a credential under another profile would tell a prober
// which accounts exist, and one for another name would let a sign-in as that
// name prove this account.
func (h *Handler) credential(raw json.RawMessage, name string) (*auth.Credential, *Refusal) {
	invalid := &Refusal{http.StatusBadRequest, "invalid_credential", "The credential is not one derived under this deployment's profile"}
	var fields struct {
		Username     string      `json:"username"`
		Salt         string      `json:"salt"`
		ArgonTime    json.Number `json:"argon_time"`
		ArgonMemory  json.Number `json:"argon_memory"`
		ArgonThreads json.Number `json:"argon_threads"`
		StoredKey    string      `json:"stored_key"`
		ServerKey    string      `json:"server_key"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return nil, invalid
	}
	cred, err := auth.ImportCredential(map[string]any{
		"username": fields.Username, "salt": fields.Salt, "argon_time": fields.ArgonTime,
		"argon_memory": fields.ArgonMemory, "argon_threads": fields.ArgonThreads,
		"stored_key": fields.StoredKey, "server_key": fields.ServerKey,
	})
	if err != nil {
		return nil, invalid
	}
	if k := h.opts.KDF; cred.ArgonMemory != k.Memory || cred.ArgonTime != k.Time || cred.ArgonThreads != k.Threads ||
		len(cred.Salt) != auth.DefaultArgonSaltLen {
		return nil, invalid
	}
	if cred.Username != name {
		return nil, &Refusal{http.StatusBadRequest, "invalid_credential", "The credential's username must be the name in lowercase"}
	}
	return cred, nil
}

// login is either SCRAM step. The name goes to the SCRAM server as the client
// spelled it, since the proof covers that spelling; an unknown one gets the
// decoy challenge and fails at the proof as a wrong password does.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) *Refusal {
	var req LoginRequest
	if refusal := ReadJSON(r, &req); refusal != nil {
		return refusal
	}
	if (req.ClientFirst == nil) == (req.Proof == nil) {
		return &Refusal{http.StatusBadRequest, "malformed_request", "Send the client first, or the proof, not both"}
	}
	addr := h.clientAddr(r)
	if req.ClientFirst != nil {
		if req.Device != "" || req.Session != "" {
			return &Refusal{http.StatusBadRequest, "malformed_request", "The device and the session ride with the proof"}
		}
		if refusal := h.charge(w, h.signIns, addr); refusal != nil {
			return refusal
		}
		challenge, err := h.opts.Scram.ProcessClientFirstMessage(req.ClientFirst.Username, req.ClientFirst.ClientNonce)
		switch {
		case errors.Is(err, auth.ErrSCRAMInvalidUsername), errors.Is(err, auth.ErrSCRAMInvalidNonce):
			return &Refusal{http.StatusBadRequest, "malformed_request", "The client first is not a username and a nonce"}
		case err != nil:
			return h.busy("challenge", err)
		}
		h.hold(challenge.FullNonce, addr)
		WriteJSON(w, http.StatusOK, LoginResponse{Challenge: &challenge})
		return nil
	}
	if req.Device == "" || utf8.RuneCountInString(req.Device) > store.MaxDevice {
		return &Refusal{http.StatusBadRequest, "malformed_request", fmt.Sprintf("A device name is 1 to %d characters", store.MaxDevice)}
	}
	if req.Session != "" && req.Session != "cookie" {
		return &Refusal{http.StatusBadRequest, "malformed_request", "The session is \"cookie\" or absent"}
	}
	addr = h.release(req.Proof.FullNonce, addr)
	final, err := h.opts.Scram.ProcessClientFinalMessage(req.Proof.FullNonce, req.Proof.ClientProof)
	if errors.Is(err, auth.ErrSCRAMStopped) {
		return errBusy
	}
	if err != nil {
		return errUnauthorized
	}
	// The SCRAM server is loaded at start, so an account disabled or deleted
	// since is refused here, as a wrong password is.
	a, err := h.opts.Store.AccountByName(r.Context(), final.Username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errUnauthorized
	case err != nil:
		return h.busy("account lookup", err)
	case a.DisabledAt != nil:
		return errUnauthorized
	}
	token := NewToken()
	now := store.Now()
	in := store.SignIn{
		ID: store.NewID(), AccountID: a.ID, TokenHash: store.HashToken(token), Device: req.Device,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(store.SignInLifetime),
	}
	if err := h.opts.Store.CreateSignIn(r.Context(), in); err != nil {
		return h.busy("create sign-in", err)
	}
	h.signIns.refund(addr)
	resp := LoginResponse{Final: &final, ExpiresIn: int64(store.SignInLifetime / time.Second)}
	if req.Session == "cookie" {
		http.SetCookie(w, signInCookie(token, int(store.SignInLifetime/time.Second)))
	} else {
		resp.Token = token
	}
	WriteJSON(w, http.StatusOK, resp)
	return nil
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) *Refusal {
	in, _, refusal := h.signedIn(r)
	if refusal != nil {
		return refusal
	}
	if err := h.opts.Store.DeleteSignInByToken(r.Context(), in.TokenHash); err != nil && !errors.Is(err, store.ErrNotFound) {
		return h.busy("logout", err)
	}
	http.SetCookie(w, signInCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) *Refusal {
	in, a, refusal := h.signedIn(r)
	if refusal != nil {
		return refusal
	}
	list, err := h.opts.Store.SignIns(r.Context(), a.ID)
	if err != nil {
		return h.busy("list sign-ins", err)
	}
	resp := MeResponse{ID: a.ID, Name: a.Name, SignIns: make([]SignInView, 0, len(list))}
	for _, s := range list {
		resp.SignIns = append(resp.SignIns, SignInView{
			ID: s.ID, Device: s.Device, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
			Current: s.ID == in.ID,
		})
	}
	WriteJSON(w, http.StatusOK, resp)
	return nil
}

func (h *Handler) deleteSignIn(w http.ResponseWriter, r *http.Request) *Refusal {
	id := strings.TrimPrefix(r.URL.Path, Prefix+"sign-ins/")
	if !idPattern.MatchString(id) {
		return &Refusal{http.StatusNotFound, "not_found", "No such sign-in"}
	}
	in, a, refusal := h.signedIn(r)
	if refusal != nil {
		return refusal
	}
	if refusal := h.charge(w, h.deletions, h.clientAddr(r)); refusal != nil {
		return refusal
	}
	switch err := h.opts.Store.DeleteSignIn(r.Context(), a.ID, id); {
	case errors.Is(err, store.ErrNotFound):
		return &Refusal{http.StatusNotFound, "not_found", "No such sign-in"}
	case err != nil:
		return h.busy("revoke sign-in", err)
	}
	if id == in.ID {
		http.SetCookie(w, signInCookie("", -1))
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// signedIn is the live sign-in a request presents as a bearer token or, from
// a page, in the cookie; a request with neither, or with a token the store
// does not know, is unauthorized without saying which.
func (h *Handler) signedIn(r *http.Request) (store.SignIn, store.Account, *Refusal) {
	var token string
	if header := r.Header.Get("Authorization"); header != "" {
		parsed, err := auth.ParseBearerToken(header)
		if err != nil {
			return store.SignIn{}, store.Account{}, errUnauthorized
		}
		token = parsed
	} else if c, err := r.Cookie(SignInCookie); err == nil {
		token = c.Value
	}
	if token == "" {
		return store.SignIn{}, store.Account{}, errUnauthorized
	}
	in, a, err := h.opts.Store.SignInByToken(r.Context(), store.HashToken(token))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.SignIn{}, store.Account{}, errUnauthorized
	case err != nil:
		return store.SignIn{}, store.Account{}, h.busy("sign-in lookup", err)
	}
	return in, a, nil
}

// charge spends one of addr's attempts from b, or refuses with the wait.
func (h *Handler) charge(w http.ResponseWriter, b *budget, addr string) *Refusal {
	wait := b.take(addr, time.Now())
	if wait == 0 {
		return nil
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	return &Refusal{http.StatusTooManyRequests, "too_many_attempts", "Too many attempts from this address; try again later"}
}

// busy is the answer when the store or the SCRAM server cannot serve: logged
// with the operation and the error, which name no credential.
func (h *Handler) busy(op string, err error) *Refusal {
	h.opts.Logger.Error("cannot answer", "op", op, "error", err)
	return errBusy
}

// hold remembers a challenged exchange until its proof, or until the
// handshake timeout abandons it.
func (h *Handler) hold(nonce, addr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.exchanges[nonce] = &exchange{addr: addr, timer: time.AfterFunc(handshakeTimeout, func() { h.abandon(nonce) })}
}

// release forgets an exchange whose proof arrived and names the address it
// was charged to; an exchange this process never challenged keeps addr.
func (h *Handler) release(nonce, addr string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ex, ok := h.exchanges[nonce]
	if !ok {
		return addr
	}
	ex.timer.Stop()
	delete(h.exchanges, nonce)
	return ex.addr
}

// abandon frees a handshake whose client never sent its proof, so it holds
// none of the SCRAM server's slots until that server's own sweep.
func (h *Handler) abandon(nonce string) {
	h.mu.Lock()
	_, ok := h.exchanges[nonce]
	delete(h.exchanges, nonce)
	h.mu.Unlock()
	if ok {
		h.opts.Scram.Abandon(nonce)
	}
}

// NewToken is a sign-in's secret: store.TokenBytes of entropy in the bearer
// alphabet, which the store keeps only hashed.
func NewToken() string {
	var b [store.TokenBytes]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// signInCookie is the token as a page holds it: unreadable by script, sent over
// TLS alone, same-site strictly, and under /vif/ alone, where the router reads
// it on the browser route's upgrade; maxAge below zero clears it, on the same
// path, or the browser would keep the old one.
func signInCookie(token string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: SignInCookie, Value: token, Path: CookiePath, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}
