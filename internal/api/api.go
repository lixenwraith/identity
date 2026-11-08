// Package api answers /vif/api/auth/, the account routes the router forwards
// byte for byte: registration with a derived credential, sign-in in two SCRAM
// steps, logout, an account's view of itself and its sign-ins, and a sign-in's
// revocation. Every body is bounded before it is decoded, every refusal is one
// JSON form, and no credential reaches a log.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

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
	// SignInCookie carries a page's token, scoped to /vif/api/ so the router
	// sees it on the browser route's upgrade and nothing else on the site does.
	SignInCookie = "vif_sign_in"
	CookiePath   = "/vif/api/"
	// ExchangeTimeout bounds one request's read and write; a SCRAM step is one
	// round trip and a slow reader holds nothing else.
	ExchangeTimeout = 10 * time.Second
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Options is what the handler needs beside the request: the store, the SCRAM
// server loaded with every verifier, and the deployment's policy.
type Options struct {
	Store               *store.Store
	Scram               *auth.ScramServer
	KDF                 config.KDF
	MaxAccounts         int
	ClientAddressHeader string
	Logger              *slog.Logger
}

type Handler struct {
	opts Options
}

func New(opts Options) *Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Handler{opts: opts}
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

var errNotImplemented = &Refusal{http.StatusNotImplemented, "not_implemented", "This route is not implemented yet"}

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
	return errNotImplemented
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) *Refusal {
	var req LoginRequest
	if refusal := ReadJSON(r, &req); refusal != nil {
		return refusal
	}
	if (req.ClientFirst == nil) == (req.Proof == nil) {
		return &Refusal{http.StatusBadRequest, "malformed_request", "Send the client first, or the proof, not both"}
	}
	return errNotImplemented
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) *Refusal {
	return errNotImplemented
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) *Refusal {
	return errNotImplemented
}

func (h *Handler) deleteSignIn(w http.ResponseWriter, r *http.Request) *Refusal {
	id := strings.TrimPrefix(r.URL.Path, Prefix+"sign-ins/")
	if !idPattern.MatchString(id) {
		return &Refusal{http.StatusNotFound, "not_found", "No such sign-in"}
	}
	return errNotImplemented
}

// NewToken is a sign-in's secret: store.TokenBytes of entropy in the bearer
// alphabet, which the store keeps only hashed.
func NewToken() string {
	var b [store.TokenBytes]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// signInCookie is the token as a page holds it: unreadable by script, sent over
// TLS alone, same-site strictly, and to /vif/api/ alone, where the router reads
// it on the browser route's upgrade; maxAge below zero clears it.
func signInCookie(token string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: SignInCookie, Value: token, Path: CookiePath, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}
