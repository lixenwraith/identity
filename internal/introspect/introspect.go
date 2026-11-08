// Package introspect answers the router's one question, on a loopback
// listener the forward never reaches: which account a sign-in token names. A
// renewal past the sign-in's half-life rides the same request, so a signed-in
// device costs the store one lookup per admission and nothing at rest.
package introspect

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/lixenwraith/identity/internal/api"
	"github.com/lixenwraith/identity/internal/store"
)

const (
	Path = "/introspect"
	// MaxBody bounds the one body this listener reads: a token and nothing else.
	MaxBody = 1024
	Timeout = 5 * time.Second
)

type Request struct {
	Token string `json:"token"`
}

// Response names the account a live sign-in belongs to, or none; renewed says
// the sign-in slid forward on this question.
type Response struct {
	Account *Account `json:"account"`
	Renewed bool     `json:"renewed,omitempty"`
}

type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

func New(s *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: s, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(Timeout))
	_ = rc.SetWriteDeadline(time.Now().Add(Timeout))
	if refusal := h.answer(w, r); refusal != nil {
		api.WriteRefusal(w, refusal)
		h.logger.Debug("refused", "method", r.Method, "path", r.URL.Path, "status", refusal.Status, "code", refusal.Code)
	}
}

func (h *Handler) answer(w http.ResponseWriter, r *http.Request) *api.Refusal {
	if r.URL.Path != Path {
		return &api.Refusal{Status: http.StatusNotFound, Code: "not_found", Message: "No such route"}
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return &api.Refusal{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "Introspection is a POST"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	var req Request
	if refusal := api.ReadJSON(r, &req); refusal != nil {
		return refusal
	}
	if req.Token == "" {
		return &api.Refusal{Status: http.StatusBadRequest, Code: "malformed_request", Message: "A token is required"}
	}
	return &api.Refusal{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "Introspection is not implemented yet"}
}
