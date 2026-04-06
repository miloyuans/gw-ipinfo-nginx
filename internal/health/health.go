package health

import (
	"context"
	"net/http"
	"sync/atomic"
)

type Checker interface {
	Check(context.Context) error
}

type Handler struct {
	ready atomic.Bool
	check Checker
}

func New(check Checker) *Handler {
	h := &Handler{check: check}
	h.ready.Store(true)
	return h
}

func (h *Handler) Liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *Handler) Readiness(w http.ResponseWriter, r *http.Request) {
	if !h.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if h.check != nil {
		if err := h.check.Check(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (h *Handler) SetReady(ready bool) {
	h.ready.Store(ready)
}
