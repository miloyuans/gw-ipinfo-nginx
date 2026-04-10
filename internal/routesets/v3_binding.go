package routesets

import (
	"sync"
	"time"
)

type v3Binding struct {
	RouteID          string
	ClientIP         string
	SelectedTargetID string
	ExpireAt         time.Time
	LastSeenAt       time.Time
}

type v3BindingStore struct {
	mu       sync.RWMutex
	bindings map[string]v3Binding
}

func newV3BindingStore() *v3BindingStore {
	return &v3BindingStore{
		bindings: make(map[string]v3Binding),
	}
}

func (s *v3BindingStore) Get(routeID, clientIP string, now time.Time) (v3Binding, bool) {
	if s == nil || clientIP == "" {
		return v3Binding{}, false
	}
	key := routeID + "|" + clientIP
	s.mu.RLock()
	binding, ok := s.bindings[key]
	s.mu.RUnlock()
	if !ok {
		return v3Binding{}, false
	}
	if now.After(binding.ExpireAt) {
		s.mu.Lock()
		delete(s.bindings, key)
		s.mu.Unlock()
		return v3Binding{}, false
	}
	return binding, true
}

func (s *v3BindingStore) Put(binding v3Binding) {
	if s == nil || binding.ClientIP == "" {
		return
	}
	s.mu.Lock()
	s.bindings[binding.RouteID+"|"+binding.ClientIP] = binding
	s.mu.Unlock()
}

func (s *v3BindingStore) Touch(routeID, clientIP string, now, expireAt time.Time) {
	if s == nil || clientIP == "" {
		return
	}
	key := routeID + "|" + clientIP
	s.mu.Lock()
	binding, ok := s.bindings[key]
	if ok {
		binding.LastSeenAt = now
		binding.ExpireAt = expireAt
		s.bindings[key] = binding
	}
	s.mu.Unlock()
}

func (s *v3BindingStore) SweepRoute(routeID string, now time.Time, maxIdle time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	for key, binding := range s.bindings {
		if binding.RouteID != routeID {
			continue
		}
		if now.After(binding.ExpireAt) {
			delete(s.bindings, key)
			continue
		}
		if maxIdle > 0 && now.Sub(binding.LastSeenAt) > maxIdle {
			delete(s.bindings, key)
		}
	}
	s.mu.Unlock()
}
