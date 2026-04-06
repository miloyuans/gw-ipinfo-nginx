package routing

import (
	"net/http"
	"slices"
	"strings"

	"gw-ipinfo-nginx/internal/config"
)

type Resolver struct {
	defaultService config.ServiceConfig
	services       map[string]config.ServiceConfig
}

func NewResolver(cfg config.RoutingConfig) *Resolver {
	services := make(map[string]config.ServiceConfig, len(cfg.Services))
	var defaultSvc config.ServiceConfig
	for _, service := range cfg.Services {
		if len(service.MatchPathPrefixes) == 0 {
			service.MatchPathPrefixes = []string{"/"}
		}
		services[service.Name] = service
		if service.Name == cfg.DefaultService {
			defaultSvc = service
		}
	}
	return &Resolver{defaultService: defaultSvc, services: services}
}

func (r *Resolver) Resolve(req *http.Request) config.ServiceConfig {
	path := req.URL.Path
	best := r.defaultService
	bestLen := -1
	for _, service := range r.services {
		for _, prefix := range service.MatchPathPrefixes {
			if strings.HasPrefix(path, prefix) && len(prefix) > bestLen {
				best = service
				bestLen = len(prefix)
			}
		}
	}
	return best
}

func (r *Resolver) ServiceNames() []string {
	names := make([]string, 0, len(r.services))
	for name := range r.services {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
