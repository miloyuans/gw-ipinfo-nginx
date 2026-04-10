package ipinfo

import (
	"context"
	"errors"
	"time"

	"gw-ipinfo-nginx/internal/cache"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/metrics"
	"gw-ipinfo-nginx/internal/syncx"
)

type CacheRepository interface {
	Get(ctx context.Context, ip string) (cache.Entry, ipctx.CacheSource, bool, error)
	Upsert(ctx context.Context, ip string, entry cache.Entry) error
}

type LookupService struct {
	enabled                bool
	enableResidentialProxy bool
	l1                     *cache.L1
	repo                   CacheRepository
	client                 *Client
	ttls                   config.CacheTTLConfig
	failureTTL             time.Duration
	metrics                *metrics.GatewayMetrics
	group                  syncx.Group
}

func NewLookupService(cfg *config.Config, l1 *cache.L1, repo CacheRepository, client *Client, metricsSet *metrics.GatewayMetrics) *LookupService {
	return &LookupService{
		enabled:                cfg.IPInfo.Enabled,
		enableResidentialProxy: cfg.Security.Privacy.EnableResidentialProxy || cfg.IPInfo.IncludeResidentialProxy,
		l1:                     l1,
		repo:                   repo,
		client:                 client,
		ttls:                   cfg.Cache.TTL,
		failureTTL:             cfg.Cache.FailureTTL,
		metrics:                metricsSet,
	}
}

func (s *LookupService) Lookup(ctx context.Context, ip string) (ipctx.Context, ipctx.CacheSource, string, error) {
	if !s.enabled || s.client == nil {
		return ipctx.Context{}, ipctx.CacheSourceNone, "disabled", nil
	}

	now := time.Now().UTC()

	if entry, ok := s.l1.Get(ip, now, s.enableResidentialProxy); ok {
		s.recordLookup(ipctx.CacheSourceL1, entry.Failure == "")
		if entry.Failure != "" {
			return ipctx.Context{}, ipctx.CacheSourceL1, "cache_hit_l1", errors.New(entry.Failure)
		}
		return entry.IPContext, ipctx.CacheSourceL1, "cache_hit_l1", nil
	}

	if s.repo != nil {
		repoStart := time.Now()
		entry, source, found, err := s.repo.Get(ctx, ip)
		s.recordMongoLatency(time.Since(repoStart))

		if err == nil && found && entry.Fresh(now, s.enableResidentialProxy) {
			s.l1.Set(ip, entry)
			s.recordLookup(source, entry.Failure == "")
			if entry.Failure != "" {
				return ipctx.Context{}, source, actionForCacheSource(source), errors.New(entry.Failure)
			}
			return entry.IPContext, source, actionForCacheSource(source), nil
		}

		if err != nil {
			s.recordLookup(source, false)
		}
	}

	value, _, _ := s.group.Do(ip, func() (any, error) {
		now := time.Now().UTC()

		if entry, ok := s.l1.Get(ip, now, s.enableResidentialProxy); ok {
			if entry.Failure != "" {
				return lookupResult{source: ipctx.CacheSourceL1, err: errors.New(entry.Failure)}, nil
			}
			return lookupResult{source: ipctx.CacheSourceL1, value: entry.IPContext}, nil
		}

		if s.repo != nil {
			repoStart := time.Now()
			entry, source, found, err := s.repo.Get(ctx, ip)
			s.recordMongoLatency(time.Since(repoStart))

			if err == nil && found && entry.Fresh(now, s.enableResidentialProxy) {
				s.l1.Set(ip, entry)
				if entry.Failure != "" {
					return lookupResult{source: source, err: errors.New(entry.Failure)}, nil
				}
				return lookupResult{source: source, value: entry.IPContext}, nil
			}
		}

		ipinfoStart := time.Now()
		details, err := s.client.LookupDetails(ctx, ip)
		s.recordIPInfoRequest(time.Since(ipinfoStart), err)

		if err != nil {
			entry := s.failureEntry(err, now)
			s.l1.Set(ip, entry)
			if s.repo != nil {
				_ = s.repo.Upsert(ctx, ip, entry)
			}
			return lookupResult{source: ipctx.CacheSourceIPInfo, err: err}, nil
		}

		entry := s.successEntryFromDetails(details, now)
		s.l1.Set(ip, entry)
		if s.repo != nil {
			_ = s.repo.Upsert(ctx, ip, entry)
		}

		return lookupResult{
			source: ipctx.CacheSourceIPInfo,
			value:  entry.IPContext,
		}, nil
	})

	result := value.(lookupResult)
	s.recordLookup(result.source, result.err == nil)

	if result.source == ipctx.CacheSourceIPInfo {
		if result.err != nil {
			return result.value, result.source, "remote_error", result.err
		}
		return result.value, result.source, "remote_success", result.err
	}

	return result.value, result.source, actionForCacheSource(result.source), result.err
}

func (s *LookupService) LookupDetails(ctx context.Context, ip string) (LookupDetails, ipctx.CacheSource, string, error) {
	if !s.enabled || s.client == nil {
		return LookupDetails{}, ipctx.CacheSourceNone, "disabled", nil
	}

	now := time.Now().UTC()

	if entry, ok := s.l1.Get(ip, now, s.enableResidentialProxy); ok {
		s.recordLookup(ipctx.CacheSourceL1, entry.Failure == "")
		if entry.Failure != "" {
			return LookupDetails{}, ipctx.CacheSourceL1, "cache_hit_l1", errors.New(entry.Failure)
		}
		return detailsFromEntry(entry), ipctx.CacheSourceL1, "cache_hit_l1", nil
	}

	if s.repo != nil {
		repoStart := time.Now()
		entry, source, found, err := s.repo.Get(ctx, ip)
		s.recordMongoLatency(time.Since(repoStart))

		if err == nil && found && entry.Fresh(now, s.enableResidentialProxy) {
			s.l1.Set(ip, entry)
			s.recordLookup(source, entry.Failure == "")
			if entry.Failure != "" {
				return LookupDetails{}, source, actionForCacheSource(source), errors.New(entry.Failure)
			}
			return detailsFromEntry(entry), source, actionForCacheSource(source), nil
		}

		if err != nil {
			s.recordLookup(source, false)
		}
	}

	value, _, _ := s.group.Do("details:"+ip, func() (any, error) {
		now := time.Now().UTC()

		if entry, ok := s.l1.Get(ip, now, s.enableResidentialProxy); ok {
			if entry.Failure != "" {
				return lookupDetailsResult{source: ipctx.CacheSourceL1, err: errors.New(entry.Failure)}, nil
			}
			return lookupDetailsResult{source: ipctx.CacheSourceL1, value: detailsFromEntry(entry)}, nil
		}

		if s.repo != nil {
			repoStart := time.Now()
			entry, source, found, err := s.repo.Get(ctx, ip)
			s.recordMongoLatency(time.Since(repoStart))

			if err == nil && found && entry.Fresh(now, s.enableResidentialProxy) {
				s.l1.Set(ip, entry)
				if entry.Failure != "" {
					return lookupDetailsResult{source: source, err: errors.New(entry.Failure)}, nil
				}
				return lookupDetailsResult{source: source, value: detailsFromEntry(entry)}, nil
			}
		}

		ipinfoStart := time.Now()
		details, err := s.client.LookupDetails(ctx, ip)
		s.recordIPInfoRequest(time.Since(ipinfoStart), err)

		if err != nil {
			entry := s.failureEntry(err, now)
			s.l1.Set(ip, entry)
			if s.repo != nil {
				_ = s.repo.Upsert(ctx, ip, entry)
			}
			return lookupDetailsResult{source: ipctx.CacheSourceIPInfo, err: err}, nil
		}

		entry := s.successEntryFromDetails(details, now)
		s.l1.Set(ip, entry)
		if s.repo != nil {
			_ = s.repo.Upsert(ctx, ip, entry)
		}

		return lookupDetailsResult{source: ipctx.CacheSourceIPInfo, value: details}, nil
	})

	result := value.(lookupDetailsResult)
	s.recordLookup(result.source, result.err == nil)

	if result.source == ipctx.CacheSourceIPInfo {
		if result.err != nil {
			return result.value, result.source, "remote_error", result.err
		}
		return result.value, result.source, "remote_success", nil
	}

	return result.value, result.source, actionForCacheSource(result.source), result.err
}

type lookupResult struct {
	source ipctx.CacheSource
	value  ipctx.Context
	err    error
}

type lookupDetailsResult struct {
	source ipctx.CacheSource
	value  LookupDetails
	err    error
}

func (s *LookupService) recordLookup(source ipctx.CacheSource, success bool) {
	if s.metrics == nil {
		return
	}
	status := "hit"
	if source == ipctx.CacheSourceIPInfo {
		status = "miss"
	}
	if !success {
		status = "error"
	}
	s.metrics.LookupResults.Inc(metrics.Labels{
		"source": string(source),
		"status": status,
	})
}

func (s *LookupService) recordMongoLatency(duration time.Duration) {
	if s.metrics == nil {
		return
	}
	s.metrics.MongoLatency.Observe(nil, duration.Seconds())
}

func (s *LookupService) recordIPInfoRequest(duration time.Duration, err error) {
	if s.metrics == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "error"
	}
	s.metrics.IPInfoRequests.Inc(metrics.Labels{"status": status})
	s.metrics.IPInfoLatency.Observe(metrics.Labels{"status": status}, duration.Seconds())
}

func maxTime(values ...time.Time) time.Time {
	var best time.Time
	for _, value := range values {
		if value.After(best) {
			best = value
		}
	}
	return best
}

func actionForCacheSource(source ipctx.CacheSource) string {
	switch source {
	case ipctx.CacheSourceL1:
		return "cache_hit_l1"
	case ipctx.CacheSourceMongo:
		return "cache_hit_mongo"
	case ipctx.CacheSourceLocal:
		return "cache_hit_localdisk"
	default:
		return "start"
	}
}
