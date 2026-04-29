package reporting

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/metrics"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/runtimex"
	"gw-ipinfo-nginx/internal/storage"

	bolt "go.etcd.io/bbolt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Event struct {
	Timestamp            time.Time
	ClientIP             string
	ServiceName          string
	RouteSetKind         string
	RouteID              string
	SourceHost           string
	TargetHost           string
	BackendService       string
	BackendHost          string
	V4RouteSource        string
	Host                 string
	Path                 string
	RequestURL           string
	UserAgent            string
	UserAgentSummary     string
	AcceptLanguage       string
	Allowed              bool
	Result               string
	ReasonCode           string
	RedirectTriggered    bool
	CountryCode          string
	CountryName          string
	Region               string
	City                 string
	Privacy              ipctx.PrivacyFlags
	ShortCircuitHit      bool
	ShortCircuitDecision string
	V3SecurityFilterEnabled bool
	V3SelectedTargetID      string
	V3SelectedTargetHost    string
	V3StrategyMode          string
	V3BindingReused         bool
	V4RuntimeMode           string
	V4SecurityChecksEnabled bool
	V4EnrichmentMode        string
	V4ProbeEnabled          bool
	IPInfoLookupAction      string
	DataSourceMode          string
}

type HostTraffic struct {
	TotalCount           uint64            `json:"total_count" bson:"total_count"`
	AllowCount           uint64            `json:"allow_count" bson:"allow_count"`
	DenyCount            uint64            `json:"deny_count" bson:"deny_count"`
	RedirectCount        uint64            `json:"redirect_count" bson:"redirect_count"`
	RouteSetCounts       map[string]uint64 `json:"route_set_counts" bson:"route_set_counts"`
	RouteIDCounts        map[string]uint64 `json:"route_id_counts" bson:"route_id_counts"`
	AllowReasons         map[string]uint64 `json:"allow_reasons" bson:"allow_reasons"`
	DenyReasons          map[string]uint64 `json:"deny_reasons" bson:"deny_reasons"`
	PathCounts           map[string]uint64 `json:"path_counts" bson:"path_counts"`
	RequestURLCounts     map[string]uint64 `json:"request_url_counts" bson:"request_url_counts"`
	UserAgentCounts      map[string]uint64 `json:"user_agent_counts" bson:"user_agent_counts"`
	AcceptLanguageCounts map[string]uint64 `json:"accept_language_counts" bson:"accept_language_counts"`
}

type Summary struct {
	ID                     string             `json:"id" bson:"_id"`
	Kind                   string             `json:"kind" bson:"kind"`
	Day                    string             `json:"day" bson:"day"`
	ClientIP               string             `json:"client_ip" bson:"client_ip"`
	ServiceName            string             `json:"service_name" bson:"service_name"`
	RouteSetKind           string             `json:"route_set_kind" bson:"route_set_kind"`
	RouteID                string             `json:"route_id" bson:"route_id"`
	SourceHost             string             `json:"source_host" bson:"source_host"`
	TargetHost             string             `json:"target_host" bson:"target_host"`
	BackendService         string             `json:"backend_service" bson:"backend_service"`
	BackendHost            string             `json:"backend_host" bson:"backend_host"`
	V4RouteSource          string             `json:"v4_route_source" bson:"v4_route_source"`
	V3SecurityFilterEnabled bool              `json:"v3_security_filter_enabled" bson:"v3_security_filter_enabled"`
	V3SelectedTargetID      string            `json:"v3_selected_target_id" bson:"v3_selected_target_id"`
	V3SelectedTargetHost    string            `json:"v3_selected_target_host" bson:"v3_selected_target_host"`
	V3StrategyMode          string            `json:"v3_strategy_mode" bson:"v3_strategy_mode"`
	V3BindingReused         bool              `json:"v3_binding_reused" bson:"v3_binding_reused"`
	V4RuntimeMode           string            `json:"v4_runtime_mode" bson:"v4_runtime_mode"`
	V4SecurityChecksEnabled bool              `json:"v4_security_checks_enabled" bson:"v4_security_checks_enabled"`
	V4EnrichmentMode        string            `json:"v4_enrichment_mode" bson:"v4_enrichment_mode"`
	V4ProbeEnabled          bool              `json:"v4_probe_enabled" bson:"v4_probe_enabled"`
	IPInfoLookupAction      string            `json:"ipinfo_lookup_action" bson:"ipinfo_lookup_action"`
	DataSourceMode          string            `json:"data_source_mode" bson:"data_source_mode"`
	Host                   string             `json:"host" bson:"host"`
	Path                   string             `json:"path" bson:"path"`
	RequestURL             string             `json:"request_url" bson:"request_url"`
	UserAgent              string             `json:"user_agent" bson:"user_agent"`
	UserAgentSummary       string             `json:"user_agent_summary" bson:"user_agent_summary"`
	AcceptLanguage         string             `json:"accept_language" bson:"accept_language"`
	AllowCount             uint64             `json:"allow_count" bson:"allow_count"`
	DenyCount              uint64             `json:"deny_count" bson:"deny_count"`
	RedirectCount          uint64             `json:"redirect_count" bson:"redirect_count"`
	ShortCircuitAllowCount uint64             `json:"short_circuit_allow_count" bson:"short_circuit_allow_count"`
	ShortCircuitDenyCount  uint64             `json:"short_circuit_deny_count" bson:"short_circuit_deny_count"`
	AllowReasons           map[string]uint64  `json:"allow_reasons" bson:"allow_reasons"`
	DenyReasons            map[string]uint64  `json:"deny_reasons" bson:"deny_reasons"`
	RouteSetCounts         map[string]uint64  `json:"route_set_counts" bson:"route_set_counts"`
	RouteIDCounts          map[string]uint64  `json:"route_id_counts" bson:"route_id_counts"`
	RequestURLCounts       map[string]uint64  `json:"request_url_counts" bson:"request_url_counts"`
	PathCounts             map[string]uint64  `json:"path_counts" bson:"path_counts"`
	UserAgentCounts        map[string]uint64  `json:"user_agent_counts" bson:"user_agent_counts"`
	AcceptLanguageCounts   map[string]uint64  `json:"accept_language_counts" bson:"accept_language_counts"`
	CountryCounts          map[string]uint64  `json:"country_counts" bson:"country_counts"`
	RegionCounts           map[string]uint64  `json:"region_counts" bson:"region_counts"`
	CityCounts             map[string]uint64  `json:"city_counts" bson:"city_counts"`
	HostStats              map[string]HostTraffic `json:"host_stats" bson:"host_stats"`
	CountryCode            string             `json:"country_code" bson:"country_code"`
	CountryName            string             `json:"country_name" bson:"country_name"`
	Region                 string             `json:"region" bson:"region"`
	City                   string             `json:"city" bson:"city"`
	Privacy                ipctx.PrivacyFlags `json:"privacy" bson:"privacy"`
	FirstSeenAt            time.Time          `json:"first_seen_at" bson:"first_seen_at"`
	LastSeenAt             time.Time          `json:"last_seen_at" bson:"last_seen_at"`
	UpdatedAt              time.Time          `json:"updated_at" bson:"updated_at"`
}

type aggregateRow struct {
	Key   string
	Value uint64
}

type reportDeliveryState struct {
	ID                string    `json:"id" bson:"_id"`
	Kind              string    `json:"kind" bson:"kind"`
	Day               string    `json:"day" bson:"day"`
	AttemptCount      int       `json:"attempt_count" bson:"attempt_count"`
	LastAttemptAt     time.Time `json:"last_attempt_at" bson:"last_attempt_at"`
	LastError         string    `json:"last_error" bson:"last_error"`
	TelegramHTMLSent  bool      `json:"telegram_html_sent" bson:"telegram_html_sent"`
	TelegramCSVSent   bool      `json:"telegram_csv_sent" bson:"telegram_csv_sent"`
	FileHTMLWritten   bool      `json:"file_html_written" bson:"file_html_written"`
	FileCSVWritten    bool      `json:"file_csv_written" bson:"file_csv_written"`
	TelegramSuccess   bool      `json:"telegram_success" bson:"telegram_success"`
	FileSuccess       bool      `json:"file_success" bson:"file_success"`
	OverallSuccess    bool      `json:"overall_success" bson:"overall_success"`
	UpdatedAt         time.Time `json:"updated_at" bson:"updated_at"`
}

type reportCandidate struct {
	ReportDay  time.Time
	ReportTime time.Time
	DayKey     string
	DayLabel   string
	State      reportDeliveryState
}

type Service struct {
	cfg            *config.Config
	controller     *storage.Controller
	logger         *slog.Logger
	sender         *alerts.Sender
	metrics        *metrics.GatewayMetrics
	location       *time.Location
	locationName   string
	queue          chan Event
	workerID       string
	collectionName string
	leaseStore     *reportLeaseStore
	indexOnce      sync.Once
	scheduleMu     sync.Mutex
	lastSkipLogKey string
	lastMongoWaitLogKey string
}

func NewService(cfg *config.Config, controller *storage.Controller, logger *slog.Logger, sender *alerts.Sender, metricsSet *metrics.GatewayMetrics, workerID string, sharedStoragePath string) (*Service, error) {
	location, locationName, err := resolveReportLocation(cfg.Reports)
	if err != nil {
		return nil, err
	}
	leaseBasePath := strings.TrimSpace(sharedStoragePath)
	if leaseBasePath == "" {
		leaseBasePath = cfg.Storage.LocalPath
	}
	service := &Service{
		cfg:            cfg,
		controller:     controller,
		logger:         logger,
		sender:         sender,
		metrics:        metricsSet,
		location:       location,
		locationName:   locationName,
		queue:          make(chan Event, cfg.Perf.StatsQueueSize),
		workerID:       workerID,
		collectionName: cfg.Cache.MongoCollections.ReportEvents,
		leaseStore:     newReportLeaseStore(controller, filepath.Join(filepath.Dir(filepath.Clean(leaseBasePath)), "report-scheduler-lease.json"), cfg.Cache.MongoCollections.ReportEvents, cfg.Reports.LeaderLeaseName),
	}
	if controller != nil {
		controller.RegisterReplayer(service)
	}
	return service, nil
}

func (s *Service) Name() string {
	return "daily_reports"
}

func (s *Service) Track(event Event) {
	if strings.TrimSpace(event.ClientIP) == "" {
		event.ClientIP = "(unknown)"
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case s.queue <- event:
	default:
		go func() {
			if err := s.persist(context.Background(), event); err != nil && s.logger != nil {
				s.logger.Warn("report_track_fallback_failed", "event", "report_track_fallback_failed", "client_ip", event.ClientIP, "error", err)
			}
		}()
	}
}

func (s *Service) Run(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 1
	}
	for idx := 0; idx < workers; idx++ {
		go s.runWorker(ctx)
	}
	if s.cfg.Reports.Enabled && s.cfg.Reports.WorkerEnabled && runtimex.IsPrimaryProcess() {
		if s.logger != nil {
			s.logger.Info("daily_report_scheduler_started",
				"event", "daily_report_scheduler_started",
				"title", s.cfg.Reports.Title,
				"timezone_mode", s.cfg.Reports.TimeZoneMode,
				"resolved_timezone", s.locationName,
				"period_mode", s.cfg.Reports.PeriodMode,
				"retry_interval", s.cfg.Reports.RetryInterval,
				"leader_lease_name", s.cfg.Reports.LeaderLeaseName,
				"leader_lease_ttl", s.cfg.Reports.LeaderLeaseTTL,
				"leader_renew_interval", s.cfg.Reports.LeaderRenewInterval,
				"max_backfill_days", s.cfg.Reports.MaxBackfillDays,
				"telegram_enabled", s.cfg.Reports.Output.TelegramEnabled,
				"file_enabled", s.cfg.Reports.Output.FileEnabled,
			)
		}
		go s.runScheduler(ctx)
	}
}

func (s *Service) reportMongoAvailable() bool {
	return s != nil && s.controller != nil && s.controller.Client() != nil && s.controller.Mode() != storage.ModeLocal
}

func (s *Service) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	keys, err := s.controller.Local().DirtyKeys(ctx, localdisk.BucketReportDirty, batchSize)
	if err != nil {
		return 0, err
	}

	replayed := 0

	for _, key := range keys {
		var summary Summary
		if err := s.controller.Local().GetJSON(ctx, localdisk.BucketReportRecords, key, &summary); err != nil {
			if err == localdisk.ErrNotFound {
				_ = s.controller.Local().ClearDirty(ctx, localdisk.BucketReportDirty, key)
				continue
			}
			return replayed, err
		}

		if err := s.upsertMongo(ctx, client, summary); err != nil {
			return replayed, err
		}

		if err := s.controller.Local().ClearDirty(ctx, localdisk.BucketReportDirty, key); err != nil {
			return replayed, err
		}

		replayed++
	}

	return replayed, nil
}

func (s *Service) GenerateDaily(ctx context.Context, day time.Time) ([]byte, []byte, error) {
	dayKey := day.In(s.location).Format("2006-01-02")
	summaries, err := s.loadDay(ctx, dayKey)
	if err != nil {
		return nil, nil, err
	}
	htmlReport, err := s.renderHTML(dayKey, summaries)
	if err != nil {
		return nil, nil, err
	}
	csvReport, err := s.renderCSV(summaries)
	if err != nil {
		return nil, nil, err
	}
	return htmlReport, csvReport, nil
}

func (s *Service) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.queue:
			if err := s.persist(ctx, event); err != nil && s.logger != nil {
				s.logger.Warn("report_persist_error", "event", "report_persist_error", "client_ip", event.ClientIP, "error", err)
			}
		}
	}
}

func (s *Service) persist(ctx context.Context, event Event) error {
	client := s.controller.Client()
	if client != nil && s.controller.Mode() != storage.ModeLocal {
		summary := s.summaryFromEvent(event)
		if err := s.upsertMongo(ctx, client, summary); err == nil {
			return nil
		} else {
			s.controller.HandleMongoError(err)
		}
	}
	_, err := s.upsertLocal(ctx, event)
	return err
}

func (s *Service) upsertLocal(ctx context.Context, event Event) (Summary, error) {
	now := event.Timestamp.UTC()
	dayKey := event.Timestamp.In(s.location).Format("2006-01-02")
	summaryID := dayKey + "|" + reportPrimaryHost(event) + "|" + event.ClientIP
	var summary Summary
	err := s.controller.Local().Update(ctx, func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(localdisk.BucketReportRecords))
		dirty := tx.Bucket([]byte(localdisk.BucketReportDirty))
		if raw := bucket.Get([]byte(summaryID)); raw != nil {
			if err := json.Unmarshal(raw, &summary); err != nil {
				return err
			}
		} else {
			summary = Summary{
				ID:           summaryID,
				Kind:         "summary",
				Day:          dayKey,
				ClientIP:     event.ClientIP,
				AllowReasons: map[string]uint64{},
				DenyReasons:  map[string]uint64{},
				RouteSetCounts: map[string]uint64{},
				RouteIDCounts: map[string]uint64{},
				RequestURLCounts: map[string]uint64{},
				PathCounts: map[string]uint64{},
				UserAgentCounts: map[string]uint64{},
				AcceptLanguageCounts: map[string]uint64{},
				CountryCounts: map[string]uint64{},
				RegionCounts: map[string]uint64{},
				CityCounts: map[string]uint64{},
				FirstSeenAt:  now,
			}
		}
		applyEvent(&summary, event, now)
		raw, err := json.Marshal(summary)
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte(summaryID), raw); err != nil {
			return err
		}
		return dirty.Put([]byte(summaryID), []byte(now.Format(time.RFC3339Nano)))
	})
	return summary, err
}

func applyEvent(summary *Summary, event Event, now time.Time) {
	if summary.Kind == "" {
		summary.Kind = "summary"
	}
	if summary.AllowReasons == nil {
		summary.AllowReasons = map[string]uint64{}
	}
	if summary.DenyReasons == nil {
		summary.DenyReasons = map[string]uint64{}
	}
	if summary.RouteSetCounts == nil {
		summary.RouteSetCounts = map[string]uint64{}
	}
	if summary.RouteIDCounts == nil {
		summary.RouteIDCounts = map[string]uint64{}
	}
	if summary.RequestURLCounts == nil {
		summary.RequestURLCounts = map[string]uint64{}
	}
	if summary.PathCounts == nil {
		summary.PathCounts = map[string]uint64{}
	}
	if summary.UserAgentCounts == nil {
		summary.UserAgentCounts = map[string]uint64{}
	}
	if summary.AcceptLanguageCounts == nil {
		summary.AcceptLanguageCounts = map[string]uint64{}
	}
	if summary.CountryCounts == nil {
		summary.CountryCounts = map[string]uint64{}
	}
	if summary.RegionCounts == nil {
		summary.RegionCounts = map[string]uint64{}
	}
	if summary.CityCounts == nil {
		summary.CityCounts = map[string]uint64{}
	}
	summary.ServiceName = event.ServiceName
	summary.RouteSetKind = event.RouteSetKind
	summary.RouteID = event.RouteID
	summary.SourceHost = normalizeReportHost(event.SourceHost)
	summary.TargetHost = normalizeReportHost(event.TargetHost)
	summary.BackendService = event.BackendService
	summary.BackendHost = normalizeReportHost(event.BackendHost)
	summary.V4RouteSource = event.V4RouteSource
	summary.V3SecurityFilterEnabled = event.V3SecurityFilterEnabled
	summary.V3SelectedTargetID = event.V3SelectedTargetID
	summary.V3SelectedTargetHost = event.V3SelectedTargetHost
	summary.V3StrategyMode = event.V3StrategyMode
	summary.V3BindingReused = event.V3BindingReused
	summary.V4RuntimeMode = event.V4RuntimeMode
	summary.V4SecurityChecksEnabled = event.V4SecurityChecksEnabled
	summary.V4EnrichmentMode = event.V4EnrichmentMode
	summary.V4ProbeEnabled = event.V4ProbeEnabled
	summary.IPInfoLookupAction = event.IPInfoLookupAction
	summary.DataSourceMode = event.DataSourceMode
	summary.Host = normalizeReportHost(event.Host)
	summary.Path = event.Path
	summary.RequestURL = event.RequestURL
	summary.UserAgent = event.UserAgent
	summary.UserAgentSummary = event.UserAgentSummary
	summary.AcceptLanguage = event.AcceptLanguage
	summary.CountryCode = event.CountryCode
	summary.CountryName = event.CountryName
	summary.Region = event.Region
	summary.City = event.City
	summary.Privacy = event.Privacy
	summary.LastSeenAt = now
	summary.UpdatedAt = now
	incrementCount(summary.RouteSetCounts, event.RouteSetKind)
	incrementCount(summary.RouteIDCounts, event.RouteID)
	incrementCount(summary.RequestURLCounts, event.RequestURL)
	incrementCount(summary.PathCounts, event.Path)
	incrementCount(summary.UserAgentCounts, event.UserAgent)
	incrementCount(summary.AcceptLanguageCounts, event.AcceptLanguage)
	incrementCount(summary.CountryCounts, reportLocationValue(event.CountryCode, event.CountryName))
	incrementCount(summary.RegionCounts, event.Region)
	incrementCount(summary.CityCounts, event.City)
	if event.Allowed {
		summary.AllowCount++
		summary.AllowReasons[event.ReasonCode]++
	} else {
		summary.DenyCount++
		summary.DenyReasons[event.ReasonCode]++
	}
	if event.RedirectTriggered {
		summary.RedirectCount++
	}
	if event.ShortCircuitHit {
		if event.ShortCircuitDecision == "allow" {
			summary.ShortCircuitAllowCount++
		} else if event.ShortCircuitDecision == "deny" {
			summary.ShortCircuitDenyCount++
		}
	}
}

func (s *Service) upsertMongo(ctx context.Context, client *mongostore.Client, summary Summary) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	collection := client.Database().Collection(s.collectionName)
	s.indexOnce.Do(func() {
		indexes := []mongo.IndexModel{
			{
				Keys:    bson.D{{Key: "day", Value: 1}, {Key: "host", Value: 1}, {Key: "client_ip", Value: 1}},
				Options: options.Index().SetName("daily_host_ip_lookup"),
			},
			{
				Keys:    bson.D{{Key: "kind", Value: 1}, {Key: "day", Value: 1}},
				Options: options.Index().SetName("report_kind_day"),
			},
			{
				Keys:    bson.D{{Key: "day", Value: 1}, {Key: "host", Value: 1}},
				Options: options.Index().SetName("report_day_host"),
			},
		}
		_, _ = collection.Indexes().CreateMany(child, indexes)
	})

	_, err := collection.ReplaceOne(child, bson.M{"_id": summary.ID}, summary, options.Replace().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("upsert report summary %s: %w", summary.ID, err)
	}
	return nil
}

func (s *Service) runScheduler(ctx context.Context) {
	if s.leaseStore == nil {
		return
	}

	workTicker := time.NewTicker(s.cfg.Reports.PollInterval)
	renewTicker := time.NewTicker(s.cfg.Reports.LeaderRenewInterval)
	defer workTicker.Stop()
	defer renewTicker.Stop()

	isLeader := false
	if s.reportMongoAvailable() && s.acquireSchedulerLeader(ctx) {
		isLeader = true
		if err := s.trySendDailyReport(ctx, time.Now().UTC()); err != nil && s.logger != nil {
			s.logger.Warn("daily_report_error", "event", "daily_report_error", "error", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			if isLeader {
				_ = s.leaseStore.Release(context.Background(), s.workerID)
			}
			return
		case <-renewTicker.C:
			if !s.reportMongoAvailable() {
				if isLeader {
					isLeader = false
				}
				s.logMongoUnavailableOnce()
				continue
			}
			if isLeader {
				ok, err := s.leaseStore.Refresh(ctx, s.workerID, time.Now().UTC(), s.cfg.Reports.LeaderLeaseTTL)
				if err != nil || !ok {
					isLeader = false
					if s.logger != nil {
						s.logger.Warn("daily_report_leader_lost",
							"event", "daily_report_leader_lost",
							"worker_id", s.workerID,
							"error", err,
						)
					}
				}
				continue
			}
			isLeader = s.acquireSchedulerLeader(ctx)
		case <-workTicker.C:
			if !s.reportMongoAvailable() {
				if isLeader {
					isLeader = false
				}
				s.logMongoUnavailableOnce()
				continue
			}
			if !isLeader {
				continue
			}
			if err := s.trySendDailyReport(ctx, time.Now().UTC()); err != nil && s.logger != nil {
				s.logger.Warn("daily_report_error", "event", "daily_report_error", "error", err)
			}
		}
	}
}

func (s *Service) acquireSchedulerLeader(ctx context.Context) bool {
	lease, acquired, err := s.leaseStore.TryAcquire(ctx, s.workerID, time.Now().UTC(), s.cfg.Reports.LeaderLeaseTTL)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("daily_report_leader_acquire_error",
				"event", "daily_report_leader_acquire_error",
				"lease_name", s.cfg.Reports.LeaderLeaseName,
				"worker_id", s.workerID,
				"error", err,
			)
		}
		return false
	}
	if !acquired {
		return false
	}
	if s.logger != nil {
		s.logger.Info("daily_report_leader_acquired",
			"event", "daily_report_leader_acquired",
			"lease_name", s.cfg.Reports.LeaderLeaseName,
			"worker_id", s.workerID,
			"owner_id", lease.OwnerID,
		)
	}
	return true
}

func (s *Service) trySendDailyReport(ctx context.Context, now time.Time) error {
	candidate, err := s.nextReportCandidate(ctx, now)
	if err != nil {
		return err
	}

	reportTime, err := s.reportTime(now)
	if err != nil {
		return err
	}
	if candidate == nil {
		s.logSkipBeforeTimeOnce(now, reportTime)
		return nil
	}

	return s.deliverReportCandidate(ctx, now, *candidate)
}

func (s *Service) reportTime(now time.Time) (time.Time, error) {
	parts := strings.Split(s.cfg.Reports.DailySendTime, ":")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("invalid report time %q", s.cfg.Reports.DailySendTime)
	}
	var hour, minute int
	if _, err := fmt.Sscanf(s.cfg.Reports.DailySendTime, "%d:%d", &hour, &minute); err != nil {
		return time.Time{}, err
	}
	localNow := now.In(s.location)
	return time.Date(localNow.Year(), localNow.Month(), localNow.Day(), hour, minute, 0, 0, s.location), nil
}

func (s *Service) resolveReportDay(reportTime time.Time) time.Time {
	if s.cfg.Reports.PeriodMode == "previous_day" {
		target := reportTime.In(s.location).AddDate(0, 0, -1)
		return time.Date(target.Year(), target.Month(), target.Day(), 0, 0, 0, 0, s.location)
	}
	return reportTime.Add(-s.cfg.Reports.Lookback)
}

func (s *Service) nextReportCandidate(ctx context.Context, now time.Time) (*reportCandidate, error) {
	localNow := now.In(s.location)
	for offset := s.cfg.Reports.MaxBackfillDays - 1; offset >= 0; offset-- {
		scheduledLocal := localNow.AddDate(0, 0, -offset)
		reportTime := time.Date(scheduledLocal.Year(), scheduledLocal.Month(), scheduledLocal.Day(), 0, 0, 0, 0, s.location)
		dailyTime, err := s.reportTime(reportTime)
		if err != nil {
			return nil, err
		}
		if dailyTime.After(localNow) {
			continue
		}

		reportDay := s.resolveReportDay(dailyTime)
		dayKey := reportDay.In(s.location).Format("2006-01-02")
		state, err := s.loadReportState(ctx, dayKey)
		if err != nil {
			return nil, err
		}
		if state.OverallSuccess {
			continue
		}
		if !state.LastAttemptAt.IsZero() && now.UTC().Sub(state.LastAttemptAt) < s.cfg.Reports.RetryInterval {
			continue
		}
		return &reportCandidate{
			ReportDay:  reportDay,
			ReportTime: dailyTime,
			DayKey:     dayKey,
			DayLabel:   reportDay.In(s.location).Format(s.cfg.Reports.Filename.DateFormat),
			State:      state,
		}, nil
	}
	return nil, nil
}

func (s *Service) deliverReportCandidate(ctx context.Context, now time.Time, candidate reportCandidate) error {
	state := candidate.State
	state.AttemptCount++
	state.LastAttemptAt = now.UTC()
	state.UpdatedAt = now.UTC()

	if state.AttemptCount > 1 && s.logger != nil {
		s.logger.Info("daily_report_backfill_started",
			"event", "daily_report_backfill_started",
			"day_key", candidate.DayKey,
			"attempt_count", state.AttemptCount,
			"retry_interval", s.cfg.Reports.RetryInterval,
		)
	}

	htmlReport, csvReport, err := s.GenerateDaily(ctx, candidate.ReportDay)
	if err != nil {
		state.LastError = err.Error()
		_ = s.saveReportState(ctx, state)
		return err
	}
	if s.logger != nil {
		s.logger.Info("daily_report_generated",
			"event", "daily_report_generated",
			"day_key", candidate.DayKey,
			"title", s.cfg.Reports.Title,
			"period_mode", s.cfg.Reports.PeriodMode,
			"timezone_mode", s.cfg.Reports.TimeZoneMode,
			"resolved_timezone", s.locationName,
			"attempt_count", state.AttemptCount,
		)
	}

	if !s.cfg.Reports.Output.TelegramEnabled && !s.cfg.Reports.Output.FileEnabled {
		if s.logger != nil {
			s.logger.Warn("daily_report_no_output_sink",
				"event", "daily_report_no_output_sink",
				"day_key", candidate.DayKey,
			)
		}
		state.OverallSuccess = true
		state.LastError = ""
		return s.saveReportState(ctx, state)
	}

	caption := s.reportCaption(candidate.DayKey)
	var errorsList []string

	if s.cfg.Reports.Output.FileEnabled {
		if s.cfg.Reports.IncludeHTML && !state.FileHTMLWritten {
			path, writeErr := s.writeReportFile(candidate.DayLabel, "html", htmlReport)
			if writeErr != nil {
				errorsList = append(errorsList, writeErr.Error())
				if s.logger != nil {
					s.logger.Warn("daily_report_write_error", "event", "daily_report_write_error", "day_key", candidate.DayKey, "format", "html", "output_dir", s.cfg.Reports.Output.OutputDir, "error", writeErr)
				}
			} else {
				state.FileHTMLWritten = true
				if saveErr := s.saveReportState(ctx, state); saveErr != nil {
					return saveErr
				}
				if s.logger != nil {
					s.logger.Info("daily_report_written", "event", "daily_report_written", "day_key", candidate.DayKey, "format", "html", "path", path)
				}
			}
		}
		if s.cfg.Reports.IncludeCSV && !state.FileCSVWritten {
			path, writeErr := s.writeReportFile(candidate.DayLabel, "csv", csvReport)
			if writeErr != nil {
				errorsList = append(errorsList, writeErr.Error())
				if s.logger != nil {
					s.logger.Warn("daily_report_write_error", "event", "daily_report_write_error", "day_key", candidate.DayKey, "format", "csv", "output_dir", s.cfg.Reports.Output.OutputDir, "error", writeErr)
				}
			} else {
				state.FileCSVWritten = true
				if saveErr := s.saveReportState(ctx, state); saveErr != nil {
					return saveErr
				}
				if s.logger != nil {
					s.logger.Info("daily_report_written", "event", "daily_report_written", "day_key", candidate.DayKey, "format", "csv", "path", path)
				}
			}
		}
	}

	if s.cfg.Reports.Output.TelegramEnabled && s.sender != nil {
		if s.cfg.Reports.IncludeHTML && !state.TelegramHTMLSent {
			if sendErr := s.sendReportDocument(ctx, candidate.DayLabel, "html", "text/html", htmlReport, caption); sendErr != nil {
				errorsList = append(errorsList, sendErr.Error())
				if s.logger != nil {
					s.logger.Warn("daily_report_send_error", "event", "daily_report_send_error", "day_key", candidate.DayKey, "format", "html", "error", sendErr)
				}
			} else {
				state.TelegramHTMLSent = true
				if saveErr := s.saveReportState(ctx, state); saveErr != nil {
					return saveErr
				}
			}
		}
		if s.cfg.Reports.IncludeCSV && !state.TelegramCSVSent {
			if sendErr := s.sendReportDocument(ctx, candidate.DayLabel, "csv", "text/csv; charset=utf-8", csvReport, caption); sendErr != nil {
				errorsList = append(errorsList, sendErr.Error())
				if s.logger != nil {
					s.logger.Warn("daily_report_send_error", "event", "daily_report_send_error", "day_key", candidate.DayKey, "format", "csv", "error", sendErr)
				}
			} else {
				state.TelegramCSVSent = true
				if saveErr := s.saveReportState(ctx, state); saveErr != nil {
					return saveErr
				}
			}
		}
	}

	state.TelegramSuccess = s.telegramReportSatisfied(state)
	state.FileSuccess = s.fileReportSatisfied(state)
	state.OverallSuccess = state.TelegramSuccess && state.FileSuccess
	state.UpdatedAt = time.Now().UTC()
	if len(errorsList) > 0 {
		state.LastError = strings.Join(errorsList, " | ")
	} else {
		state.LastError = ""
	}

	if err := s.saveReportState(ctx, state); err != nil {
		if s.metrics != nil {
			s.metrics.ReportRuns.Inc(metrics.Labels{"status": "state_error"})
		}
		return err
	}

	status := "partial"
	switch {
	case state.OverallSuccess:
		status = "sent"
	case state.TelegramSuccess || state.FileSuccess:
		status = "partial"
	default:
		status = "send_error"
	}
	if s.metrics != nil {
		s.metrics.ReportRuns.Inc(metrics.Labels{"status": status})
	}
	if state.OverallSuccess {
		if s.logger != nil {
			s.logger.Info("daily_report_completed",
				"event", "daily_report_completed",
				"day_key", candidate.DayKey,
				"telegram_success", state.TelegramSuccess,
				"file_success", state.FileSuccess,
				"attempt_count", state.AttemptCount,
			)
		}
		return nil
	}
	return fmt.Errorf("daily report %s not fully delivered yet: %s", candidate.DayKey, state.LastError)
}

func (s *Service) isReportSent(ctx context.Context, dayKey string) (bool, error) {
	state, err := s.loadReportState(ctx, dayKey)
	if err != nil {
		return false, err
	}
	return state.OverallSuccess, nil
}

func (s *Service) markReportSent(ctx context.Context, dayKey string) error {
	state, err := s.loadReportState(ctx, dayKey)
	if err != nil {
		return err
	}
	state.TelegramSuccess = true
	state.FileSuccess = true
	state.OverallSuccess = true
	state.UpdatedAt = time.Now().UTC()
	state.LastError = ""
	return s.saveReportState(ctx, state)
}

func (s *Service) reportStateKey(dayKey string) string {
	return "report_state:" + dayKey
}

func (s *Service) defaultReportState(dayKey string) reportDeliveryState {
	return reportDeliveryState{
		ID:   s.reportStateKey(dayKey),
		Kind: "report_state",
		Day:  dayKey,
	}
}

func (s *Service) loadReportState(ctx context.Context, dayKey string) (reportDeliveryState, error) {
	defaultState := s.defaultReportState(dayKey)
	if !s.reportMongoAvailable() {
		return defaultState, errors.New("mongo unavailable for report state")
	}

	client := s.controller.Client()
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var state reportDeliveryState
	err := client.Database().Collection(s.collectionName).FindOne(child, bson.M{"_id": s.reportStateKey(dayKey)}).Decode(&state)
	if err == nil {
		return state, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return defaultState, nil
	}
	s.controller.HandleMongoError(err)
	return defaultState, err
}

func (s *Service) saveReportState(ctx context.Context, state reportDeliveryState) error {
	state.TelegramSuccess = s.telegramReportSatisfied(state)
	state.FileSuccess = s.fileReportSatisfied(state)
	state.OverallSuccess = state.TelegramSuccess && state.FileSuccess
	state.UpdatedAt = time.Now().UTC()

	if !s.reportMongoAvailable() {
		return errors.New("mongo unavailable for report state")
	}

	client := s.controller.Client()
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	update := bson.M{
		"$setOnInsert": bson.M{
			"_id":  state.ID,
			"kind": state.Kind,
			"day":  state.Day,
		},
		"$max": bson.M{
			"attempt_count":   state.AttemptCount,
			"last_attempt_at": state.LastAttemptAt,
			"updated_at":      state.UpdatedAt,
		},
	}

	setFields := bson.M{}
	if state.TelegramHTMLSent {
		setFields["telegram_html_sent"] = true
	}
	if state.TelegramCSVSent {
		setFields["telegram_csv_sent"] = true
	}
	if state.FileHTMLWritten {
		setFields["file_html_written"] = true
	}
	if state.FileCSVWritten {
		setFields["file_csv_written"] = true
	}
	if state.TelegramSuccess {
		setFields["telegram_success"] = true
	}
	if state.FileSuccess {
		setFields["file_success"] = true
	}
	if state.OverallSuccess {
		setFields["overall_success"] = true
		setFields["last_error"] = ""
	} else if strings.TrimSpace(state.LastError) != "" {
		setFields["last_error"] = state.LastError
	}
	if len(setFields) > 0 {
		update["$set"] = setFields
	}

	_, err := client.Database().Collection(s.collectionName).UpdateOne(
		child,
		bson.M{"_id": state.ID},
		update,
		options.Update().SetUpsert(true),
	)
	if err != nil {
		s.controller.HandleMongoError(err)
		return err
	}
	return nil
}

func (s *Service) telegramReportSatisfied(state reportDeliveryState) bool {
	if !s.cfg.Reports.Output.TelegramEnabled || s.sender == nil {
		return true
	}
	if s.cfg.Reports.IncludeHTML && !state.TelegramHTMLSent {
		return false
	}
	if s.cfg.Reports.IncludeCSV && !state.TelegramCSVSent {
		return false
	}
	return true
}

func (s *Service) fileReportSatisfied(state reportDeliveryState) bool {
	if !s.cfg.Reports.Output.FileEnabled {
		return true
	}
	if s.cfg.Reports.IncludeHTML && !state.FileHTMLWritten {
		return false
	}
	if s.cfg.Reports.IncludeCSV && !state.FileCSVWritten {
		return false
	}
	return true
}

func (s *Service) logSkipBeforeTimeOnce(now, reportTime time.Time) {
	if !now.In(s.location).Before(reportTime) {
		return
	}
	logKey := reportTime.Format(time.RFC3339)
	s.scheduleMu.Lock()
	if s.lastSkipLogKey == logKey {
		s.scheduleMu.Unlock()
		return
	}
	s.lastSkipLogKey = logKey
	s.scheduleMu.Unlock()

	if s.logger != nil {
		s.logger.Info("daily_report_waiting_for_schedule",
			"event", "daily_report_waiting_for_schedule",
			"title", s.cfg.Reports.Title,
			"next_report_time", reportTime.Format(time.RFC3339),
			"timezone_mode", s.cfg.Reports.TimeZoneMode,
			"resolved_timezone", s.locationName,
		)
	}
}

func (s *Service) logMongoUnavailableOnce() {
	logKey := time.Now().UTC().Format("2006-01-02T15:04")
	s.scheduleMu.Lock()
	if s.lastMongoWaitLogKey == logKey {
		s.scheduleMu.Unlock()
		return
	}
	s.lastMongoWaitLogKey = logKey
	s.scheduleMu.Unlock()

	if s.logger != nil {
		s.logger.Warn("daily_report_waiting_for_mongo",
			"event", "daily_report_waiting_for_mongo",
			"title", s.cfg.Reports.Title,
			"mode", s.controller.Mode(),
		)
	}
}

func (s *Service) reportCaption(dayKey string) string {
	title := strings.TrimSpace(s.cfg.Reports.Title)
	if title == "" {
		title = "gw-ipinfo-nginx daily report"
	}
	if prefix := strings.TrimSpace(s.cfg.Alerts.Telegram.TitlePrefix); prefix != "" {
		return prefix + " " + title + " " + dayKey
	}
	return title + " " + dayKey
}

func (s *Service) loadDay(ctx context.Context, dayKey string) ([]Summary, error) {
	if !s.reportMongoAvailable() {
		return nil, errors.New("mongo unavailable for report data")
	}

	client := s.controller.Client()
	summaries, err := s.loadDayFromMongo(ctx, client, dayKey)
	if err != nil {
		s.controller.HandleMongoError(err)
		return nil, err
	}
	return summaries, nil
}

func (s *Service) loadDayFromMongo(ctx context.Context, client *mongostore.Client, dayKey string) ([]Summary, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	cursor, err := client.Database().Collection(s.collectionName).Find(child, bson.M{"day": dayKey, "kind": "summary"})
	if err != nil {
		return nil, fmt.Errorf("find report summaries for %s: %w", dayKey, err)
	}
	defer cursor.Close(child)

	var summaries []Summary
	for cursor.Next(child) {
		var summary Summary
		if err := cursor.Decode(&summary); err != nil {
			return nil, err
		}
		if s.shouldIgnoreStoredSummary(summary) {
			continue
		}
		summaries = append(summaries, summary)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].AllowCount+summaries[i].DenyCount == summaries[j].AllowCount+summaries[j].DenyCount {
			return summaries[i].ClientIP < summaries[j].ClientIP
		}
		return summaries[i].AllowCount+summaries[i].DenyCount > summaries[j].AllowCount+summaries[j].DenyCount
	})
	return summaries, nil
}

func (s *Service) renderCSV(summaries []Summary) ([]byte, error) {
	return s.renderCSVHostPrimary(summaries)

	buf := &bytes.Buffer{}
	writer := csv.NewWriter(buf)
	rows := [][]string{{
		"client_ip",
		"allow_count",
		"deny_count",
		"allow_reasons",
		"deny_reasons",
		"country",
		"region",
		"city",
		"route_set_kind",
		"route_id",
		"v3_strategy_mode",
		"v3_selected_target_id",
		"v3_selected_target_host",
		"v4_runtime_mode",
		"v4_security_checks_enabled",
		"v4_enrichment_mode",
		"v4_probe_enabled",
		"source_host",
		"target_host",
		"backend_service",
		"backend_host",
		"user_agent_summary",
		"host",
		"path",
		"short_circuit_allow_count",
		"short_circuit_deny_count",
	}}
	for _, summary := range summaries {
		rows = append(rows, []string{
			summary.ClientIP,
			fmt.Sprintf("%d", summary.AllowCount),
			fmt.Sprintf("%d", summary.DenyCount),
			joinTopReasons(summary.AllowReasons),
			joinTopReasons(summary.DenyReasons),
			summary.CountryCode,
			summary.Region,
			summary.City,
			summary.RouteSetKind,
			summary.RouteID,
			summary.V3StrategyMode,
			summary.V3SelectedTargetID,
			summary.V3SelectedTargetHost,
			summary.V4RuntimeMode,
			fmt.Sprintf("%t", summary.V4SecurityChecksEnabled),
			summary.V4EnrichmentMode,
			fmt.Sprintf("%t", summary.V4ProbeEnabled),
			summary.SourceHost,
			summary.TargetHost,
			summary.BackendService,
			summary.BackendHost,
			summary.UserAgentSummary,
			summary.Host,
			summary.Path,
			fmt.Sprintf("%d", summary.ShortCircuitAllowCount),
			fmt.Sprintf("%d", summary.ShortCircuitDenyCount),
		})
	}
	if err := writer.WriteAll(rows); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Service) renderHTML(dayKey string, summaries []Summary) ([]byte, error) {
	return s.renderHTMLHostPrimary(dayKey, summaries)

	totalRequests := uint64(0)
	allowed := uint64(0)
	denied := uint64(0)
	shortCircuitAllow := uint64(0)
	shortCircuitDeny := uint64(0)

	topDeny := map[string]uint64{}
	topAllow := map[string]uint64{}
	topCountry := map[string]uint64{}
	topHost := map[string]uint64{}
	topUA := map[string]uint64{}

	for _, summary := range summaries {
		requests := summary.AllowCount + summary.DenyCount
		totalRequests += requests
		allowed += summary.AllowCount
		denied += summary.DenyCount
		shortCircuitAllow += summary.ShortCircuitAllowCount
		shortCircuitDeny += summary.ShortCircuitDenyCount

		for key, value := range summary.AllowReasons {
			topAllow[key] += value
		}
		for key, value := range summary.DenyReasons {
			topDeny[key] += value
		}

		countryKey := strings.TrimSpace(summary.CountryName)
		if countryKey == "" {
			countryKey = strings.TrimSpace(summary.CountryCode)
		}
		if countryKey == "" {
			countryKey = "(unknown)"
		}
		topCountry[countryKey] += requests

		hostKey := strings.TrimSpace(summary.Host)
		if hostKey == "" {
			hostKey = strings.TrimSpace(summary.SourceHost)
		}
		if hostKey == "" {
			hostKey = "(unknown)"
		}
		topHost[hostKey] += requests

		uaKey := strings.TrimSpace(summary.UserAgentSummary)
		if uaKey == "" {
			uaKey = "(unknown)"
		}
		topUA[uaKey] += requests
	}

	title := strings.TrimSpace(s.cfg.Reports.Title)
	if title == "" {
		title = "gw-ipinfo-nginx daily report"
	}

	topN := s.cfg.Reports.TopN
	if topN <= 0 {
		topN = 5
	}

	topDenyRows := topMap(topDeny, topN)
	topAllowRows := topMap(topAllow, topN)
	topCountryRows := topMap(topCountry, topN)
	topHostRows := topMap(topHost, topN)
	topUARows := topMap(topUA, topN)

	leadDeny := reportFirstAggregate(topDenyRows, "no deny reasons")
	leadCountry := reportFirstAggregate(topCountryRows, "no country data")
	leadHost := reportFirstAggregate(topHostRows, "no host data")

	shortCircuitTotal := shortCircuitAllow + shortCircuitDeny

	buf := &bytes.Buffer{}
	buf.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	buf.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	buf.WriteString(`<title>` + html.EscapeString(title) + `</title>`)
	buf.WriteString(`
<style>
:root{
	--bg:#f3f7fb;
	--panel:#ffffff;
	--panel-soft:#f8fbff;
	--text:#0f172a;
	--muted:#64748b;
	--line:#dbe5f0;
	--line-strong:#c7d5e5;
	--shadow:0 10px 30px rgba(15,23,42,.08);
	--blue:#2563eb;
	--blue-soft:#dbeafe;
	--green:#16a34a;
	--green-soft:#dcfce7;
	--red:#ef4444;
	--red-soft:#fee2e2;
	--amber:#d97706;
	--amber-soft:#fef3c7;
	--slate:#334155;
	--slate-soft:#e2e8f0;
}
*{box-sizing:border-box}
body{
	margin:0;
	padding:24px;
	background:
		radial-gradient(circle at top left, rgba(37,99,235,.08), transparent 28%),
		radial-gradient(circle at top right, rgba(22,163,74,.06), transparent 22%),
		var(--bg);
	color:var(--text);
	font-family:Inter, Arial, Helvetica, sans-serif;
}
.wrapper{
	max-width:1500px;
	margin:0 auto;
}
.hero{
	background:linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
	color:#fff;
	border-radius:24px;
	padding:28px 28px 24px;
	box-shadow:var(--shadow);
}
.hero-eyebrow{
	font-size:12px;
	font-weight:700;
	letter-spacing:.12em;
	text-transform:uppercase;
	opacity:.72;
	margin-bottom:10px;
}
.hero h1{
	margin:0;
	font-size:30px;
	line-height:1.15;
}
.hero-meta{
	margin-top:12px;
	font-size:14px;
	line-height:1.6;
	opacity:.86;
}
.metric-grid{
	display:grid;
	grid-template-columns:repeat(6,minmax(0,1fr));
	gap:16px;
	margin-top:18px;
}
.metric-card{
	background:rgba(255,255,255,.10);
	backdrop-filter:blur(6px);
	border:1px solid rgba(255,255,255,.14);
	border-radius:20px;
	padding:18px 18px 16px;
	min-height:116px;
}
.metric-card .label{
	font-size:12px;
	font-weight:700;
	text-transform:uppercase;
	letter-spacing:.08em;
	opacity:.75;
}
.metric-card .value{
	margin-top:10px;
	font-size:32px;
	font-weight:800;
	line-height:1;
}
.metric-card .sub{
	margin-top:10px;
	font-size:13px;
	line-height:1.45;
	opacity:.82;
}
.section{
	margin-top:22px;
}
.section-title{
	display:flex;
	align-items:flex-end;
	justify-content:space-between;
	gap:12px;
	margin:0 0 12px;
}
.section-title h2{
	margin:0;
	font-size:20px;
}
.section-title p{
	margin:0;
	font-size:13px;
	color:var(--muted);
}
.insight-grid{
	display:grid;
	grid-template-columns:repeat(3,minmax(0,1fr));
	gap:16px;
}
.insight-card,
.panel{
	background:var(--panel);
	border:1px solid var(--line);
	border-radius:22px;
	box-shadow:var(--shadow);
}
.insight-card{
	padding:18px;
}
.insight-label{
	font-size:12px;
	font-weight:700;
	letter-spacing:.08em;
	text-transform:uppercase;
	color:var(--muted);
}
.insight-value{
	margin-top:10px;
	font-size:20px;
	font-weight:800;
	line-height:1.35;
}
.insight-sub{
	margin-top:8px;
	font-size:13px;
	color:var(--muted);
}
.chart-grid{
	display:grid;
	grid-template-columns:1.12fr 1.88fr;
	gap:16px;
}
.chart-grid-right{
	display:grid;
	grid-template-columns:repeat(2,minmax(0,1fr));
	gap:16px;
}
.panel{
	padding:18px;
}
.panel h3{
	margin:0;
	font-size:17px;
}
.panel-head{
	display:flex;
	align-items:flex-start;
	justify-content:space-between;
	gap:12px;
	margin-bottom:16px;
}
.panel-sub{
	font-size:13px;
	color:var(--muted);
	margin-top:6px;
}
.donut-shell{
	display:flex;
	align-items:center;
	justify-content:center;
	gap:20px;
	min-height:340px;
}
.donut-chart{
	width:220px;
	height:220px;
	border-radius:50%;
	position:relative;
	flex:0 0 auto;
	box-shadow:inset 0 0 0 1px rgba(15,23,42,.06);
}
.donut-hole{
	position:absolute;
	inset:28px;
	background:var(--panel);
	border-radius:50%;
	display:flex;
	flex-direction:column;
	align-items:center;
	justify-content:center;
	text-align:center;
	box-shadow:0 0 0 1px var(--line) inset;
	padding:18px;
}
.donut-hole .big{
	font-size:28px;
	font-weight:800;
	line-height:1;
}
.donut-hole .small{
	margin-top:8px;
	font-size:12px;
	color:var(--muted);
	line-height:1.45;
}
.legend{
	display:grid;
	gap:12px;
	min-width:220px;
}
.legend-item{
	display:flex;
	align-items:center;
	justify-content:space-between;
	gap:12px;
	padding:12px 14px;
	border:1px solid var(--line);
	border-radius:16px;
	background:var(--panel-soft);
}
.legend-left{
	display:flex;
	align-items:center;
	gap:10px;
	font-size:14px;
	font-weight:700;
}
.legend-dot{
	width:12px;
	height:12px;
	border-radius:50%;
}
.legend-dot.allow{background:var(--green)}
.legend-dot.deny{background:var(--red)}
.legend-right{
	text-align:right;
	font-size:13px;
	color:var(--muted);
	line-height:1.35;
}
.bar-list{
	display:grid;
	gap:14px;
}
.bar-row{
	display:grid;
	gap:8px;
}
.bar-meta{
	display:flex;
	align-items:center;
	justify-content:space-between;
	gap:12px;
	font-size:13px;
}
.bar-label{
	font-weight:700;
	color:var(--slate);
	max-width:68%;
	white-space:nowrap;
	overflow:hidden;
	text-overflow:ellipsis;
}
.bar-value{
	color:var(--muted);
	white-space:nowrap;
}
.bar-track{
	height:12px;
	border-radius:999px;
	background:#edf2f7;
	overflow:hidden;
}
.bar-fill{
	height:100%;
	border-radius:999px;
}
.bar-fill.danger{background:linear-gradient(90deg, #f97316 0%, #ef4444 100%)}
.bar-fill.success{background:linear-gradient(90deg, #22c55e 0%, #16a34a 100%)}
.bar-fill.info{background:linear-gradient(90deg, #38bdf8 0%, #2563eb 100%)}
.bar-fill.neutral{background:linear-gradient(90deg, #94a3b8 0%, #475569 100%)}
.table-panel{
	padding:0;
	overflow:hidden;
}
.table-panel .section-title{
	padding:18px 18px 0;
}
.table-wrap{
	overflow:auto;
	padding:0 18px 18px;
}
table{
	width:100%;
	border-collapse:separate;
	border-spacing:0;
	min-width:1200px;
}
thead th{
	position:sticky;
	top:0;
	z-index:1;
	background:#eff6ff;
	color:#1e3a8a;
	font-size:12px;
	text-transform:uppercase;
	letter-spacing:.06em;
	border-bottom:1px solid var(--line-strong);
	padding:12px 12px;
	text-align:left;
}
tbody td{
	padding:12px;
	border-bottom:1px solid var(--line);
	vertical-align:top;
	font-size:13px;
}
tbody tr:nth-child(even){
	background:#fbfdff;
}
tbody tr:hover{
	background:#f6fbff;
}
.num{
	text-align:right;
	font-variant-numeric:tabular-nums;
	white-space:nowrap;
}
.ip{
	font-weight:800;
	color:#0f172a;
}
.stacked{
	display:grid;
	gap:4px;
}
.stacked .primary{
	font-weight:700;
	color:#0f172a;
	word-break:break-word;
}
.stacked .secondary{
	font-size:12px;
	color:var(--muted);
	word-break:break-word;
}
.badge{
	display:inline-flex;
	align-items:center;
	border-radius:999px;
	padding:5px 10px;
	font-size:12px;
	font-weight:800;
	white-space:nowrap;
}
.badge.success{
	background:var(--green-soft);
	color:#166534;
}
.badge.danger{
	background:var(--red-soft);
	color:#991b1b;
}
.badge.info{
	background:var(--blue-soft);
	color:#1d4ed8;
}
.badge.warning{
	background:var(--amber-soft);
	color:#92400e;
}
.badge.neutral{
	background:var(--slate-soft);
	color:#334155;
}
.empty{
	padding:22px 0 8px;
	color:var(--muted);
	font-size:13px;
}
.footer-note{
	margin-top:14px;
	font-size:12px;
	color:var(--muted);
}
@media (max-width: 1280px){
	.metric-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
	.chart-grid{grid-template-columns:1fr}
	.chart-grid-right{grid-template-columns:repeat(2,minmax(0,1fr))}
	.insight-grid{grid-template-columns:1fr}
}
@media (max-width: 780px){
	body{padding:14px}
	.hero{padding:20px}
	.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
	.chart-grid-right{grid-template-columns:1fr}
	.donut-shell{flex-direction:column}
	.legend{width:100%}
}
</style></head><body><div class="wrapper">`)

	buf.WriteString(`<section class="hero">`)
	buf.WriteString(`<div class="hero-eyebrow">gateway daily report</div>`)
	buf.WriteString(`<h1>` + html.EscapeString(title) + ` · ` + html.EscapeString(dayKey) + `</h1>`)
	buf.WriteString(`<div class="hero-meta">Deduplicated by real client IP · Timezone: ` + html.EscapeString(reportSafeText(s.locationName)) + ` · TopN: ` + fmt.Sprintf("%d", topN) + ` · Generated by gw-ipinfo-nginx reporting service</div>`)

	buf.WriteString(`<div class="metric-grid">`)
	buf.WriteString(reportMetricCard("total requests", fmt.Sprintf("%d", totalRequests), "Total allow + deny request volume", "neutral"))
	buf.WriteString(reportMetricCard("unique IPs", fmt.Sprintf("%d", len(summaries)), "Unique real client IPs after daily dedup", "info"))
	buf.WriteString(reportMetricCard("allowed", fmt.Sprintf("%d", allowed), reportPercentString(allowed, totalRequests)+" of total traffic", "success"))
	buf.WriteString(reportMetricCard("denied", fmt.Sprintf("%d", denied), reportPercentString(denied, totalRequests)+" of total traffic", "danger"))
	buf.WriteString(reportMetricCard("allow rate", reportPercentString(allowed, totalRequests), "Traffic accepted by policy engine", "success"))
	buf.WriteString(reportMetricCard("short-circuit hits", fmt.Sprintf("%d", shortCircuitTotal), reportPercentString(shortCircuitTotal, totalRequests)+" of total requests", "warning"))
	buf.WriteString(`</div></section>`)

	buf.WriteString(`<section class="section">`)
	buf.WriteString(`<div class="section-title"><h2>Executive highlights</h2><p>The highest-impact signals from the daily aggregate.</p></div>`)
	buf.WriteString(`<div class="insight-grid">`)
	buf.WriteString(reportInsightCard("Top deny reason", leadDeny, denied, "danger"))
	buf.WriteString(reportInsightCard("Top country", leadCountry, totalRequests, "info"))
	buf.WriteString(reportInsightCard("Top host", leadHost, totalRequests, "neutral"))
	buf.WriteString(`</div></section>`)

	buf.WriteString(`<section class="section">`)
	buf.WriteString(`<div class="section-title"><h2>Visual overview</h2><p>Use the donut to read health quickly, then use the bar charts to locate concentration.</p></div>`)
	buf.WriteString(`<div class="chart-grid">`)
	buf.WriteString(reportDonutPanel(allowed, denied))
	buf.WriteString(`<div class="chart-grid-right">`)
	buf.WriteString(reportBarPanel("Top deny reasons", "Most frequent causes of blocked traffic", topDenyRows, denied, "danger"))
	buf.WriteString(reportBarPanel("Top allow reasons", "Most frequent pass reasons", topAllowRows, allowed, "success"))
	buf.WriteString(reportBarPanel("Top countries", "Geographic request concentration", topCountryRows, totalRequests, "info"))
	buf.WriteString(reportBarPanel("Top hosts / domains", "Most active requested hostnames", topHostRows, totalRequests, "neutral"))
	buf.WriteString(`</div></div></section>`)

	buf.WriteString(`<section class="section">`)
	buf.WriteString(`<div class="section-title"><h2>Client profile distribution</h2><p>User agent concentration by deduplicated traffic volume.</p></div>`)
	buf.WriteString(reportBarPanel("Top user agents", "Condensed UA fingerprints seen in this period", topUARows, totalRequests, "info"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section panel table-panel">`)
	buf.WriteString(`<div class="section-title"><div><h2>Deduplicated IP summary</h2><p>Grouped by real client IP. Key routing, decision, and traffic context are preserved in a denser layout.</p></div></div>`)
	buf.WriteString(`<div class="table-wrap"><table><thead><tr>`)
	buf.WriteString(`<th>IP</th>`)
	buf.WriteString(`<th class="num">Requests</th>`)
	buf.WriteString(`<th>Allow</th>`)
	buf.WriteString(`<th>Deny</th>`)
	buf.WriteString(`<th>Top allow reason</th>`)
	buf.WriteString(`<th>Top deny reason</th>`)
	buf.WriteString(`<th>Location</th>`)
	buf.WriteString(`<th>Host / Path</th>`)
	buf.WriteString(`<th>Route / Target</th>`)
	buf.WriteString(`<th>Short-circuit</th>`)
	buf.WriteString(`<th>User agent</th>`)
	buf.WriteString(`</tr></thead><tbody>`)

	for _, summary := range summaries {
		total := summary.AllowCount + summary.DenyCount

		locationPrimary := reportFirstNonEmpty(strings.TrimSpace(summary.CountryName), strings.TrimSpace(summary.CountryCode), "(unknown)")
		locationSecondary := reportJoinParts(
			strings.TrimSpace(summary.Region),
			strings.TrimSpace(summary.City),
		)

		hostPrimary := reportFirstNonEmpty(strings.TrimSpace(summary.Host), strings.TrimSpace(summary.SourceHost), "(unknown)")
		hostSecondary := reportFirstNonEmpty(strings.TrimSpace(summary.Path), strings.TrimSpace(summary.RequestURL), "—")

		routePrimary := reportFirstNonEmpty(strings.TrimSpace(summary.RouteID), strings.TrimSpace(summary.RouteSetKind), "—")
		routeSecondary := reportJoinParts(
			reportFirstNonEmpty(strings.TrimSpace(summary.V3SelectedTargetHost), strings.TrimSpace(summary.TargetHost), strings.TrimSpace(summary.BackendHost), ""),
			reportFirstNonEmpty(strings.TrimSpace(summary.V3SelectedTargetID), strings.TrimSpace(summary.V4RuntimeMode), strings.TrimSpace(summary.V3StrategyMode), ""),
		)

		shortCircuitLabel := "none"
		shortCircuitTone := "neutral"
		if summary.ShortCircuitAllowCount > 0 || summary.ShortCircuitDenyCount > 0 {
			shortCircuitLabel = fmt.Sprintf("allow %d / deny %d", summary.ShortCircuitAllowCount, summary.ShortCircuitDenyCount)
			if summary.ShortCircuitDenyCount > 0 {
				shortCircuitTone = "danger"
			} else {
				shortCircuitTone = "warning"
			}
		}

		buf.WriteString(`<tr>`)
		buf.WriteString(reportTDClass(summary.ClientIP, "ip"))
		buf.WriteString(reportTDClass(fmt.Sprintf("%d", total), "num"))
		buf.WriteString(reportTDHTML("", reportBadge(fmt.Sprintf("%d", summary.AllowCount), "success")))
		buf.WriteString(reportTDHTML("", reportBadge(fmt.Sprintf("%d", summary.DenyCount), "danger")))
		buf.WriteString(reportTD(joinTopReasons(summary.AllowReasons)))
		buf.WriteString(reportTD(joinTopReasons(summary.DenyReasons)))
		buf.WriteString(reportTDHTML("", reportStackedValue(locationPrimary, locationSecondary)))
		buf.WriteString(reportTDHTML("", reportStackedValue(hostPrimary, hostSecondary)))
		buf.WriteString(reportTDHTML("", reportStackedValue(routePrimary, routeSecondary)))
		buf.WriteString(reportTDHTML("", reportBadge(shortCircuitLabel, shortCircuitTone)))
		buf.WriteString(reportTD(reportSafeText(summary.UserAgentSummary)))
		buf.WriteString(`</tr>`)
	}

	buf.WriteString(`</tbody></table></div>`)
	buf.WriteString(`<div class="footer-note" style="padding:0 18px 18px;">Tip: the summary table stays detailed, while the sections above are optimized for quick scanning and management-level review.</div>`)
	buf.WriteString(`</section>`)

	buf.WriteString(`</div></body></html>`)
	return buf.Bytes(), nil
}

type hostAggregate struct {
	Host             string
	TotalRequests    uint64
	UniqueClients    uint64
	AllowCount       uint64
	DenyCount        uint64
	RedirectCount    uint64
	UniqueAllowedIPs uint64
	DenyReasons      map[string]uint64
	RouteSetCounts   map[string]uint64
	RouteIDCounts    map[string]uint64
	ClientIPs        map[string]uint64
	PathCounts       map[string]uint64
	RequestURLCounts map[string]uint64
}

func (s *Service) renderCSVHostPrimary(summaries []Summary) ([]byte, error) {
	sort.Slice(summaries, func(i, j int) bool {
		leftHost := reportFirstNonEmpty(normalizeReportHost(summaries[i].Host), normalizeReportHost(summaries[i].SourceHost), "(unknown)")
		rightHost := reportFirstNonEmpty(normalizeReportHost(summaries[j].Host), normalizeReportHost(summaries[j].SourceHost), "(unknown)")
		if leftHost != rightHost {
			return leftHost < rightHost
		}
		leftTotal := summaries[i].AllowCount + summaries[i].DenyCount
		rightTotal := summaries[j].AllowCount + summaries[j].DenyCount
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		return summaries[i].ClientIP < summaries[j].ClientIP
	})

	buf := &bytes.Buffer{}
	writer := csv.NewWriter(buf)
	rows := [][]string{{
		"host",
		"client_ip",
		"total_requests",
		"allow_count",
		"deny_count",
		"redirect_count",
		"redirect_triggered",
		"allow_reasons",
		"deny_reasons",
		"route_set_kinds",
		"route_ids",
		"paths",
		"request_urls",
		"country",
		"region",
		"city",
		"user_agents",
		"accept_languages",
		"v3_strategy_mode",
		"v3_selected_target_id",
		"v3_selected_target_host",
		"v4_runtime_mode",
		"v4_route_source",
		"v4_security_checks_enabled",
		"v4_enrichment_mode",
		"v4_probe_enabled",
		"backend_service",
		"backend_host",
		"source_host",
		"target_host",
		"short_circuit_allow_count",
		"short_circuit_deny_count",
	}}
	for _, summary := range summaries {
		host := reportFirstNonEmpty(normalizeReportHost(summary.Host), normalizeReportHost(summary.SourceHost), "(unknown)")
		totalRequests := summary.AllowCount + summary.DenyCount
		rows = append(rows, []string{
			host,
			summary.ClientIP,
			fmt.Sprintf("%d", totalRequests),
			fmt.Sprintf("%d", summary.AllowCount),
			fmt.Sprintf("%d", summary.DenyCount),
			fmt.Sprintf("%d", summary.RedirectCount),
			fmt.Sprintf("%t", summary.RedirectCount > 0),
			joinAllCounts(summary.AllowReasons),
			joinAllCounts(summary.DenyReasons),
			joinAllCounts(summary.RouteSetCounts),
			joinAllCounts(summary.RouteIDCounts),
			joinAllCounts(summary.PathCounts),
			joinAllCounts(summary.RequestURLCounts),
			reportLocationValue(summary.CountryCode, summary.CountryName),
			reportSafeText(summary.Region),
			reportSafeText(summary.City),
			joinAllCounts(summary.UserAgentCounts),
			joinAllCounts(summary.AcceptLanguageCounts),
			summary.V3StrategyMode,
			summary.V3SelectedTargetID,
			summary.V3SelectedTargetHost,
			summary.V4RuntimeMode,
			summary.V4RouteSource,
			fmt.Sprintf("%t", summary.V4SecurityChecksEnabled),
			summary.V4EnrichmentMode,
			fmt.Sprintf("%t", summary.V4ProbeEnabled),
			summary.BackendService,
			summary.BackendHost,
			summary.SourceHost,
			summary.TargetHost,
			fmt.Sprintf("%d", summary.ShortCircuitAllowCount),
			fmt.Sprintf("%d", summary.ShortCircuitDenyCount),
		})
	}
	if err := writer.WriteAll(rows); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Service) renderHTMLHostPrimaryLegacy(dayKey string, summaries []Summary) ([]byte, error) {
	title := strings.TrimSpace(s.cfg.Reports.Title)
	if title == "" {
		title = "gw-ipinfo-nginx daily report"
	}

	totalRequests := uint64(0)
	totalAllows := uint64(0)
	totalDenies := uint64(0)
	totalRedirects := uint64(0)
	shortCircuitTotal := uint64(0)
	hostStats := map[string]hostAggregate{}
	uaCounts := map[string]uint64{}
	langCounts := map[string]uint64{}
	countryCounts := map[string]uint64{}
	regionCounts := map[string]uint64{}
	cityCounts := map[string]uint64{}
	denyReasonCounts := map[string]uint64{}
	allowReasonCounts := map[string]uint64{}
	routeSetCounts := map[string]uint64{}
	routeIDCounts := map[string]uint64{}

	for _, summary := range summaries {
		host := reportFirstNonEmpty(normalizeReportHost(summary.Host), normalizeReportHost(summary.SourceHost), "(unknown)")
		total := summary.AllowCount + summary.DenyCount
		totalRequests += total
		totalAllows += summary.AllowCount
		totalDenies += summary.DenyCount
		totalRedirects += summary.RedirectCount
		shortCircuitTotal += summary.ShortCircuitAllowCount + summary.ShortCircuitDenyCount
		mergeCountMaps(uaCounts, summary.UserAgentCounts)
		mergeCountMaps(langCounts, summary.AcceptLanguageCounts)
		mergeCountMaps(countryCounts, summary.CountryCounts)
		mergeCountMaps(regionCounts, summary.RegionCounts)
		mergeCountMaps(cityCounts, summary.CityCounts)
		mergeCountMaps(denyReasonCounts, summary.DenyReasons)
		mergeCountMaps(allowReasonCounts, summary.AllowReasons)
		mergeCountMaps(routeSetCounts, summary.RouteSetCounts)
		mergeCountMaps(routeIDCounts, summary.RouteIDCounts)

		agg := hostStats[host]
		agg.Host = host
		agg.TotalRequests += total
		agg.UniqueClients++
		agg.AllowCount += summary.AllowCount
		agg.DenyCount += summary.DenyCount
		agg.RedirectCount += summary.RedirectCount
		if summary.AllowCount > 0 {
			agg.UniqueAllowedIPs++
		}
		if agg.DenyReasons == nil {
			agg.DenyReasons = map[string]uint64{}
		}
		if agg.RouteSetCounts == nil {
			agg.RouteSetCounts = map[string]uint64{}
		}
		if agg.RouteIDCounts == nil {
			agg.RouteIDCounts = map[string]uint64{}
		}
		if agg.ClientIPs == nil {
			agg.ClientIPs = map[string]uint64{}
		}
		if agg.PathCounts == nil {
			agg.PathCounts = map[string]uint64{}
		}
		if agg.RequestURLCounts == nil {
			agg.RequestURLCounts = map[string]uint64{}
		}
		mergeCountMaps(agg.DenyReasons, summary.DenyReasons)
		mergeCountMaps(agg.RouteSetCounts, summary.RouteSetCounts)
		mergeCountMaps(agg.RouteIDCounts, summary.RouteIDCounts)
		mergeCountMaps(agg.PathCounts, summary.PathCounts)
		mergeCountMaps(agg.RequestURLCounts, summary.RequestURLCounts)
		agg.ClientIPs[summary.ClientIP] = total
		hostStats[host] = agg
	}

	buf := &bytes.Buffer{}
	buf.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">`)
	buf.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	buf.WriteString(`<title>` + html.EscapeString(title) + `</title>`)
	buf.WriteString(`
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f5f7fb;color:#111827;margin:0;padding:24px}
.wrap{max-width:1680px;margin:0 auto}
.hero{background:#111827;color:#fff;border-radius:18px;padding:24px}
.hero h1{margin:0 0 8px 0;font-size:30px}
.hero p{margin:0;font-size:14px;color:#d1d5db}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}
.metric{background:#1f2937;border-radius:14px;padding:14px}
.metric .k{font-size:12px;color:#9ca3af;text-transform:uppercase}
.metric .v{margin-top:8px;font-size:28px;font-weight:700}
.metric .s{margin-top:8px;font-size:12px;color:#cbd5e1}
.section{margin-top:22px;background:#fff;border:1px solid #dbe5f0;border-radius:18px;padding:18px}
.section h2{margin:0 0 6px 0;font-size:20px}
.section p{margin:0 0 14px 0;font-size:13px;color:#64748b}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse;min-width:1080px}
th,td{padding:10px 12px;border-bottom:1px solid #e5e7eb;vertical-align:top;text-align:left;font-size:13px}
th{background:#eff6ff;color:#1d4ed8;position:sticky;top:0}
.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.muted{color:#64748b}
@media (max-width:1100px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style></head><body><div class="wrap">`)

	buf.WriteString(`<section class="hero">`)
	buf.WriteString(`<h1>` + html.EscapeString(title) + ` · ` + html.EscapeString(dayKey) + `</h1>`)
	buf.WriteString(`<p>按 host 为主键、按真实客户端 IP 去重汇总。健康探测请求已忽略，CSV 作为该统计视图的明细补充。</p>`)
	buf.WriteString(`<div class="metrics">`)
	buf.WriteString(reportMetricCard("总 Host 数", fmt.Sprintf("%d", len(hostStats)), "参与统计的 host 域名数量", "neutral"))
	buf.WriteString(reportMetricCard("总请求数", fmt.Sprintf("%d", totalRequests), "所有 host 的 allow + deny 总量", "neutral"))
	buf.WriteString(reportMetricCard("总放行数", fmt.Sprintf("%d", totalAllows), reportPercentString(totalAllows, totalRequests)+" 放行率", "success"))
	buf.WriteString(reportMetricCard("总拦截数", fmt.Sprintf("%d", totalDenies), reportPercentString(totalDenies, totalRequests)+" 拦截率", "danger"))
	buf.WriteString(reportMetricCard("重定向触发数", fmt.Sprintf("%d", totalRedirects), "触发 v1/v2/v3/v4 或 deny redirect 的请求数", "warning"))
	buf.WriteString(reportMetricCard("短路命中数", fmt.Sprintf("%d", shortCircuitTotal), reportPercentString(shortCircuitTotal, totalRequests)+" 的总请求占比", "warning"))
	buf.WriteString(`</div></section>`)

	buf.WriteString(`<section class="section"><h2>Host 维度汇总</h2><p>按 host 展示总请求数、去重客户端 IP 数、放行/拦截数、拦截原因和路由策略。</p>`)
	buf.WriteString(reportHostSummaryTable(hostStats))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>UA 统计分析</h2><p>完整展示全部 User-Agent 聚合结果，不做 TopN 截断。</p>`)
	buf.WriteString(reportCountTable("User-Agent", uaCounts, "UA", "请求数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>语言统计分析</h2><p>完整展示全部 Accept-Language 聚合结果。</p>`)
	buf.WriteString(reportCountTable("Accept-Language", langCounts, "语言", "请求数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>地区统计分析</h2><p>完整展示国家、地区、城市聚合结果。</p>`)
	buf.WriteString(reportCountTable("Country", countryCounts, "国家", "请求数"))
	buf.WriteString(reportCountTable("Region", regionCounts, "地区", "请求数"))
	buf.WriteString(reportCountTable("City", cityCounts, "城市", "请求数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>拦截分析</h2><p>完整展示拦截原因与放行原因。</p>`)
	buf.WriteString(reportCountTable("Deny reason", denyReasonCounts, "拦截原因", "次数"))
	buf.WriteString(reportCountTable("Allow reason", allowReasonCounts, "放行原因", "次数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>路由策略分析</h2><p>完整展示 route_set_kind 与 route_id 的聚合结果。</p>`)
	buf.WriteString(reportCountTable("Route set", routeSetCounts, "路由策略", "次数"))
	buf.WriteString(reportCountTable("Route ID", routeIDCounts, "规则 ID", "次数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`</div></body></html>`)
	return buf.Bytes(), nil
}

func reportPrimaryHost(event Event) string {
	return reportFirstNonEmpty(normalizeReportHost(event.Host), normalizeReportHost(event.SourceHost), "(unknown)")
}

func normalizeReportHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	value = strings.TrimSuffix(value, ".")
	if host, port, err := net.SplitHostPort(value); err == nil && host != "" && port != "" {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	}
	if strings.Count(value, ":") == 1 {
		if idx := strings.LastIndex(value, ":"); idx > 0 {
			return strings.TrimSuffix(value[:idx], ".")
		}
	}
	return value
}

func (s *Service) shouldIgnoreStoredSummary(summary Summary) bool {
	total := summary.AllowCount + summary.DenyCount
	if total == 0 {
		return false
	}

	if len(summary.UserAgentCounts) > 0 {
		ignoredCount := uint64(0)
		for userAgent, count := range summary.UserAgentCounts {
			if isIgnoredReportUserAgent(userAgent, s.cfg.V4.ProbeDefaults.UserAgent) {
				ignoredCount += count
			}
		}
		if ignoredCount >= total {
			return true
		}
	}

	if len(summary.PathCounts) > 0 {
		ignoredCount := uint64(0)
		for pathValue, count := range summary.PathCounts {
			if isIgnoredReportPath(pathValue) {
				ignoredCount += count
			}
		}
		if ignoredCount >= total {
			return true
		}
	}

	return false
}

func isIgnoredReportUserAgent(userAgent, probeUserAgent string) bool {
	value := strings.ToLower(strings.TrimSpace(userAgent))
	if value == "" {
		return false
	}
	probeUserAgent = strings.ToLower(strings.TrimSpace(probeUserAgent))
	if probeUserAgent != "" && strings.Contains(value, probeUserAgent) {
		return true
	}
	for _, marker := range []string{
		"kube-probe",
		"googlehc",
		"elb-healthchecker",
		"healthcheck",
		"health-check",
		"uptimerobot",
		"pingdom",
		"statuscake",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func isIgnoredReportPath(pathValue string) bool {
	switch strings.TrimSpace(pathValue) {
	case "/healthz", "/readyz", "/metrics":
		return true
	default:
		return false
	}
}

func incrementCount(values map[string]uint64, key string) {
	if values == nil {
		return
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "(empty)"
	}
	values[key]++
}

func mergeCountMaps(dst, src map[string]uint64) {
	for key, value := range src {
		dst[key] += value
	}
}

func joinAllCounts(values map[string]uint64) string {
	if len(values) == 0 {
		return ""
	}
	rows := topMap(values, 0)
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, fmt.Sprintf("%s=%d", row.Key, row.Value))
	}
	return strings.Join(parts, "; ")
}

func joinHostKeys(values map[string]HostTraffic) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "; ")
}

func reportLocationValue(code, name string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return strings.TrimSpace(code)
}

func reportCountTableLegacy(title string, values map[string]uint64, keyLabel string, valueLabel string) string {
	rows := topMap(values, 0)
	var b strings.Builder
	b.WriteString(`<div class="panel"><div class="table-wrap"><table><thead><tr>`)
	b.WriteString(`<th>` + html.EscapeString(keyLabel) + `</th>`)
	b.WriteString(`<th class="num">` + html.EscapeString(valueLabel) + `</th>`)
	b.WriteString(`</tr></thead><tbody>`)
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="2" class="muted">No data</td></tr>`)
	} else {
		for _, row := range rows {
			b.WriteString(`<tr><td>` + html.EscapeString(reportSafeText(row.Key)) + `</td><td class="num">` + fmt.Sprintf("%d", row.Value) + `</td></tr>`)
		}
	}
	b.WriteString(`</tbody></table></div></div>`)
	return b.String()
}

func reportHostSummaryTableLegacy(values map[string]hostAggregate) string {
	rows := make([]hostAggregate, 0, len(values))
	for _, row := range values {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalRequests == rows[j].TotalRequests {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].TotalRequests > rows[j].TotalRequests
	})

	var b strings.Builder
	b.WriteString(`<div class="panel"><div class="table-wrap"><table><thead><tr>`)
	b.WriteString(`<th>Host</th>`)
	b.WriteString(`<th class="num">总请求</th>`)
	b.WriteString(`<th class="num">去重客户端 IP</th>`)
	b.WriteString(`<th class="num">放行次数</th>`)
	b.WriteString(`<th class="num">放行去重数</th>`)
	b.WriteString(`<th class="num">拦截次数</th>`)
	b.WriteString(`<th class="num">跳转次数</th>`)
	b.WriteString(`<th>拦截原因</th>`)
	b.WriteString(`<th>路由策略</th>`)
	b.WriteString(`<th>客户端 IP 列表</th>`)
	b.WriteString(`</tr></thead><tbody>`)
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="10" class="muted">No host traffic</td></tr>`)
	} else {
		for _, row := range rows {
			ipRows := topMap(row.ClientIPs, 0)
			ipValues := make([]string, 0, len(ipRows))
			for _, ipRow := range ipRows {
				ipValues = append(ipValues, fmt.Sprintf("%s=%d", ipRow.Key, ipRow.Value))
			}
			b.WriteString(`<tr>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(row.Host)) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.TotalRequests) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.UniqueClients) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.AllowCount) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.UniqueAllowedIPs) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.DenyCount) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.RedirectCount) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(joinAllCounts(row.DenyReasons))) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(joinAllCounts(row.RouteSetCounts))) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(strings.Join(ipValues, "; "))) + `</td>`)
			b.WriteString(`</tr>`)
		}
	}
	b.WriteString(`</tbody></table></div></div>`)
	return b.String()
}

func (s *Service) renderHTMLHostPrimary(dayKey string, summaries []Summary) ([]byte, error) {
	title := strings.TrimSpace(s.cfg.Reports.Title)
	if title == "" {
		title = "gw-ipinfo-nginx daily report"
	}

	dedupedRequestCount := uint64(len(summaries))
	totalRequests := uint64(0)
	totalAllows := uint64(0)
	totalDenies := uint64(0)
	totalRedirects := uint64(0)
	shortCircuitTotal := uint64(0)
	dedupedSuccessCount := uint64(0)
	hostStats := map[string]hostAggregate{}
	uaCounts := map[string]uint64{}
	langCounts := map[string]uint64{}
	countryCounts := map[string]uint64{}
	regionCounts := map[string]uint64{}
	cityCounts := map[string]uint64{}
	denyReasonCounts := map[string]uint64{}
	allowReasonCounts := map[string]uint64{}
	routeSetCounts := map[string]uint64{}
	routeIDCounts := map[string]uint64{}

	for _, summary := range summaries {
		host := reportFirstNonEmpty(strings.TrimSpace(summary.Host), strings.TrimSpace(summary.SourceHost), "(unknown)")
		total := summary.AllowCount + summary.DenyCount
		totalRequests += total
		totalAllows += summary.AllowCount
		totalDenies += summary.DenyCount
		totalRedirects += summary.RedirectCount
		shortCircuitTotal += summary.ShortCircuitAllowCount + summary.ShortCircuitDenyCount
		if summary.AllowCount > 0 {
			dedupedSuccessCount++
		}

		mergeCountMaps(uaCounts, summary.UserAgentCounts)
		mergeCountMaps(langCounts, summary.AcceptLanguageCounts)
		mergeCountMaps(countryCounts, summary.CountryCounts)
		mergeCountMaps(regionCounts, summary.RegionCounts)
		mergeCountMaps(cityCounts, summary.CityCounts)
		mergeCountMaps(denyReasonCounts, summary.DenyReasons)
		mergeCountMaps(allowReasonCounts, summary.AllowReasons)
		mergeCountMaps(routeSetCounts, summary.RouteSetCounts)
		mergeCountMaps(routeIDCounts, summary.RouteIDCounts)

		agg := hostStats[host]
		agg.Host = host
		agg.TotalRequests += total
		agg.UniqueClients++
		agg.AllowCount += summary.AllowCount
		agg.DenyCount += summary.DenyCount
		agg.RedirectCount += summary.RedirectCount
		if summary.AllowCount > 0 {
			agg.UniqueAllowedIPs++
		}
		if agg.DenyReasons == nil {
			agg.DenyReasons = map[string]uint64{}
		}
		if agg.RouteSetCounts == nil {
			agg.RouteSetCounts = map[string]uint64{}
		}
		if agg.RouteIDCounts == nil {
			agg.RouteIDCounts = map[string]uint64{}
		}
		if agg.ClientIPs == nil {
			agg.ClientIPs = map[string]uint64{}
		}
		if agg.PathCounts == nil {
			agg.PathCounts = map[string]uint64{}
		}
		if agg.RequestURLCounts == nil {
			agg.RequestURLCounts = map[string]uint64{}
		}
		mergeCountMaps(agg.DenyReasons, summary.DenyReasons)
		mergeCountMaps(agg.RouteSetCounts, summary.RouteSetCounts)
		mergeCountMaps(agg.RouteIDCounts, summary.RouteIDCounts)
		mergeCountMaps(agg.PathCounts, summary.PathCounts)
		mergeCountMaps(agg.RequestURLCounts, summary.RequestURLCounts)
		agg.ClientIPs[summary.ClientIP] = total
		hostStats[host] = agg
	}

	buf := &bytes.Buffer{}
	buf.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">`)
	buf.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	buf.WriteString(`<title>` + html.EscapeString(title) + `</title>`)
	buf.WriteString(`
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f5f7fb;color:#111827;margin:0;padding:24px}
.wrap{max-width:1680px;margin:0 auto}
.hero{background:#111827;color:#fff;border-radius:18px;padding:24px}
.hero h1{margin:0 0 8px 0;font-size:30px}
.hero p{margin:0;font-size:14px;color:#d1d5db}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}
.metric-card{background:#1f2937;border-radius:14px;padding:14px}
.metric-card .label{font-size:12px;color:#9ca3af;text-transform:uppercase}
.metric-card .value{margin-top:8px;font-size:28px;font-weight:700}
.metric-card .sub{margin-top:8px;font-size:12px;color:#cbd5e1}
.section{margin-top:22px;background:#fff;border:1px solid #dbe5f0;border-radius:18px;padding:18px}
.section h2{margin:0 0 6px 0;font-size:20px}
.section p{margin:0 0 14px 0;font-size:13px;color:#64748b}
.panel{margin-top:12px}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse;min-width:1180px}
th,td{padding:10px 12px;border-bottom:1px solid #e5e7eb;vertical-align:top;text-align:left;font-size:13px}
th{background:#eff6ff;color:#1d4ed8;position:sticky;top:0}
.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.muted{color:#64748b}
@media (max-width:1100px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style></head><body><div class="wrap">`)

	buf.WriteString(`<section class="hero">`)
	buf.WriteString(`<h1>` + html.EscapeString(title) + ` | ` + html.EscapeString(dayKey) + `</h1>`)
	buf.WriteString(`<p>按 Host 为主键、按真实客户端 IP 去重统计。健康探测请求已自动忽略，CSV 作为当前统计视图的详细明细补充。</p>`)
	buf.WriteString(`<div class="metrics">`)
	buf.WriteString(reportMetricCard("总 Host 数", fmt.Sprintf("%d", len(hostStats)), "参与统计的 Host 域名数量", "neutral"))
	buf.WriteString(reportMetricCard("总请求数", fmt.Sprintf("%d", totalRequests), "所有 Host 的 allow + deny 总量", "neutral"))
	buf.WriteString(reportMetricCard("去重请求数", fmt.Sprintf("%d", dedupedRequestCount), "按 Host + 客户端 IP 去重后的请求主体数", "info"))
	buf.WriteString(reportMetricCard("总放行数", fmt.Sprintf("%d", totalAllows), reportPercentString(totalAllows, totalRequests)+" 放行率", "success"))
	buf.WriteString(reportMetricCard("总拦截数", fmt.Sprintf("%d", totalDenies), reportPercentString(totalDenies, totalRequests)+" 拦截率", "danger"))
	buf.WriteString(reportMetricCard("成功去重数", fmt.Sprintf("%d", dedupedSuccessCount), "至少发生过一次放行的去重客户端数", "success"))
	buf.WriteString(reportMetricCard("重定向触发数", fmt.Sprintf("%d", totalRedirects), "触发 v1/v2/v3/v4 或 deny redirect 的请求数", "warning"))
	buf.WriteString(reportMetricCard("短路命中数", fmt.Sprintf("%d", shortCircuitTotal), reportPercentString(shortCircuitTotal, totalRequests)+" 的总请求占比", "warning"))
	buf.WriteString(`</div></section>`)

	buf.WriteString(`<section class="section"><h2>Host 维度汇总</h2><p>按 Host 展示总请求数、按客户端 IP 去重后的请求数、放行/拦截结果、路径资源概览和路由策略。</p>`)
	buf.WriteString(reportHostSummaryTable(hostStats))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>UA 统计分析</h2><p>完整展示全部 User-Agent 聚合结果，不做 TopN 截断。</p>`)
	buf.WriteString(reportCountTable("User-Agent", uaCounts, "UA", "请求数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>语言统计分析</h2><p>完整展示全部 Accept-Language 聚合结果。</p>`)
	buf.WriteString(reportCountTable("Accept-Language", langCounts, "语言", "请求数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>地区统计分析</h2><p>完整展示国家、地区、城市聚合结果。</p>`)
	buf.WriteString(reportCountTable("Country", countryCounts, "国家", "请求数"))
	buf.WriteString(reportCountTable("Region", regionCounts, "地区", "请求数"))
	buf.WriteString(reportCountTable("City", cityCounts, "城市", "请求数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>拦截分析</h2><p>完整展示拦截原因与放行原因。</p>`)
	buf.WriteString(reportCountTable("Deny reason", denyReasonCounts, "拦截原因", "次数"))
	buf.WriteString(reportCountTable("Allow reason", allowReasonCounts, "放行原因", "次数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`<section class="section"><h2>路由策略分析</h2><p>完整展示 route_set_kind 与 route_id 的聚合结果。</p>`)
	buf.WriteString(reportCountTable("Route set", routeSetCounts, "路由策略", "次数"))
	buf.WriteString(reportCountTable("Route ID", routeIDCounts, "规则 ID", "次数"))
	buf.WriteString(`</section>`)

	buf.WriteString(`</div></body></html>`)
	return buf.Bytes(), nil
}

func reportCountTable(title string, values map[string]uint64, keyLabel string, valueLabel string) string {
	rows := topMap(values, 0)
	var b strings.Builder
	b.WriteString(`<div class="panel">`)
	if strings.TrimSpace(title) != "" {
		b.WriteString(`<div class="muted" style="margin:0 0 10px 0;">` + html.EscapeString(reportSafeText(title)) + `</div>`)
	}
	b.WriteString(`<div class="table-wrap"><table><thead><tr>`)
	b.WriteString(`<th>` + html.EscapeString(keyLabel) + `</th>`)
	b.WriteString(`<th class="num">` + html.EscapeString(valueLabel) + `</th>`)
	b.WriteString(`</tr></thead><tbody>`)
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="2" class="muted">No data</td></tr>`)
	} else {
		for _, row := range rows {
			b.WriteString(`<tr><td>` + html.EscapeString(reportSafeText(row.Key)) + `</td><td class="num">` + fmt.Sprintf("%d", row.Value) + `</td></tr>`)
		}
	}
	b.WriteString(`</tbody></table></div></div>`)
	return b.String()
}

func reportHostSummaryTable(values map[string]hostAggregate) string {
	rows := make([]hostAggregate, 0, len(values))
	for _, row := range values {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalRequests == rows[j].TotalRequests {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].TotalRequests > rows[j].TotalRequests
	})

	var b strings.Builder
	b.WriteString(`<div class="panel"><div class="table-wrap"><table><thead><tr>`)
	b.WriteString(`<th>Host 域名</th>`)
	b.WriteString(`<th class="num">总请求次数</th>`)
	b.WriteString(`<th class="num">去重请求数</th>`)
	b.WriteString(`<th class="num">总成功次数</th>`)
	b.WriteString(`<th class="num">成功去重数</th>`)
	b.WriteString(`<th class="num">拦截次数</th>`)
	b.WriteString(`<th class="num">跳转次数</th>`)
	b.WriteString(`<th>拦截原因</th>`)
	b.WriteString(`<th>路由策略</th>`)
	b.WriteString(`<th class="num">路径去重数</th>`)
	b.WriteString(`<th>路径列表</th>`)
	b.WriteString(`</tr></thead><tbody>`)
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="11" class="muted">No host traffic</td></tr>`)
	} else {
		for _, row := range rows {
			routeSummary := joinAllCounts(row.RouteSetCounts)
			routeIDSummary := joinAllCounts(row.RouteIDCounts)
			if routeIDSummary != "" {
				if routeSummary != "" {
					routeSummary += "; "
				}
				routeSummary += routeIDSummary
			}
			b.WriteString(`<tr>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(row.Host)) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.TotalRequests) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.UniqueClients) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.AllowCount) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.UniqueAllowedIPs) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.DenyCount) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", row.RedirectCount) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(joinAllCounts(row.DenyReasons))) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(routeSummary)) + `</td>`)
			b.WriteString(`<td class="num">` + fmt.Sprintf("%d", len(row.PathCounts)) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(reportSafeText(joinAllCounts(row.PathCounts))) + `</td>`)
			b.WriteString(`</tr>`)
		}
	}
	b.WriteString(`</tbody></table></div></div>`)
	return b.String()
}

func topMap(values map[string]uint64, limit int) []aggregateRow {
	rows := make([]aggregateRow, 0, len(values))
	for key, value := range values {
		if key == "" {
			key = "(empty)"
		}
		rows = append(rows, aggregateRow{Key: key, Value: value})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Value == rows[j].Value {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].Value > rows[j].Value
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func joinTopReasons(values map[string]uint64) string {
	if len(values) == 0 {
		return ""
	}
	rows := topMap(values, 3)
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, fmt.Sprintf("%s=%d", row.Key, row.Value))
	}
	return strings.Join(parts, "; ")
}

func card(title, value string) string {
	return "<div class=\"card\"><strong>" + html.EscapeString(title) + "</strong><div>" + html.EscapeString(value) + "</div></div>"
}

func listBlock(title string, rows []aggregateRow) string {
	var b strings.Builder
	b.WriteString("<h3>" + html.EscapeString(title) + "</h3><ul>")
	for _, row := range rows {
		b.WriteString("<li>" + html.EscapeString(row.Key) + ": " + fmt.Sprintf("%d", row.Value) + "</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func td(value string) string {
	return "<td>" + html.EscapeString(value) + "</td>"
}

func (s *Service) writeReportFile(dayLabel, format string, data []byte) (string, error) {
	if err := os.MkdirAll(s.cfg.Reports.Output.OutputDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir report output dir: %w", err)
	}
	fileName := s.buildReportFileName(dayLabel, format)
	finalPath := filepath.Join(s.cfg.Reports.Output.OutputDir, fileName)
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write report tmp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", fmt.Errorf("rename report file: %w", err)
	}
	return finalPath, nil
}

func (s *Service) sendReportDocument(ctx context.Context, dayLabel, format, contentType string, data []byte, caption string) error {
	sendCtx, cancel := context.WithTimeout(ctx, s.reportDocumentTimeout())
	defer cancel()
	return s.sender.SendDocument(sendCtx, s.buildReportFileName(dayLabel, format), contentType, data, caption)
}

func (s *Service) reportDocumentTimeout() time.Duration {
	timeout := s.cfg.Alerts.Telegram.Timeout
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	return timeout
}

func (s *Service) buildReportFileName(dayLabel, format string) string {
	base := strings.TrimSpace(s.cfg.Reports.Filename.Prefix)
	if base == "" {
		base = "gw-report"
	}
	if s.cfg.Reports.Filename.AppendDate {
		base += "-" + dayLabel
	}
	return base + "." + format
}

func resolveReportLocation(cfg config.ReportsConfig) (*time.Location, string, error) {
	if cfg.TimeZoneMode == "system" {
		location := time.Local
		return location, location.String(), nil
	}
	location, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		return nil, "", err
	}
	return location, location.String(), nil
}

func mergeSummaries(left, right Summary) Summary {
	merged := left

	if merged.ID == "" {
		merged.ID = right.ID
	}
	if merged.Kind == "" {
		merged.Kind = right.Kind
	}
	if merged.Day == "" {
		merged.Day = right.Day
	}
	if merged.ClientIP == "" {
		merged.ClientIP = right.ClientIP
	}

	merged.AllowCount += right.AllowCount
	merged.DenyCount += right.DenyCount
	merged.RedirectCount += right.RedirectCount
	merged.ShortCircuitAllowCount += right.ShortCircuitAllowCount
	merged.ShortCircuitDenyCount += right.ShortCircuitDenyCount

	if merged.AllowReasons == nil {
		merged.AllowReasons = map[string]uint64{}
	}
	if merged.DenyReasons == nil {
		merged.DenyReasons = map[string]uint64{}
	}
	if merged.RouteSetCounts == nil {
		merged.RouteSetCounts = map[string]uint64{}
	}
	if merged.RouteIDCounts == nil {
		merged.RouteIDCounts = map[string]uint64{}
	}
	if merged.RequestURLCounts == nil {
		merged.RequestURLCounts = map[string]uint64{}
	}
	if merged.PathCounts == nil {
		merged.PathCounts = map[string]uint64{}
	}
	if merged.UserAgentCounts == nil {
		merged.UserAgentCounts = map[string]uint64{}
	}
	if merged.AcceptLanguageCounts == nil {
		merged.AcceptLanguageCounts = map[string]uint64{}
	}
	if merged.CountryCounts == nil {
		merged.CountryCounts = map[string]uint64{}
	}
	if merged.RegionCounts == nil {
		merged.RegionCounts = map[string]uint64{}
	}
	if merged.CityCounts == nil {
		merged.CityCounts = map[string]uint64{}
	}
	for key, value := range right.AllowReasons {
		merged.AllowReasons[key] += value
	}
	for key, value := range right.DenyReasons {
		merged.DenyReasons[key] += value
	}
	for key, value := range right.RouteSetCounts {
		merged.RouteSetCounts[key] += value
	}
	for key, value := range right.RouteIDCounts {
		merged.RouteIDCounts[key] += value
	}
	for key, value := range right.RequestURLCounts {
		merged.RequestURLCounts[key] += value
	}
	for key, value := range right.PathCounts {
		merged.PathCounts[key] += value
	}
	for key, value := range right.UserAgentCounts {
		merged.UserAgentCounts[key] += value
	}
	for key, value := range right.AcceptLanguageCounts {
		merged.AcceptLanguageCounts[key] += value
	}
	for key, value := range right.CountryCounts {
		merged.CountryCounts[key] += value
	}
	for key, value := range right.RegionCounts {
		merged.RegionCounts[key] += value
	}
	for key, value := range right.CityCounts {
		merged.CityCounts[key] += value
	}

	if merged.FirstSeenAt.IsZero() || (!right.FirstSeenAt.IsZero() && right.FirstSeenAt.Before(merged.FirstSeenAt)) {
		merged.FirstSeenAt = right.FirstSeenAt
	}
	if right.LastSeenAt.After(merged.LastSeenAt) {
		merged.LastSeenAt = right.LastSeenAt
		merged.ServiceName = right.ServiceName
		merged.RouteSetKind = right.RouteSetKind
		merged.RouteID = right.RouteID
		merged.SourceHost = right.SourceHost
		merged.TargetHost = right.TargetHost
		merged.BackendService = right.BackendService
		merged.BackendHost = right.BackendHost
		merged.V4RouteSource = right.V4RouteSource
		merged.V3SecurityFilterEnabled = right.V3SecurityFilterEnabled
		merged.V3SelectedTargetID = right.V3SelectedTargetID
		merged.V3SelectedTargetHost = right.V3SelectedTargetHost
		merged.V3StrategyMode = right.V3StrategyMode
		merged.V3BindingReused = right.V3BindingReused
		merged.V4RuntimeMode = right.V4RuntimeMode
		merged.V4SecurityChecksEnabled = right.V4SecurityChecksEnabled
		merged.V4EnrichmentMode = right.V4EnrichmentMode
		merged.V4ProbeEnabled = right.V4ProbeEnabled
		merged.IPInfoLookupAction = right.IPInfoLookupAction
		merged.DataSourceMode = right.DataSourceMode
		merged.Host = right.Host
		merged.Path = right.Path
		merged.RequestURL = right.RequestURL
		merged.UserAgent = right.UserAgent
		merged.UserAgentSummary = right.UserAgentSummary
		merged.AcceptLanguage = right.AcceptLanguage
		merged.CountryCode = right.CountryCode
		merged.CountryName = right.CountryName
		merged.Region = right.Region
		merged.City = right.City
		merged.Privacy = right.Privacy
	}
	if right.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = right.UpdatedAt
	}

	return merged
}

func reportMetricCard(title, value, sub, tone string) string {
	return `<div class="metric-card ` + html.EscapeString(tone) + `">` +
		`<div class="label">` + html.EscapeString(reportSafeText(title)) + `</div>` +
		`<div class="value">` + html.EscapeString(reportSafeText(value)) + `</div>` +
		`<div class="sub">` + html.EscapeString(reportSafeText(sub)) + `</div>` +
		`</div>`
}

func reportInsightCard(title string, row aggregateRow, total uint64, tone string) string {
	label := reportSafeText(row.Key)
	if label == "—" {
		label = "no data"
	}

	sub := "0 occurrences"
	if row.Value > 0 {
		sub = fmt.Sprintf("%d occurrences · %s", row.Value, reportPercentString(row.Value, total))
	}
	return `<div class="insight-card ` + html.EscapeString(tone) + `">` +
		`<div class="insight-label">` + html.EscapeString(reportSafeText(title)) + `</div>` +
		`<div class="insight-value">` + html.EscapeString(label) + `</div>` +
		`<div class="insight-sub">` + html.EscapeString(sub) + `</div>` +
		`</div>`
}

func reportDonutPanel(allowed, denied uint64) string {
	total := allowed + denied
	allowPct := reportPercentValue(allowed, total)
	denyPct := reportPercentValue(denied, total)

	gradient := fmt.Sprintf(
		"background:conic-gradient(#16a34a 0 %.2f%%, #ef4444 %.2f%% 100%%);",
		allowPct,
		allowPct,
	)

	return `<div class="panel">` +
		`<div class="panel-head">` +
		`<div><h3>Allow vs deny ratio</h3><div class="panel-sub">Quick health read of accepted versus rejected traffic.</div></div>` +
		`</div>` +
		`<div class="donut-shell">` +
		`<div class="donut-chart" style="` + gradient + `">` +
		`<div class="donut-hole">` +
		`<div class="big">` + html.EscapeString(reportPercentString(allowed, total)) + `</div>` +
		`<div class="small">allow rate<br>` + fmt.Sprintf("%d total", total) + `</div>` +
		`</div></div>` +
		`<div class="legend">` +
		`<div class="legend-item">` +
		`<div class="legend-left"><span class="legend-dot allow"></span><span>Allowed</span></div>` +
		`<div class="legend-right">` + fmt.Sprintf("%d", allowed) + `<br>` + html.EscapeString(reportPercentString(allowed, total)) + `</div>` +
		`</div>` +
		`<div class="legend-item">` +
		`<div class="legend-left"><span class="legend-dot deny"></span><span>Denied</span></div>` +
		`<div class="legend-right">` + fmt.Sprintf("%d", denied) + `<br>` + html.EscapeString(reportPercentString(denied, total)) + `</div>` +
		`</div>` +
		`<div class="legend-item">` +
		`<div class="legend-left"><span class="legend-dot allow" style="background:#f59e0b"></span><span>Traffic posture</span></div>` +
		`<div class="legend-right">` + html.EscapeString(reportTrafficPosture(allowPct, denyPct)) + `</div>` +
		`</div>` +
		`</div></div></div>`
}

func reportBarPanel(title, subtitle string, rows []aggregateRow, total uint64, tone string) string {
	var maxValue uint64
	for _, row := range rows {
		if row.Value > maxValue {
			maxValue = row.Value
		}
	}

	var b strings.Builder
	b.WriteString(`<div class="panel">`)
	b.WriteString(`<div class="panel-head"><div><h3>`)
	b.WriteString(html.EscapeString(reportSafeText(title)))
	b.WriteString(`</h3><div class="panel-sub">`)
	b.WriteString(html.EscapeString(reportSafeText(subtitle)))
	b.WriteString(`</div></div></div>`)

	if len(rows) == 0 {
		b.WriteString(`<div class="empty">No aggregate data available for this section.</div></div>`)
		return b.String()
	}

	b.WriteString(`<div class="bar-list">`)
	for _, row := range rows {
		width := 0.0
		if maxValue > 0 {
			width = float64(row.Value) * 100 / float64(maxValue)
		}

		b.WriteString(`<div class="bar-row">`)
		b.WriteString(`<div class="bar-meta">`)
		b.WriteString(`<span class="bar-label" title="`)
		b.WriteString(html.EscapeString(reportSafeText(row.Key)))
		b.WriteString(`">`)
		b.WriteString(html.EscapeString(reportCompactText(reportSafeText(row.Key), 48)))
		b.WriteString(`</span>`)
		b.WriteString(`<span class="bar-value">`)
		b.WriteString(fmt.Sprintf("%d", row.Value))
		b.WriteString(` · `)
		b.WriteString(html.EscapeString(reportPercentString(row.Value, total)))
		b.WriteString(`</span></div>`)
		b.WriteString(`<div class="bar-track"><div class="bar-fill `)
		b.WriteString(html.EscapeString(tone))
		b.WriteString(`" style="width:`)
		b.WriteString(fmt.Sprintf("%.2f", width))
		b.WriteString(`%"></div></div>`)
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

func reportTD(value string) string {
	return `<td>` + html.EscapeString(reportSafeText(value)) + `</td>`
}

func reportTDClass(value, className string) string {
	return `<td class="` + html.EscapeString(strings.TrimSpace(className)) + `">` +
		html.EscapeString(reportSafeText(value)) +
		`</td>`
}

func reportTDHTML(className, raw string) string {
	return `<td class="` + html.EscapeString(strings.TrimSpace(className)) + `">` + raw + `</td>`
}

func reportBadge(label, tone string) string {
	return `<span class="badge ` + html.EscapeString(strings.TrimSpace(tone)) + `">` +
		html.EscapeString(reportSafeText(label)) +
		`</span>`
}

func reportStackedValue(primary, secondary string) string {
	return `<div class="stacked">` +
		`<div class="primary">` + html.EscapeString(reportSafeText(primary)) + `</div>` +
		`<div class="secondary">` + html.EscapeString(reportSafeText(secondary)) + `</div>` +
		`</div>`
}

func reportPercentValue(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func reportPercentString(part, total uint64) string {
	return fmt.Sprintf("%.1f%%", reportPercentValue(part, total))
}

func reportSafeText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func reportFirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func reportJoinParts(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "-" {
			parts = append(parts, value)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " | ")
}

func reportCompactText(value string, limit int) string {
	if limit <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit <= 1 {
		return string(runes[:limit])
	}
	return string(runes[:limit-1]) + "..."
}

func reportFirstAggregate(rows []aggregateRow, fallback string) aggregateRow {
	if len(rows) == 0 {
		return aggregateRow{
			Key:   fallback,
			Value: 0,
		}
	}
	return rows[0]
}

func reportTrafficPosture(allowPct, denyPct float64) string {
	switch {
	case allowPct >= 95:
		return "mostly clean traffic"
	case allowPct >= 80:
		return "healthy with visible filtering"
	case denyPct >= 40:
		return "elevated block pressure"
	default:
		return "mixed traffic profile"
	}
}

func (s *Service) summaryFromEvent(event Event) Summary {
	now := event.Timestamp.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	dayKey := now.In(s.location).Format("2006-01-02")
	hostKey := reportPrimaryHost(event)
	summary := Summary{
		ID:           dayKey + "|" + hostKey + "|" + event.ClientIP,
		Kind:         "summary",
		Day:          dayKey,
		ClientIP:     event.ClientIP,
		AllowReasons: map[string]uint64{},
		DenyReasons:  map[string]uint64{},
		RouteSetCounts: map[string]uint64{},
		RouteIDCounts: map[string]uint64{},
		RequestURLCounts: map[string]uint64{},
		PathCounts: map[string]uint64{},
		UserAgentCounts: map[string]uint64{},
		AcceptLanguageCounts: map[string]uint64{},
		CountryCounts: map[string]uint64{},
		RegionCounts: map[string]uint64{},
		CityCounts: map[string]uint64{},
		FirstSeenAt:  now,
	}
	applyEvent(&summary, event, now)
	return summary
}
