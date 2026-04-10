package reporting

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
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
	Host                 string
	Path                 string
	RequestURL           string
	UserAgentSummary     string
	Allowed              bool
	Result               string
	ReasonCode           string
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
	IPInfoLookupAction      string
	DataSourceMode          string
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
	V3SecurityFilterEnabled bool              `json:"v3_security_filter_enabled" bson:"v3_security_filter_enabled"`
	V3SelectedTargetID      string            `json:"v3_selected_target_id" bson:"v3_selected_target_id"`
	V3SelectedTargetHost    string            `json:"v3_selected_target_host" bson:"v3_selected_target_host"`
	V3StrategyMode          string            `json:"v3_strategy_mode" bson:"v3_strategy_mode"`
	V3BindingReused         bool              `json:"v3_binding_reused" bson:"v3_binding_reused"`
	IPInfoLookupAction      string            `json:"ipinfo_lookup_action" bson:"ipinfo_lookup_action"`
	DataSourceMode          string            `json:"data_source_mode" bson:"data_source_mode"`
	Host                   string             `json:"host" bson:"host"`
	Path                   string             `json:"path" bson:"path"`
	RequestURL             string             `json:"request_url" bson:"request_url"`
	UserAgentSummary       string             `json:"user_agent_summary" bson:"user_agent_summary"`
	AllowCount             uint64             `json:"allow_count" bson:"allow_count"`
	DenyCount              uint64             `json:"deny_count" bson:"deny_count"`
	ShortCircuitAllowCount uint64             `json:"short_circuit_allow_count" bson:"short_circuit_allow_count"`
	ShortCircuitDenyCount  uint64             `json:"short_circuit_deny_count" bson:"short_circuit_deny_count"`
	AllowReasons           map[string]uint64  `json:"allow_reasons" bson:"allow_reasons"`
	DenyReasons            map[string]uint64  `json:"deny_reasons" bson:"deny_reasons"`
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
	indexOnce      sync.Once
	scheduleMu     sync.Mutex
	lastSkipLogKey string
}

func NewService(cfg *config.Config, controller *storage.Controller, logger *slog.Logger, sender *alerts.Sender, metricsSet *metrics.GatewayMetrics, workerID string) (*Service, error) {
	location, locationName, err := resolveReportLocation(cfg.Reports)
	if err != nil {
		return nil, err
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
				"max_backfill_days", s.cfg.Reports.MaxBackfillDays,
				"telegram_enabled", s.cfg.Reports.Output.TelegramEnabled,
				"file_enabled", s.cfg.Reports.Output.FileEnabled,
			)
		}
		go s.runScheduler(ctx)
	}
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
	summaryID := dayKey + "|" + event.ClientIP
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
	summary.ServiceName = event.ServiceName
	summary.RouteSetKind = event.RouteSetKind
	summary.RouteID = event.RouteID
	summary.SourceHost = event.SourceHost
	summary.TargetHost = event.TargetHost
	summary.V3SecurityFilterEnabled = event.V3SecurityFilterEnabled
	summary.V3SelectedTargetID = event.V3SelectedTargetID
	summary.V3SelectedTargetHost = event.V3SelectedTargetHost
	summary.V3StrategyMode = event.V3StrategyMode
	summary.V3BindingReused = event.V3BindingReused
	summary.IPInfoLookupAction = event.IPInfoLookupAction
	summary.DataSourceMode = event.DataSourceMode
	summary.Host = event.Host
	summary.Path = event.Path
	summary.RequestURL = event.RequestURL
	summary.UserAgentSummary = event.UserAgentSummary
	summary.CountryCode = event.CountryCode
	summary.CountryName = event.CountryName
	summary.Region = event.Region
	summary.City = event.City
	summary.Privacy = event.Privacy
	summary.LastSeenAt = now
	summary.UpdatedAt = now
	if event.Allowed {
		summary.AllowCount++
		summary.AllowReasons[event.ReasonCode]++
	} else {
		summary.DenyCount++
		summary.DenyReasons[event.ReasonCode]++
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
				Keys:    bson.D{{Key: "day", Value: 1}, {Key: "client_ip", Value: 1}},
				Options: options.Index().SetName("daily_ip_lookup"),
			},
			{
				Keys:    bson.D{{Key: "kind", Value: 1}, {Key: "day", Value: 1}},
				Options: options.Index().SetName("report_kind_day"),
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
	ticker := time.NewTicker(s.cfg.Reports.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.trySendDailyReport(ctx, time.Now().UTC()); err != nil && s.logger != nil {
				s.logger.Warn("daily_report_error", "event", "daily_report_error", "error", err)
			}
		}
	}
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
			}
		}
		if s.cfg.Reports.IncludeCSV && !state.TelegramCSVSent {
			if sendErr := s.sendReportDocument(ctx, candidate.DayLabel, "csv", "text/csv", csvReport, caption); sendErr != nil {
				errorsList = append(errorsList, sendErr.Error())
				if s.logger != nil {
					s.logger.Warn("daily_report_send_error", "event", "daily_report_send_error", "day_key", candidate.DayKey, "format", "csv", "error", sendErr)
				}
			} else {
				state.TelegramCSVSent = true
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
	if client := s.controller.Client(); client != nil && s.controller.Mode() != storage.ModeLocal {
		child, cancel := client.WithTimeout(ctx)
		defer cancel()

		var state reportDeliveryState
		err := client.Database().Collection(s.collectionName).FindOne(child, bson.M{"_id": s.reportStateKey(dayKey)}).Decode(&state)
		if err == nil {
			return state, nil
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			s.controller.HandleMongoError(err)
		}
	}

	var state reportDeliveryState
	err := s.controller.Local().GetJSON(ctx, localdisk.BucketMetadata, s.reportStateKey(dayKey), &state)
	if err == nil {
		return state, nil
	}
	if errors.Is(err, localdisk.ErrNotFound) {
		return defaultState, nil
	}
	return defaultState, err
}

func (s *Service) saveReportState(ctx context.Context, state reportDeliveryState) error {
	state.TelegramSuccess = s.telegramReportSatisfied(state)
	state.FileSuccess = s.fileReportSatisfied(state)
	state.OverallSuccess = state.TelegramSuccess && state.FileSuccess
	state.UpdatedAt = time.Now().UTC()

	if client := s.controller.Client(); client != nil && s.controller.Mode() != storage.ModeLocal {
		child, cancel := client.WithTimeout(ctx)
		defer cancel()

		_, err := client.Database().Collection(s.collectionName).ReplaceOne(
			child,
			bson.M{"_id": state.ID},
			state,
			options.Replace().SetUpsert(true),
		)
		if err == nil {
			return nil
		}
		s.controller.HandleMongoError(err)
	}

	return s.controller.Local().PutJSON(ctx, localdisk.BucketMetadata, state.ID, state)
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
	if client := s.controller.Client(); client != nil && s.controller.Mode() != storage.ModeLocal {
		summaries, err := s.loadDayFromMongo(ctx, client, dayKey)
		if err == nil {
			return summaries, nil
		}
		s.controller.HandleMongoError(err)
	}

	prefix := dayKey + "|"
	summaryMap := make(map[string]Summary, 128)
	err := s.controller.Local().ForEachJSON(ctx, localdisk.BucketReportRecords, func(key string, raw []byte) error {
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		var summary Summary
		if err := json.Unmarshal(raw, &summary); err != nil {
			return err
		}
		if existing, ok := summaryMap[summary.ID]; ok {
			summaryMap[summary.ID] = mergeSummaries(existing, summary)
			return nil
		}
		summaryMap[summary.ID] = summary
		return nil
	})
	if err != nil {
		return nil, err
	}
	summaries := make([]Summary, 0, len(summaryMap))
	for _, summary := range summaryMap {
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].AllowCount+summaries[i].DenyCount == summaries[j].AllowCount+summaries[j].DenyCount {
			return summaries[i].ClientIP < summaries[j].ClientIP
		}
		return summaries[i].AllowCount+summaries[i].DenyCount > summaries[j].AllowCount+summaries[j].DenyCount
	})
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
		"source_host",
		"target_host",
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
			summary.SourceHost,
			summary.TargetHost,
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
	totalRequests := uint64(0)
	allowed := uint64(0)
	denied := uint64(0)
	topDeny := map[string]uint64{}
	topAllow := map[string]uint64{}
	topCountry := map[string]uint64{}
	topHost := map[string]uint64{}
	topUA := map[string]uint64{}
	for _, summary := range summaries {
		totalRequests += summary.AllowCount + summary.DenyCount
		allowed += summary.AllowCount
		denied += summary.DenyCount
		for key, value := range summary.AllowReasons {
			topAllow[key] += value
		}
		for key, value := range summary.DenyReasons {
			topDeny[key] += value
		}
		topCountry[summary.CountryCode] += summary.AllowCount + summary.DenyCount
		topHost[summary.Host] += summary.AllowCount + summary.DenyCount
		topUA[summary.UserAgentSummary] += summary.AllowCount + summary.DenyCount
	}

	buf := &bytes.Buffer{}
	title := strings.TrimSpace(s.cfg.Reports.Title)
	if title == "" {
		title = "gw-ipinfo-nginx daily report"
	}
	buf.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(title) + "</title>")
	buf.WriteString("<style>body{font-family:Arial,sans-serif;margin:24px;background:#f8fafc;color:#0f172a}table{border-collapse:collapse;width:100%}th,td{border:1px solid #cbd5e1;padding:8px;font-size:13px;text-align:left}th{background:#e2e8f0}h1,h2{margin:0 0 12px}section{margin:24px 0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card{background:#fff;padding:12px;border:1px solid #cbd5e1;border-radius:8px}</style></head><body>")
	buf.WriteString("<h1>" + html.EscapeString(title) + " " + html.EscapeString(dayKey) + "</h1>")
	buf.WriteString("<section class=\"grid\">")
	buf.WriteString(card("total requests", fmt.Sprintf("%d", totalRequests)))
	buf.WriteString(card("unique IPs", fmt.Sprintf("%d", len(summaries))))
	buf.WriteString(card("allowed", fmt.Sprintf("%d", allowed)))
	buf.WriteString(card("denied", fmt.Sprintf("%d", denied)))
	buf.WriteString("</section>")
	buf.WriteString("<section><h2>Top Aggregates</h2>")
	buf.WriteString(listBlock("deny reasons", topMap(topDeny, s.cfg.Reports.TopN)))
	buf.WriteString(listBlock("allow reasons", topMap(topAllow, s.cfg.Reports.TopN)))
	buf.WriteString(listBlock("countries", topMap(topCountry, s.cfg.Reports.TopN)))
	buf.WriteString(listBlock("hosts", topMap(topHost, s.cfg.Reports.TopN)))
	buf.WriteString(listBlock("ua", topMap(topUA, s.cfg.Reports.TopN)))
	buf.WriteString("</section>")
	buf.WriteString("<section><h2>Deduplicated IP Summary</h2><table><thead><tr><th>IP</th><th>Allow</th><th>Deny</th><th>Allow reason</th><th>Deny reason</th><th>Country</th><th>Region</th><th>City</th><th>Route set</th><th>Route ID</th><th>V3 strategy</th><th>V3 target ID</th><th>V3 target host</th><th>Source host</th><th>Target host</th><th>UA</th><th>Host</th><th>Path</th><th>SC allow</th><th>SC deny</th></tr></thead><tbody>")
	for _, summary := range summaries {
		buf.WriteString("<tr>")
		buf.WriteString(td(summary.ClientIP))
		buf.WriteString(td(fmt.Sprintf("%d", summary.AllowCount)))
		buf.WriteString(td(fmt.Sprintf("%d", summary.DenyCount)))
		buf.WriteString(td(joinTopReasons(summary.AllowReasons)))
		buf.WriteString(td(joinTopReasons(summary.DenyReasons)))
		buf.WriteString(td(summary.CountryCode))
		buf.WriteString(td(summary.Region))
		buf.WriteString(td(summary.City))
		buf.WriteString(td(summary.RouteSetKind))
		buf.WriteString(td(summary.RouteID))
		buf.WriteString(td(summary.V3StrategyMode))
		buf.WriteString(td(summary.V3SelectedTargetID))
		buf.WriteString(td(summary.V3SelectedTargetHost))
		buf.WriteString(td(summary.SourceHost))
		buf.WriteString(td(summary.TargetHost))
		buf.WriteString(td(summary.UserAgentSummary))
		buf.WriteString(td(summary.Host))
		buf.WriteString(td(summary.Path))
		buf.WriteString(td(fmt.Sprintf("%d", summary.ShortCircuitAllowCount)))
		buf.WriteString(td(fmt.Sprintf("%d", summary.ShortCircuitDenyCount)))
		buf.WriteString("</tr>")
	}
	buf.WriteString("</tbody></table></section></body></html>")
	return buf.Bytes(), nil
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
	sendCtx, cancel := context.WithTimeout(ctx, s.cfg.Alerts.Telegram.Timeout)
	defer cancel()
	return s.sender.SendDocument(sendCtx, s.buildReportFileName(dayLabel, format), contentType, data, caption)
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
	merged.ShortCircuitAllowCount += right.ShortCircuitAllowCount
	merged.ShortCircuitDenyCount += right.ShortCircuitDenyCount

	if merged.AllowReasons == nil {
		merged.AllowReasons = map[string]uint64{}
	}
	if merged.DenyReasons == nil {
		merged.DenyReasons = map[string]uint64{}
	}
	for key, value := range right.AllowReasons {
		merged.AllowReasons[key] += value
	}
	for key, value := range right.DenyReasons {
		merged.DenyReasons[key] += value
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
		merged.V3SecurityFilterEnabled = right.V3SecurityFilterEnabled
		merged.V3SelectedTargetID = right.V3SelectedTargetID
		merged.V3SelectedTargetHost = right.V3SelectedTargetHost
		merged.V3StrategyMode = right.V3StrategyMode
		merged.V3BindingReused = right.V3BindingReused
		merged.IPInfoLookupAction = right.IPInfoLookupAction
		merged.DataSourceMode = right.DataSourceMode
		merged.Host = right.Host
		merged.Path = right.Path
		merged.RequestURL = right.RequestURL
		merged.UserAgentSummary = right.UserAgentSummary
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

func (s *Service) summaryFromEvent(event Event) Summary {
	now := event.Timestamp.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	dayKey := now.In(s.location).Format("2006-01-02")
	summary := Summary{
		ID:           dayKey + "|" + event.ClientIP,
		Kind:         "summary",
		Day:          dayKey,
		ClientIP:     event.ClientIP,
		AllowReasons: map[string]uint64{},
		DenyReasons:  map[string]uint64{},
		FirstSeenAt:  now,
	}
	applyEvent(&summary, event, now)
	return summary
}
