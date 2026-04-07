package reporting

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
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
}

type Summary struct {
	ID                     string             `json:"id" bson:"_id"`
	Kind                   string             `json:"kind" bson:"kind"`
	Day                    string             `json:"day" bson:"day"`
	ClientIP               string             `json:"client_ip" bson:"client_ip"`
	ServiceName            string             `json:"service_name" bson:"service_name"`
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

type Service struct {
	cfg            *config.Config
	controller     *storage.Controller
	logger         *slog.Logger
	sender         *alerts.Sender
	metrics        *metrics.GatewayMetrics
	location       *time.Location
	queue          chan Event
	workerID       string
	collectionName string
	indexOnce      sync.Once
}

func NewService(cfg *config.Config, controller *storage.Controller, logger *slog.Logger, sender *alerts.Sender, metricsSet *metrics.GatewayMetrics, workerID string) (*Service, error) {
	location, err := time.LoadLocation(cfg.Reports.TimeZone)
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
	if event.ClientIP == "" {
		return
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
	if s.cfg.Reports.Enabled && s.cfg.Reports.WorkerEnabled && s.sender != nil {
		go s.runScheduler(ctx)
	}
}

func (s *Service) Replay(ctx context.Context, client *mongostore.Client, batchSize int) error {
	keys, err := s.controller.Local().DirtyKeys(ctx, localdisk.BucketReportDirty, batchSize)
	if err != nil {
		return err
	}
	for _, key := range keys {
		var summary Summary
		if err := s.controller.Local().GetJSON(ctx, localdisk.BucketReportRecords, key, &summary); err != nil {
			if err == localdisk.ErrNotFound {
				_ = s.controller.Local().ClearDirty(ctx, localdisk.BucketReportDirty, key)
				continue
			}
			return err
		}
		if err := s.upsertMongo(ctx, client, summary); err != nil {
			return err
		}
		if err := s.controller.Local().ClearDirty(ctx, localdisk.BucketReportDirty, key); err != nil {
			return err
		}
	}
	return nil
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
	summary, err := s.upsertLocal(ctx, event)
	if err != nil {
		return err
	}
	client := s.controller.Client()
	if client != nil && s.controller.Mode() != storage.ModeLocal {
		if err := s.upsertMongo(ctx, client, summary); err == nil {
			return s.controller.Local().ClearDirty(ctx, localdisk.BucketReportDirty, summary.ID)
		} else {
			s.controller.HandleMongoError(err)
		}
	}
	return nil
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
	reportTime, err := s.reportTime(now)
	if err != nil {
		return err
	}
	if now.In(s.location).Before(reportTime) {
		return nil
	}
	reportDay := reportTime.Add(-s.cfg.Reports.Lookback)
	dayKey := reportDay.In(s.location).Format("2006-01-02")
	if sent, err := s.isReportSent(ctx, dayKey); err == nil && sent {
		return nil
	}

	htmlReport, csvReport, err := s.GenerateDaily(ctx, reportDay)
	if err != nil {
		return err
	}
	caption := fmt.Sprintf("gw-ipinfo-nginx daily report %s", dayKey)
	sendCtx, cancel := context.WithTimeout(ctx, s.cfg.Alerts.Telegram.Timeout)
	defer cancel()

	if s.cfg.Reports.IncludeHTML {
		if err := s.sender.SendDocument(sendCtx, "gw-report-"+dayKey+".html", "text/html", htmlReport, caption); err != nil {
			if s.metrics != nil {
				s.metrics.ReportRuns.Inc(metrics.Labels{"status": "send_error"})
			}
			return err
		}
	}
	if s.cfg.Reports.IncludeCSV {
		if err := s.sender.SendDocument(sendCtx, "gw-report-"+dayKey+".csv", "text/csv", csvReport, caption); err != nil {
			if s.metrics != nil {
				s.metrics.ReportRuns.Inc(metrics.Labels{"status": "send_error"})
			}
			return err
		}
	}
	if err := s.markReportSent(ctx, dayKey); err != nil {
		if s.metrics != nil {
			s.metrics.ReportRuns.Inc(metrics.Labels{"status": "mark_error"})
		}
		return err
	}
	if s.metrics != nil {
		s.metrics.ReportRuns.Inc(metrics.Labels{"status": "sent"})
	}
	return nil
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

func (s *Service) isReportSent(ctx context.Context, dayKey string) (bool, error) {
	if client := s.controller.Client(); client != nil && s.controller.Mode() != storage.ModeLocal {
		child, cancel := client.WithTimeout(ctx)
		defer cancel()
		count, err := client.Database().Collection(s.collectionName).CountDocuments(child, bson.M{
			"_id":  "report_sent:" + dayKey,
			"kind": "report_sent",
		})
		if err == nil {
			return count > 0, nil
		}
		s.controller.HandleMongoError(err)
	}

	type marker struct {
		SentAt time.Time `json:"sent_at"`
	}
	var value marker
	err := s.controller.Local().GetJSON(ctx, localdisk.BucketMetadata, "report_sent:"+dayKey, &value)
	if err == nil {
		return true, nil
	}
	if err == localdisk.ErrNotFound {
		return false, nil
	}
	return false, err
}

func (s *Service) markReportSent(ctx context.Context, dayKey string) error {
	if client := s.controller.Client(); client != nil && s.controller.Mode() != storage.ModeLocal {
		child, cancel := client.WithTimeout(ctx)
		defer cancel()
		_, err := client.Database().Collection(s.collectionName).UpdateByID(child, "report_sent:"+dayKey, bson.M{
			"$set": bson.M{
				"kind":    "report_sent",
				"day":     dayKey,
				"sent_at": time.Now().UTC(),
			},
		}, options.Update().SetUpsert(true))
		if err == nil {
			return nil
		}
		s.controller.HandleMongoError(err)
	}

	return s.controller.Local().PutJSON(ctx, localdisk.BucketMetadata, "report_sent:"+dayKey, map[string]time.Time{
		"sent_at": time.Now().UTC(),
	})
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
	summaries := make([]Summary, 0, 128)
	err := s.controller.Local().ForEachJSON(ctx, localdisk.BucketReportRecords, func(key string, raw []byte) error {
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		var summary Summary
		if err := json.Unmarshal(raw, &summary); err != nil {
			return err
		}
		summaries = append(summaries, summary)
		return nil
	})
	if err != nil {
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
	buf.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>gw-ipinfo-nginx report</title>")
	buf.WriteString("<style>body{font-family:Arial,sans-serif;margin:24px;background:#f8fafc;color:#0f172a}table{border-collapse:collapse;width:100%}th,td{border:1px solid #cbd5e1;padding:8px;font-size:13px;text-align:left}th{background:#e2e8f0}h1,h2{margin:0 0 12px}section{margin:24px 0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card{background:#fff;padding:12px;border:1px solid #cbd5e1;border-radius:8px}</style></head><body>")
	buf.WriteString("<h1>gw-ipinfo-nginx Daily Report " + html.EscapeString(dayKey) + "</h1>")
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
	buf.WriteString("<section><h2>Deduplicated IP Summary</h2><table><thead><tr><th>IP</th><th>Allow</th><th>Deny</th><th>Allow reason</th><th>Deny reason</th><th>Country</th><th>Region</th><th>City</th><th>UA</th><th>Host</th><th>Path</th><th>SC allow</th><th>SC deny</th></tr></thead><tbody>")
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
