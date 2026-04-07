package shortcircuit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/policy"
	"gw-ipinfo-nginx/internal/storage"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Source string

const (
	SourceNone      Source = "none"
	SourceL1        Source = "l1"
	SourceMongo     Source = "mongo"
	SourceLocalDisk Source = "localdisk"
)

type writeKind string

const (
	writeDecision writeKind = "decision"
	writeHit      writeKind = "hit"
)

type writeRequest struct {
	record Record
	kind   writeKind
}

type Service struct {
	logger         *slog.Logger
	controller     *storage.Controller
	l1             *L1
	queue          chan writeRequest
	ttl            time.Duration
	failureTTL     time.Duration
	collectionName string
	indexOnce      sync.Once
}

func NewService(cfg *config.Config, controller *storage.Controller, logger *slog.Logger) *Service {
	service := &Service{
		logger:         logger,
		controller:     controller,
		l1:             NewL1(cfg.Cache.L1.Enabled, cfg.Cache.L1.ShortCircuitEntries, cfg.Cache.L1.Shards),
		queue:          make(chan writeRequest, cfg.Perf.AsyncWriteQueueSize),
		ttl:            cfg.Cache.ShortCircuitTTL,
		failureTTL:     cfg.Cache.FailureTTL,
		collectionName: cfg.Cache.MongoCollections.DecisionCache,
	}
	if controller != nil {
		controller.RegisterReplayer(service)
	}
	return service
}

func (s *Service) Name() string {
	return "short_circuit_cache"
}

func (s *Service) Run(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 1
	}
	for idx := 0; idx < workers; idx++ {
		go s.runWorker(ctx)
	}
}

func (s *Service) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-s.queue:
			if err := s.persist(ctx, req.record); err != nil && s.logger != nil {
				s.logger.Warn("short_circuit_persist_error",
					"event", "short_circuit_persist_error",
					"client_ip", req.record.ClientIP,
					"error", err,
				)
			}
		}
	}
}

func (s *Service) Lookup(ctx context.Context, clientIP string) (Record, Source, bool) {
	now := time.Now().UTC()
	if record, ok := s.l1.Get(clientIP, now); ok {
		return record, SourceL1, true
	}

	if client := s.mongoClient(); client != nil && s.controller.Mode() != storage.ModeLocal {
		record, ok, err := s.getMongo(ctx, client, clientIP)
		if err == nil && ok && record.Fresh(now) {
			s.l1.Set(clientIP, record)
			return record, SourceMongo, true
		}
		if err != nil {
			s.controller.HandleMongoError(err)
		}
	}

	record, ok, err := s.getLocal(ctx, clientIP)
	if err == nil && ok && record.Fresh(now) {
		s.l1.Set(clientIP, record)
		return record, SourceLocalDisk, true
	}
	return Record{}, SourceNone, false
}

func (s *Service) RememberDecision(clientIP, host, path, userAgent string, decision policy.Decision, ipContext *ipctx.Context) Record {
	now := time.Now().UTC()
	ttl := s.ttl
	if decision.Ambiguous && s.failureTTL > 0 && s.failureTTL < ttl {
		ttl = s.failureTTL
	}
	record, _, ok := s.Lookup(context.Background(), clientIP)
	if !ok {
		record = NewRecord(clientIP, host, path, userAgent, decision, ipContext, ttl, now)
	} else {
		record.ApplyDecision(decision, ipContext, host, path, userAgent, ttl, now)
	}
	s.l1.Set(clientIP, record)
	s.enqueue(writeRequest{record: record, kind: writeDecision})
	return record
}

func (s *Service) RememberShortCircuitHit(record Record) Record {
	now := time.Now().UTC()
	record.ApplyShortCircuitHit(s.ttl, now)
	s.l1.Set(record.ClientIP, record)
	s.enqueue(writeRequest{record: record, kind: writeHit})
	return record
}

func (s *Service) Decision(record Record) policy.Decision {
	decision := policy.Decision{
		Allowed:   record.LastDecision == DecisionAllow,
		Result:    record.LastDecision,
		Reason:    record.LastReasonCode,
		RiskTypes: record.PrivacyRiskTypes(),
	}
	if decision.Allowed {
		decision.Result = "allow"
		if strings.HasPrefix(record.LastReasonCode, "allow_privacy_") {
			decision.Result = "allow_with_risk"
			decision.AlertType = "allowed_with_risk"
		}
	} else {
		decision.Result = "deny"
		if strings.HasPrefix(record.LastReasonCode, "deny_geo_city_missing") || strings.HasPrefix(record.LastReasonCode, "deny_ipinfo_lookup_failed") {
			decision.Ambiguous = true
			decision.AlertType = "blocked_with_ambiguity"
		}
	}
	return decision
}

func (s *Service) IPContext(record Record) ipctx.Context {
	return ipctx.Context{
		IP:          record.ClientIP,
		CountryCode: record.CountryCode,
		CountryName: record.CountryName,
		Region:      record.Region,
		City:        record.City,
		Privacy:     record.Privacy,
	}
}

func (s *Service) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	keys, err := s.controller.Local().DirtyKeys(ctx, localdisk.BucketDecisionDirty, batchSize)
	if err != nil {
		return 0, err
	}

	replayed := 0

	for _, key := range keys {
		var record Record
		if err := s.controller.Local().GetJSON(ctx, localdisk.BucketDecisionCache, key, &record); err != nil {
			if errors.Is(err, localdisk.ErrNotFound) {
				_ = s.controller.Local().ClearDirty(ctx, localdisk.BucketDecisionDirty, key)
				continue
			}
			return replayed, err
		}

		if err := s.upsertMongo(ctx, client, record); err != nil {
			return replayed, err
		}

		if err := s.controller.Local().ClearDirty(ctx, localdisk.BucketDecisionDirty, key); err != nil {
			return replayed, err
		}

		replayed++
	}

	return replayed, nil
}

func (r Record) PrivacyRiskTypes() []string {
	var risks []string
	if r.Privacy.VPN {
		risks = append(risks, "vpn")
	}
	if r.Privacy.Proxy {
		risks = append(risks, "proxy")
	}
	if r.Privacy.Tor {
		risks = append(risks, "tor")
	}
	if r.Privacy.Relay {
		risks = append(risks, "relay")
	}
	if r.Privacy.Hosting {
		risks = append(risks, "hosting")
	}
	if r.Privacy.ResidentialProxy {
		risks = append(risks, "residential_proxy")
	}
	return risks
}

func (s *Service) enqueue(req writeRequest) {
	select {
	case s.queue <- req:
	default:
		go func() {
			_ = s.persist(context.Background(), req.record)
		}()
	}
}

func (s *Service) persist(ctx context.Context, record Record) error {
	if client := s.mongoClient(); client != nil && s.controller.Mode() != storage.ModeLocal {
		if err := s.upsertMongo(ctx, client, record); err == nil {
			return nil
		} else {
			s.controller.HandleMongoError(err)
		}
	}
	return s.controller.Local().PutJSONDirty(ctx, localdisk.BucketDecisionCache, localdisk.BucketDecisionDirty, record.ClientIP, record)
}

func (s *Service) mongoClient() *mongostore.Client {
	if s.controller == nil {
		return nil
	}
	return s.controller.Client()
}

func (s *Service) getMongo(ctx context.Context, client *mongostore.Client, clientIP string) (Record, bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var record Record
	err := client.Database().Collection(s.collectionName).FindOne(child, bson.M{"_id": clientIP}).Decode(&record)
	if err == nil {
		return record, true, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Record{}, false, nil
	}
	return Record{}, false, fmt.Errorf("find short circuit %s: %w", clientIP, err)
}

func (s *Service) getLocal(ctx context.Context, clientIP string) (Record, bool, error) {
	var record Record
	if err := s.controller.Local().GetJSON(ctx, localdisk.BucketDecisionCache, clientIP, &record); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	return record, true, nil
}

func (s *Service) upsertMongo(ctx context.Context, client *mongostore.Client, record Record) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	collection := client.Database().Collection(s.collectionName)

	s.indexOnce.Do(func() {
		index := mongo.IndexModel{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0).
				SetName("ttl_expires_at"),
		}
		_, _ = collection.Indexes().CreateOne(child, index)
	})

	_, err := collection.UpdateByID(
		child,
		record.ClientIP,
		bson.M{
			"$set": bson.M{
				"client_ip":                 record.ClientIP,
				"last_decision":             record.LastDecision,
				"last_reason_code":          record.LastReasonCode,
				"country_code":              record.CountryCode,
				"country_name":              record.CountryName,
				"region":                    record.Region,
				"city":                      record.City,
				"privacy":                   record.Privacy,
				"last_seen_at":              record.LastSeenAt,
				"allow_count":               record.AllowCount,
				"deny_count":                record.DenyCount,
				"short_circuit_allow_count": record.ShortCircuitAllowCount,
				"short_circuit_deny_count":  record.ShortCircuitDenyCount,
				"host":                      record.Host,
				"path":                      record.Path,
				"user_agent_hash":           record.UserAgentHash,
				"expires_at":                record.ExpiresAt,
				"updated_at":                record.UpdatedAt,
			},
			"$setOnInsert": bson.M{
				"first_seen_at": record.FirstSeenAt,
			},
		},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("upsert short circuit %s: %w", record.ClientIP, err)
	}

	return nil
}
