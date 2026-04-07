package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/audit"
	"gw-ipinfo-nginx/internal/blockpage"
	"gw-ipinfo-nginx/internal/cache"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/health"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/ipinfo"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/logging"
	"gw-ipinfo-nginx/internal/metrics"
	"gw-ipinfo-nginx/internal/middleware"
	"gw-ipinfo-nginx/internal/model"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/policy"
	"gw-ipinfo-nginx/internal/proxy"
	"gw-ipinfo-nginx/internal/realip"
	"gw-ipinfo-nginx/internal/reporting"
	"gw-ipinfo-nginx/internal/routing"
	"gw-ipinfo-nginx/internal/server"
	"gw-ipinfo-nginx/internal/shortcircuit"
	"gw-ipinfo-nginx/internal/storage"
)

type Application struct {
	cfg              *config.Config
	logger           *slog.Logger
	server           *http.Server
	mongoClient      *mongostore.Client
	localStore       *localdisk.Store
	storageControl   *storage.Controller
	shortCircuit     *shortcircuit.Service
	alertWorkers     []*alerts.Worker
	reportingService *reporting.Service
	startReplayLoop  bool
}

func New(configPath string) (*Application, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	logger := logging.New(cfg.Logging)
	metricsRegistry := metrics.NewRegistry()
	metricSet := metrics.NewGatewayMetrics(metricsRegistry)

	localStore, err := localdisk.Open(cfg.Storage.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("open local storage: %w", err)
	}
	cleanupStore := true
	defer func() {
		if cleanupStore {
			_ = localStore.Close()
		}
	}()

	storageControl := storage.NewController(cfg.Storage, cfg.Mongo, localStore, logger)

	var mongoClient *mongostore.Client
	mongoConfigured := strings.TrimSpace(cfg.Mongo.URI) != "" && strings.TrimSpace(cfg.Mongo.Database) != ""
	if mongoConfigured {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Mongo.ConnectTimeout+cfg.Mongo.OperationTimeout)
		defer cancel()
		mongoClient, err = mongostore.Connect(ctx, cfg.Mongo)
		if err != nil {
			logger.Warn("mongo_startup_degraded",
				"event", "mongo_degraded_to_local",
				"error", err,
				"data_source_mode", storage.ModeLocal,
			)
		}
	}
	cleanupMongo := true
	defer func() {
		if cleanupMongo && mongoClient != nil {
			_ = mongoClient.Disconnect(context.Background())
		}
	}()
	storageControl.SetMongoClient(mongoClient)

	realIPExtractor, err := realip.NewExtractor(cfg.RealIP)
	if err != nil {
		return nil, err
	}
	policyEngine, err := policy.NewEngine(cfg.Security)
	if err != nil {
		return nil, err
	}
	resolver := routing.NewResolver(cfg.Routing)
	proxyManager, err := proxy.NewManager(cfg.Routing.Services, cfg.Perf, metricSet, logger)
	if err != nil {
		return nil, err
	}
	denyResponder, err := blockpage.NewResponder(cfg.DenyPage, cfg.Perf, logger)
	if err != nil {
		return nil, fmt.Errorf("init deny responder: %w", err)
	}

	l1 := cache.NewL1(cfg.Cache.L1.Enabled, cfg.Cache.L1.MaxEntries, cfg.Cache.L1.Shards)
	cacheRepo := cache.NewResilientRepository(cfg, storageControl)
	storageControl.RegisterReplayer(cacheRepo)
	shortCircuitService := shortcircuit.NewService(cfg, storageControl, logger)

	var ipinfoClient *ipinfo.Client
	if cfg.IPInfo.Enabled {
		ipinfoClient, err = ipinfo.NewClient(cfg.IPInfo)
		if err != nil {
			return nil, err
		}
	}
	lookupService := ipinfo.NewLookupService(cfg, l1, cacheRepo, ipinfoClient, metricSet)

	var sender *alerts.Sender
	if cfg.Alerts.Telegram.Enabled {
		sender, err = alerts.NewSender(cfg.Alerts.Telegram)
		if err != nil {
			return nil, err
		}
	}

	var alertRepo *alerts.ResilientRepository
	if cfg.Alerts.Telegram.Enabled || cfg.Alerts.Delivery.WorkerEnabled {
		alertRepo = alerts.NewResilientRepository(cfg, storageControl, logger)
	}

	var alertWorkers []*alerts.Worker
	if cfg.Alerts.Delivery.WorkerEnabled && sender != nil && alertRepo != nil {
		count := cfg.Perf.AlertWorkers
		if count <= 0 {
			count = 1
		}
		baseID := workerID()
		alertWorkers = make([]*alerts.Worker, 0, count)
		for idx := 0; idx < count; idx++ {
			alertWorkers = append(alertWorkers, alerts.NewWorker(logger, alertRepo, sender, cfg.Alerts.Delivery, metricSet, fmt.Sprintf("%s-%d", baseID, idx+1)))
		}
	}

	var reportingService *reporting.Service
	if sender != nil || cfg.Reports.Enabled {
		reportingService, err = reporting.NewService(cfg, storageControl, logger, sender, metricSet, workerID())
		if err != nil {
			return nil, err
		}
	}

	healthHandler := health.New(mongoChecker{controller: storageControl})
	auditor := audit.New(logger)
	gatewayHandler := &GatewayHandler{
		cfg:             cfg,
		logger:          logger,
		auditor:         auditor,
		metrics:         metricSet,
		controller:      storageControl,
		realIPExtractor: realIPExtractor,
		resolver:        resolver,
		policyEngine:    policyEngine,
		lookupService:   lookupService,
		shortCircuit:    shortCircuitService,
		alertRepo:       alertRepo,
		reporting:       reportingService,
		proxyManager:    proxyManager,
		denyResponder:   denyResponder,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler.Liveness)
	mux.HandleFunc("/readyz", healthHandler.Readiness)
	if cfg.Metrics.Enabled {
		mux.Handle(cfg.Metrics.Path, metricsRegistry)
	}
	mux.Handle("/", middleware.WithRequestID(gatewayHandler))

	cleanupStore = false
	cleanupMongo = false
	return &Application{
		cfg:              cfg,
		logger:           logger,
		server:           server.NewHTTPServer(cfg.Server, mux),
		mongoClient:      mongoClient,
		localStore:       localStore,
		storageControl:   storageControl,
		shortCircuit:     shortCircuitService,
		alertWorkers:     alertWorkers,
		reportingService: reportingService,
		startReplayLoop:  mongoConfigured,
	}, nil
}

func (a *Application) Run(ctx context.Context) error {
	errCh := make(chan error, len(a.alertWorkers)+2)

	if a.startReplayLoop && a.storageControl != nil {
		go a.storageControl.Start(ctx)
	}
	if a.shortCircuit != nil {
		a.shortCircuit.Run(ctx, a.cfg.Perf.DecisionWorkers)
	}
	if a.reportingService != nil {
		a.reportingService.Run(ctx, a.cfg.Storage.ReplayWorkers)
	}
	for _, worker := range a.alertWorkers {
		current := worker
		go func() {
			errCh <- current.Run(ctx)
		}()
	}
	go func() {
		a.logger.Info("gateway_listening", "event", "gateway_listening", "addr", a.server.Addr)
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}
	if a.mongoClient != nil {
		if err := a.mongoClient.Disconnect(shutdownCtx); err != nil {
			return fmt.Errorf("disconnect mongo: %w", err)
		}
	}
	if err := a.localStore.Close(); err != nil {
		return fmt.Errorf("close local store: %w", err)
	}
	return nil
}

type GatewayHandler struct {
	cfg             *config.Config
	logger          *slog.Logger
	auditor         *audit.Logger
	metrics         *metrics.GatewayMetrics
	controller      *storage.Controller
	realIPExtractor *realip.Extractor
	resolver        *routing.Resolver
	policyEngine    *policy.Engine
	lookupService   *ipinfo.LookupService
	shortCircuit    *shortcircuit.Service
	alertRepo       alerts.QueueRepository
	reporting       *reporting.Service
	proxyManager    *proxy.Manager
	denyResponder   *blockpage.Responder
}

func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := middleware.RequestID(r.Context())
	service := h.resolver.Resolve(r)
	cacheSource := ipctx.CacheSourceNone
	ipinfoLookupAction := "disabled"
	if h.lookupService != nil && h.cfg.IPInfo.Enabled {
		ipinfoLookupAction = "start"
	}
	shortCircuitHit := false
	shortCircuitSource := "none"
	shortCircuitDecision := ""
	dataSourceMode := string(h.controller.Mode())

	clientIP, err := h.realIPExtractor.Extract(r)
	if err != nil {
		decision := policy.Decision{Allowed: false, Result: "deny", Reason: "deny_real_ip_extract_failed"}
		h.finish(w, r, requestID, service, "", cacheSource, ipctx.Context{}, decision, start, dataSourceMode, shortCircuitHit, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction)
		return
	}

	if requestDecision := h.policyEngine.EvaluateRequest(r, service.Name); requestDecision != nil {
		h.finish(w, r, requestID, service, clientIP, cacheSource, ipctx.Context{}, *requestDecision, start, dataSourceMode, shortCircuitHit, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction)
		return
	}

	if h.shortCircuit != nil {
		if record, source, ok := h.shortCircuit.Lookup(r.Context(), clientIP); ok {
			shortCircuitHit = true
			shortCircuitSource = string(source)
			shortCircuitDecision = record.LastDecision
			record = h.shortCircuit.RememberShortCircuitHit(record)
			ipContext := h.shortCircuit.IPContext(record)
			decision := h.shortCircuit.Decision(record)
			ipinfoLookupAction = "short_circuit_hit"
			if h.metrics != nil {
				h.metrics.ShortCircuit.Inc(metrics.Labels{
					"source":   shortCircuitSource,
					"decision": shortCircuitDecision,
				})
			}
			h.finish(w, r, requestID, service, clientIP, cacheSource, ipContext, decision, start, dataSourceMode, shortCircuitHit, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction)
			return
		}
	}

	var ipContext ipctx.Context
	var lookupErr error
	if h.lookupService != nil {
		ipContext, cacheSource, ipinfoLookupAction, lookupErr = h.lookupService.Lookup(r.Context(), clientIP)
	}

	decision := policy.Decision{Allowed: true, Result: "allow", Reason: "allow_prechecks_passed"}
	if h.cfg.IPInfo.Enabled {
		decision = h.policyEngine.EvaluateIP(ipContext, lookupErr)
	}

	if h.shortCircuit != nil {
		record := h.shortCircuit.RememberDecision(clientIP, r.Host, safeURL(r, h.cfg.Logging.RedactQuery), r.UserAgent(), decision, &ipContext)
		shortCircuitDecision = record.LastDecision
	}
	h.finish(w, r, requestID, service, clientIP, cacheSource, ipContext, decision, start, dataSourceMode, shortCircuitHit, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction)
}

func (h *GatewayHandler) finish(w http.ResponseWriter, req *http.Request, requestID string, service config.ServiceConfig, clientIP string, cacheSource ipctx.CacheSource, ipContext ipctx.Context, decision policy.Decision, start time.Time, dataSourceMode string, shortCircuitHit bool, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction string) {
	if h.controller != nil {
		dataSourceMode = string(h.controller.Mode())
	}
	if decision.AlertType != "" {
		h.enqueueAlert(req, requestID, service.Name, clientIP, cacheSource, decision, &ipContext)
	}
	latency := time.Since(start)
	h.observe(service.Name, decision, start)

	record := h.auditRecord(req, requestID, service, clientIP, cacheSource, decision, &ipContext, latency, dataSourceMode, shortCircuitHit, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction)
	h.auditor.LogDecision(record)
	h.trackReport(req, record)

	if !decision.Allowed {
		h.denyResponder.ServeHTTP(
			w,
			req,
			h.cfg.Server.DenyStatusCode,
			requestID,
			decision.Reason,
			service.Name,
			clientIP,
		)
		return
	}
	h.proxyManager.ServeHTTP(w, req, service, clientIP, &ipContext)
}

func (h *GatewayHandler) enqueueAlert(req *http.Request, requestID, serviceName, clientIP string, cacheSource ipctx.CacheSource, decision policy.Decision, ipContext *ipctx.Context) {
	if h.alertRepo == nil || !h.cfg.Alerts.Telegram.Enabled || decision.AlertType == "" {
		return
	}
	payload := alerts.NewPayload(
		req,
		requestID,
		serviceName,
		clientIP,
		safeURL(req, h.cfg.Alerts.Telegram.MaskQuery),
		cacheSource,
		decision,
		ipContext,
		h.cfg.Alerts.Telegram.IncludeUserAgent,
	)
	ctx, cancel := context.WithTimeout(req.Context(), 500*time.Millisecond)
	defer cancel()
	enqueued, err := h.alertRepo.Enqueue(ctx, decision.AlertType, payload, h.cfg.Alerts.Dedupe.Window)
	if err != nil {
		h.logger.Error("alert_enqueue_failed", "event", "alert_enqueue_failed", "type", decision.AlertType, "service_name", serviceName, "request_id", requestID, "error", err)
		if h.metrics != nil {
			h.metrics.AlertOutbox.Inc(metrics.Labels{"type": decision.AlertType, "status": "error"})
		}
		return
	}
	if h.metrics != nil {
		status := "deduped"
		if enqueued {
			status = "queued"
		}
		h.metrics.AlertOutbox.Inc(metrics.Labels{"type": decision.AlertType, "status": status})
	}
}

func (h *GatewayHandler) trackReport(req *http.Request, record model.AuditRecord) {
	if h.reporting == nil {
		return
	}
	h.reporting.Track(reporting.Event{
		Timestamp:            time.Now().UTC(),
		ClientIP:             record.ClientIP,
		ServiceName:          record.ServiceName,
		Host:                 record.Host,
		Path:                 record.Path,
		RequestURL:           record.RequestURL,
		UserAgentSummary:     summarizeUserAgent(req.UserAgent()),
		Allowed:              record.Allowed,
		Result:               record.Result,
		ReasonCode:           record.ReasonCode,
		CountryCode:          record.CountryCode,
		CountryName:          record.CountryName,
		Region:               record.Region,
		City:                 record.City,
		Privacy:              record.Privacy,
		ShortCircuitHit:      record.ShortCircuitHit,
		ShortCircuitDecision: record.ShortCircuitDecision,
	})
}

func summarizeUserAgent(userAgent string) string {
	value := strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case value == "":
		return "empty"
	case strings.Contains(value, "curl"):
		return "curl"
	case strings.Contains(value, "chrome"):
		return "chrome"
	case strings.Contains(value, "firefox"):
		return "firefox"
	case strings.Contains(value, "safari"):
		return "safari"
	case strings.Contains(value, "edge"):
		return "edge"
	case strings.Contains(value, "bot"), strings.Contains(value, "crawler"), strings.Contains(value, "spider"):
		return "bot"
	default:
		return "other"
	}
}

func (h *GatewayHandler) observe(serviceName string, decision policy.Decision, start time.Time) {
	if h.metrics == nil {
		return
	}
	h.metrics.Requests.Inc(metrics.Labels{
		"service": serviceName,
		"result":  decision.Result,
	})
	if !decision.Allowed {
		h.metrics.DecisionReasons.Inc(metrics.Labels{
			"service": serviceName,
			"reason":  decision.Reason,
		})
	}
	h.metrics.RequestLatency.Observe(metrics.Labels{
		"service": serviceName,
		"result":  decision.Result,
	}, time.Since(start).Seconds())
}

type mongoChecker struct {
	controller *storage.Controller
}

func (c mongoChecker) Check(ctx context.Context) error {
	if c.controller == nil {
		return nil
	}
	client := c.controller.Client()
	if client == nil {
		return nil
	}
	if err := client.Ping(ctx); err != nil {
		c.controller.HandleMongoError(err)
		return nil
	}
	return nil
}

func safeURL(req *http.Request, maskQuery bool) string {
	if !maskQuery {
		return req.URL.RequestURI()
	}
	return req.URL.Path
}

func (h *GatewayHandler) auditRecord(req *http.Request, requestID string, service config.ServiceConfig, clientIP string, cacheSource ipctx.CacheSource, decision policy.Decision, ipContext *ipctx.Context, latency time.Duration, dataSourceMode string, shortCircuitHit bool, shortCircuitSource, shortCircuitDecision, ipinfoLookupAction string) model.AuditRecord {
	record := model.AuditRecord{
		RequestID:            requestID,
		ClientIP:             clientIP,
		ServiceName:          service.Name,
		UpstreamURL:          service.TargetURL,
		Host:                 req.Host,
		Method:               req.Method,
		Path:                 req.URL.Path,
		RequestURL:           safeURL(req, h.cfg.Logging.RedactQuery),
		Allowed:              decision.Allowed,
		Result:               decision.Result,
		ReasonCode:           decision.Reason,
		CacheSource:          cacheSource,
		DataSourceMode:       dataSourceMode,
		ShortCircuitHit:      shortCircuitHit,
		ShortCircuitSource:   shortCircuitSource,
		ShortCircuitDecision: shortCircuitDecision,
		IPInfoLookupAction:   ipinfoLookupAction,
		LatencyMS:            float64(latency.Milliseconds()),
	}
	if ipContext != nil {
		record.CountryCode = ipContext.CountryCode
		record.CountryName = ipContext.CountryName
		record.Region = ipContext.Region
		record.City = ipContext.City
		record.Privacy = ipContext.Privacy
	}
	return record
}

func workerID() string {
	if value := os.Getenv("POD_NAME"); value != "" {
		return value
	}
	if value, err := os.Hostname(); err == nil && value != "" {
		return value
	}
	return "gw-ipinfo-nginx-worker"
}
