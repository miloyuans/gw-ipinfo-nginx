package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/audit"
	"gw-ipinfo-nginx/internal/blockpage"
	"gw-ipinfo-nginx/internal/cache"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/health"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/ipinfo"
	"gw-ipinfo-nginx/internal/logging"
	"gw-ipinfo-nginx/internal/metrics"
	"gw-ipinfo-nginx/internal/middleware"
	"gw-ipinfo-nginx/internal/model"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/policy"
	"gw-ipinfo-nginx/internal/proxy"
	"gw-ipinfo-nginx/internal/realip"
	"gw-ipinfo-nginx/internal/routing"
	"gw-ipinfo-nginx/internal/server"
)

type Application struct {
	cfg         *config.Config
	logger      *slog.Logger
	server      *http.Server
	mongoClient *mongostore.Client
	worker      *alerts.Worker
}

func New(configPath string) (*Application, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	logger := logging.New(cfg.Logging)
	metricsRegistry := metrics.NewRegistry()
	metricSet := metrics.NewGatewayMetrics(metricsRegistry)

	realIPExtractor, err := realip.NewExtractor(cfg.RealIP)
	if err != nil {
		return nil, err
	}
	policyEngine, err := policy.NewEngine(cfg.Security)
	if err != nil {
		return nil, err
	}
	resolver := routing.NewResolver(cfg.Routing)
	proxyManager, err := proxy.NewManager(cfg.Routing.Services, metricSet, logger)
	if err != nil {
		return nil, err
	}

	var mongoClient *mongostore.Client
	var cacheRepo *cache.Repository
	var alertRepo *alerts.Repository
	l1 := cache.NewL1(cfg.Cache.L1.Enabled, cfg.Cache.L1.MaxEntries)

	if cfg.NeedsMongo() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Mongo.ConnectTimeout+cfg.Mongo.OperationTimeout)
		defer cancel()

		mongoClient, err = mongostore.Connect(ctx, cfg.Mongo)
		if err != nil {
			return nil, err
		}

		cacheRepo = cache.NewRepository(mongoClient, cfg.Cache.MongoCollections.IPCache)
		if cfg.IPInfo.Enabled {
			if err := cacheRepo.InitIndexes(context.Background()); err != nil {
				return nil, err
			}
		}

		if cfg.Alerts.Telegram.Enabled || cfg.Alerts.Delivery.WorkerEnabled {
			alertRepo = alerts.NewRepository(mongoClient, cfg.Cache.MongoCollections.AlertOutbox, cfg.Cache.MongoCollections.AlertDedupe)
			if err := alertRepo.InitIndexes(context.Background()); err != nil {
				return nil, err
			}
		}
	}

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

	var worker *alerts.Worker
	if cfg.Alerts.Telegram.Enabled && cfg.Alerts.Delivery.WorkerEnabled {
		worker = alerts.NewWorker(logger, alertRepo, sender, cfg.Alerts.Delivery, metricSet, workerID())
	}

	healthHandler := health.New(mongoChecker{client: mongoClient})
	auditor := audit.New(logger)
	gatewayHandler := &GatewayHandler{
		cfg:             cfg,
		logger:          logger,
		auditor:         auditor,
		metrics:         metricSet,
		realIPExtractor: realIPExtractor,
		resolver:        resolver,
		policyEngine:    policyEngine,
		lookupService:   lookupService,
		alertRepo:       alertRepo,
		proxyManager:    proxyManager,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler.Liveness)
	mux.HandleFunc("/readyz", healthHandler.Readiness)
	if cfg.Metrics.Enabled {
		mux.Handle(cfg.Metrics.Path, metricsRegistry)
	}
	mux.Handle("/", middleware.WithRequestID(gatewayHandler))

	return &Application{
		cfg:         cfg,
		logger:      logger,
		server:      server.NewHTTPServer(cfg.Server, mux),
		mongoClient: mongoClient,
		worker:      worker,
	}, nil
}

func (a *Application) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	if a.worker != nil {
		go func() {
			errCh <- a.worker.Run(ctx)
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
	return nil
}

type GatewayHandler struct {
	cfg             *config.Config
	logger          *slog.Logger
	auditor         *audit.Logger
	metrics         *metrics.GatewayMetrics
	realIPExtractor *realip.Extractor
	resolver        *routing.Resolver
	policyEngine    *policy.Engine
	lookupService   *ipinfo.LookupService
	alertRepo       *alerts.Repository
	proxyManager    *proxy.Manager
}

func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := middleware.RequestID(r.Context())
	service := h.resolver.Resolve(r)
	cacheSource := ipctx.CacheSourceNone

	clientIP, err := h.realIPExtractor.Extract(r)
	if err != nil {
		decision := policy.Decision{Allowed: false, Result: "deny", Reason: "deny_real_ip_extract_failed"}
		h.denyRequest(w, r, requestID, service, "", cacheSource, decision, nil, start)
		return
	}

	if requestDecision := h.policyEngine.EvaluateRequest(r, service.Name); requestDecision != nil {
		h.denyRequest(w, r, requestID, service, clientIP, cacheSource, *requestDecision, nil, start)
		return
	}

	var ipContext ipctx.Context
	var lookupErr error
	if h.lookupService != nil {
		ipContext, cacheSource, lookupErr = h.lookupService.Lookup(r.Context(), clientIP)
	}

	decision := policy.Decision{Allowed: true, Result: "allow", Reason: "allow_prechecks_passed"}
	if h.cfg.IPInfo.Enabled {
		decision = h.policyEngine.EvaluateIP(ipContext, lookupErr)
	}
	if !decision.Allowed {
		h.denyRequest(w, r, requestID, service, clientIP, cacheSource, decision, &ipContext, start)
		return
	}

	if decision.AlertType != "" {
		h.enqueueAlert(r, requestID, service.Name, clientIP, cacheSource, decision, &ipContext)
	}
	h.auditor.LogDecision(h.auditRecord(r, requestID, service, clientIP, cacheSource, decision, &ipContext, time.Since(start)))
	h.proxyManager.ServeHTTP(w, r, service, clientIP, &ipContext)
	h.observe(service.Name, decision, start)
}

func (h *GatewayHandler) denyRequest(w http.ResponseWriter, req *http.Request, requestID string, service config.ServiceConfig, clientIP string, cacheSource ipctx.CacheSource, decision policy.Decision, ipContext *ipctx.Context, start time.Time) {
	if decision.AlertType != "" {
		h.enqueueAlert(req, requestID, service.Name, clientIP, cacheSource, decision, ipContext)
	}
	h.observe(service.Name, decision, start)
	h.auditor.LogDecision(h.auditRecord(req, requestID, service, clientIP, cacheSource, decision, ipContext, time.Since(start)))
	blockpage.Write(w, h.cfg.Server.DenyStatusCode, h.cfg.DenyPage, requestID)
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
	client *mongostore.Client
}

func (c mongoChecker) Check(ctx context.Context) error {
	if c.client == nil {
		return nil
	}
	return c.client.Ping(ctx)
}

func safeURL(req *http.Request, maskQuery bool) string {
	if !maskQuery {
		return req.URL.String()
	}
	return req.URL.Path
}

func (h *GatewayHandler) auditRecord(req *http.Request, requestID string, service config.ServiceConfig, clientIP string, cacheSource ipctx.CacheSource, decision policy.Decision, ipContext *ipctx.Context, latency time.Duration) model.AuditRecord {
	record := model.AuditRecord{
		RequestID:   requestID,
		ClientIP:    clientIP,
		ServiceName: service.Name,
		UpstreamURL: service.TargetURL,
		Method:      req.Method,
		Path:        req.URL.Path,
		Allowed:     decision.Allowed,
		Result:      decision.Result,
		ReasonCode:  decision.Reason,
		CacheSource: cacheSource,
		LatencyMS:   float64(latency.Milliseconds()),
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
