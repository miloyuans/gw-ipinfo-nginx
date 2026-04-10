package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	"gw-ipinfo-nginx/internal/routesets"
	"gw-ipinfo-nginx/internal/runtimex"
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
	routeRuntime     *routesets.Runtime
	shortCircuit     *shortcircuit.Service
	alertWorkers     []*alerts.Worker
	commandBot       *alerts.CommandBot
	lifecycleManager *alerts.LifecycleManager
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

	sharedStoragePath := cfg.Storage.LocalPath
	cfg.Storage.LocalPath = resolveLocalStoragePath(cfg.Storage.LocalPath)
	logger.Info("local_storage_path_resolved",
		"event", "local_storage_path_resolved",
		"path", cfg.Storage.LocalPath,
	)

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
	compiledRouteSets, err := routesets.LoadAndCompile(configPath, cfg.RouteSets, cfg.Routing, cfg.V3Defaults, logger)
	if err != nil {
		return nil, fmt.Errorf("compile route sets: %w", err)
	}
	routeRuntime := routesets.NewRuntime(compiledRouteSets, cfg.RouteSets, logger)
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

	var commandBot *alerts.CommandBot
	if cfg.Alerts.Telegram.CommandBot.Enabled {
		commandLookupService := lookupService
		commandToken := strings.TrimSpace(cfg.Alerts.Telegram.CommandBot.IPInfoToken)
		sharedLookupEligible := commandLookupService != nil &&
			cfg.IPInfo.Enabled &&
			commandToken != "" &&
			commandToken == strings.TrimSpace(cfg.IPInfo.Token)
		if !sharedLookupEligible {
			commandIPInfoCfg := cfg.IPInfo
			commandIPInfoCfg.Enabled = true
			commandIPInfoCfg.Token = cfg.Alerts.Telegram.CommandBot.IPInfoToken
			commandIPInfoClient, commandClientErr := ipinfo.NewClient(commandIPInfoCfg)
			if commandClientErr != nil {
				return nil, commandClientErr
			}
			commandLookupCfg := *cfg
			commandLookupCfg.IPInfo = commandIPInfoCfg
			commandLookupService = ipinfo.NewLookupService(&commandLookupCfg, l1, cacheRepo, commandIPInfoClient, metricSet)
		}
		commandBotStatePath := filepath.Join(filepath.Dir(filepath.Clean(sharedStoragePath)), "telegram-command-bot-state.json")
		commandBot, err = alerts.NewCommandBot(cfg.Alerts.Telegram.CommandBot, logger, commandLookupService, storageControl, commandBotStatePath, workerID())
		if err != nil {
			return nil, err
		}
	}

	var reportingService *reporting.Service
	if sender != nil || cfg.Reports.Enabled {
		reportingService, err = reporting.NewService(cfg, storageControl, logger, sender, metricSet, workerID())
		if err != nil {
			return nil, err
		}
	}
	lifecycleStatePath := filepath.Join(filepath.Dir(cfg.Storage.LocalPath), "gw-ipinfo-nginx.runtime.json")
	hostname, _ := os.Hostname()
	lifecycleManager := alerts.NewLifecycleManager(cfg.Alerts.Telegram, sender, logger, workerID(), hostname, lifecycleStatePath)

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
		routeRuntime:    routeRuntime,
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
		routeRuntime:     routeRuntime,
		shortCircuit:     shortCircuitService,
		alertWorkers:     alertWorkers,
		commandBot:       commandBot,
		lifecycleManager: lifecycleManager,
		reportingService: reportingService,
		startReplayLoop:  mongoConfigured,
	}, nil
}

func (a *Application) Run(ctx context.Context) error {
	return a.run(ctx, nil)
}

func (a *Application) RunWithListener(ctx context.Context, listener net.Listener) error {
	return a.run(ctx, listener)
}

func (a *Application) run(ctx context.Context, listener net.Listener) error {
	errCh := make(chan error, len(a.alertWorkers)+2)

	if a.startReplayLoop && a.storageControl != nil {
		go a.storageControl.Start(ctx)
	}
	if a.lifecycleManager != nil {
		a.lifecycleManager.Startup(ctx, a.cfg.Reports.Enabled, a.cfg.Alerts.Telegram.Enabled)
	}
	if a.shortCircuit != nil {
		a.shortCircuit.Run(ctx, a.cfg.Perf.DecisionWorkers)
	}
	if a.routeRuntime != nil {
		a.routeRuntime.Run(ctx)
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
	if a.commandBot != nil && runtimex.IsPrimaryProcess() {
		go func() {
			if err := a.commandBot.Run(ctx); err != nil && a.logger != nil {
				a.logger.Warn("telegram_command_bot_stopped",
					"event", "telegram_command_bot_stopped",
					"error", err,
				)
			}
		}()
	}
	go func() {
		a.logger.Info("gateway_listening", "event", "gateway_listening", "addr", a.server.Addr)
		var err error
		if listener != nil {
			err = a.server.Serve(listener)
		} else {
			err = a.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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
	if a.lifecycleManager != nil {
		a.lifecycleManager.Shutdown(shutdownCtx)
	}

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
	routeRuntime    *routesets.Runtime
	policyEngine    *policy.Engine
	lookupService   *ipinfo.LookupService
	shortCircuit    *shortcircuit.Service
	alertRepo       alerts.QueueRepository
	reporting       *reporting.Service
	proxyManager    *proxy.Manager
	denyResponder   *blockpage.Responder
}

type flowState struct {
	cacheSource          ipctx.CacheSource
	ipinfoLookupAction   string
	dataSourceMode       string
	shortCircuitHit      bool
	shortCircuitSource   string
	shortCircuitDecision string
}

type evaluationResult struct {
	service  config.ServiceConfig
	clientIP string
	ipContext ipctx.Context
	decision policy.Decision
	state    flowState
}

type routeContext struct {
	RouteSetKind     string
	RouteID          string
	SourceHost       string
	SourcePathPrefix string
	TargetHost       string
	TargetPublicURL  string
	BackendService   string
	BackendHost      string
	GrantStatus      string
	GrantExpireAt    string
	V3SecurityFilterEnabled bool
	V3SelectedTargetID      string
	V3SelectedTargetHost    string
	V3StrategyMode          string
	V3BindingReused         bool
}

type responseAction struct {
	redirectURL   string
	redirectCode  int
	cookie        *http.Cookie
	upstreamHost  string
}

func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := middleware.RequestID(r.Context())
	fallbackService := h.resolver.Resolve(r)

	if h.routeRuntime != nil && h.routeRuntime.Enabled() {
		h.serveWithRouteSets(w, r, requestID, start, fallbackService)
		return
	}

	outcome := h.evaluateFullChain(r, fallbackService)
	h.finish(w, r, requestID, outcome.service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeContext{}, responseAction{})
}

func (h *GatewayHandler) serveWithRouteSets(w http.ResponseWriter, r *http.Request, requestID string, start time.Time, fallbackService config.ServiceConfig) {
	resolution := h.routeRuntime.Resolve(r)
	if resolution.DenyReason != "" {
		h.finish(
			w,
			r,
			requestID,
			fallbackService,
			"",
			ipctx.Context{},
			policy.Decision{Allowed: false, Result: "deny", Reason: resolution.DenyReason},
			start,
			h.newFlowState(),
			h.routeContextFromResolution(resolution),
			responseAction{},
		)
		return
	}

	switch resolution.MatchType {
	case routesets.MatchSource:
		h.serveSourceRoute(w, r, requestID, start, fallbackService, resolution)
	case routesets.MatchTarget:
		h.serveTargetRoute(w, r, requestID, start, fallbackService, resolution)
	default:
		h.finish(
			w,
			r,
			requestID,
			fallbackService,
			"",
			ipctx.Context{},
			policy.Decision{Allowed: false, Result: "deny", Reason: "deny_route_not_found"},
			start,
			h.newFlowState(),
			h.routeContextFromResolution(resolution),
			responseAction{},
		)
	}
}

func (h *GatewayHandler) serveSourceRoute(w http.ResponseWriter, r *http.Request, requestID string, start time.Time, fallbackService config.ServiceConfig, resolution routesets.Resolution) {
	routeMeta := h.routeContextFromRule(resolution.Rule)

	switch resolution.Rule.Kind {
	case routesets.KindBypass:
		service, ok := h.resolver.Service(resolution.Rule.BackendService)
		if !ok {
			h.finish(
				w,
				r,
				requestID,
				fallbackService,
				"",
				ipctx.Context{},
				policy.Decision{Allowed: false, Result: "deny", Reason: "deny_route_not_found"},
				start,
				h.newFlowState(),
				routeMeta,
				responseAction{},
			)
			return
		}
		outcome := h.evaluateBypassChain(r, service)
		h.finish(
			w,
			r,
			requestID,
			service,
			outcome.clientIP,
			outcome.ipContext,
			outcome.decision,
			start,
			outcome.state,
			routeMeta,
			responseAction{upstreamHost: resolution.Rule.BackendHost},
		)
		return
	case routesets.KindV3:
		outcome, selectedTarget, bindingReused := h.evaluateV3Chain(r, fallbackService, resolution.Rule)
		routeMeta.V3SecurityFilterEnabled = resolution.Rule.V3SecurityFilterEnabled
		routeMeta.V3StrategyMode = resolution.Rule.V3StrategyMode
		if selectedTarget.ID != "" {
			routeMeta.V3SelectedTargetID = selectedTarget.ID
			routeMeta.V3SelectedTargetHost = selectedTarget.Host
			routeMeta.TargetHost = selectedTarget.Host
			routeMeta.TargetPublicURL = selectedTarget.PublicURL
			routeMeta.V3BindingReused = bindingReused
		}
		if !outcome.decision.Allowed {
			h.finish(w, r, requestID, outcome.service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeMeta, responseAction{})
			return
		}
		h.finish(
			w,
			r,
			requestID,
			outcome.service,
			outcome.clientIP,
			outcome.ipContext,
			outcome.decision,
			start,
			outcome.state,
			routeMeta,
			responseAction{
				redirectURL:  selectedTarget.PublicURL,
				redirectCode: h.routeRuntime.RedirectStatusCode(),
			},
		)
		return
	case routesets.KindDefault:
		outcome := h.evaluateFullChain(r, fallbackService)
		if !outcome.decision.Allowed {
			h.finish(w, r, requestID, outcome.service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeMeta, responseAction{})
			return
		}
		h.finish(w, r, requestID, outcome.service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeMeta, responseAction{})
	case routesets.KindV1:
		outcome := h.evaluateFullChain(r, fallbackService)
		if !outcome.decision.Allowed {
			h.finish(w, r, requestID, outcome.service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeMeta, responseAction{})
			return
		}
		token, expiresAt, err := h.routeRuntime.IssueV1Grant(resolution.Rule, outcome.clientIP, r.UserAgent())
		if err != nil {
			h.logger.Error("v1_grant_issue_failed",
				"event", "v1_grant_issue_failed",
				"route_id", resolution.Rule.ID,
				"target_host", resolution.Rule.TargetHost,
				"request_id", requestID,
				"error", err,
			)
			h.finish(
				w,
				r,
				requestID,
				outcome.service,
				outcome.clientIP,
				outcome.ipContext,
				policy.Decision{Allowed: false, Result: "deny", Reason: "deny_v1_target_unauthorized"},
				start,
				outcome.state,
				routeMeta,
				responseAction{},
			)
			return
		}
		redirectURL, err := h.routeRuntime.BuildRedirectURL(resolution.Rule.TargetPublicURL, token)
		if err != nil {
			h.logger.Error("v1_redirect_build_failed",
				"event", "v1_redirect_build_failed",
				"route_id", resolution.Rule.ID,
				"target_public_url", resolution.Rule.TargetPublicURL,
				"request_id", requestID,
				"error", err,
			)
			h.finish(
				w,
				r,
				requestID,
				outcome.service,
				outcome.clientIP,
				outcome.ipContext,
				policy.Decision{Allowed: false, Result: "deny", Reason: "deny_v1_target_unauthorized"},
				start,
				outcome.state,
				routeMeta,
				responseAction{},
			)
			return
		}
		redirectDecision := outcome.decision
		redirectDecision.Reason = "allow_v1_redirect"
		routeMeta.GrantExpireAt = expiresAt.UTC().Format(time.RFC3339)
		h.finish(
			w,
			r,
			requestID,
			outcome.service,
			outcome.clientIP,
			outcome.ipContext,
			redirectDecision,
			start,
			outcome.state,
			routeMeta,
			responseAction{
				redirectURL:  redirectURL,
				redirectCode: h.routeRuntime.RedirectStatusCode(),
			},
		)
	case routesets.KindV2:
		outcome := h.evaluateFullChain(r, fallbackService)
		if !outcome.decision.Allowed {
			h.finish(w, r, requestID, outcome.service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeMeta, responseAction{})
			return
		}
		redirectDecision := outcome.decision
		redirectDecision.Reason = "allow_v2_redirect"
		h.finish(
			w,
			r,
			requestID,
			outcome.service,
			outcome.clientIP,
			outcome.ipContext,
			redirectDecision,
			start,
			outcome.state,
			routeMeta,
			responseAction{
				redirectURL:  resolution.Rule.TargetPublicURL,
				redirectCode: h.routeRuntime.RedirectStatusCode(),
			},
		)
	default:
		h.finish(
			w,
			r,
			requestID,
			fallbackService,
			"",
			ipctx.Context{},
			policy.Decision{Allowed: false, Result: "deny", Reason: "deny_route_not_found"},
			start,
			h.newFlowState(),
			routeMeta,
			responseAction{},
		)
	}
}

func (h *GatewayHandler) serveTargetRoute(w http.ResponseWriter, r *http.Request, requestID string, start time.Time, fallbackService config.ServiceConfig, resolution routesets.Resolution) {
	routeMeta := h.routeContextFromResolution(resolution)
	service, ok := h.resolver.Service(resolution.Binding.BackendService)
	if !ok {
		h.finish(
			w,
			r,
			requestID,
			fallbackService,
			"",
			ipctx.Context{},
			policy.Decision{Allowed: false, Result: "deny", Reason: "deny_route_not_found"},
			start,
			h.newFlowState(),
			routeMeta,
			responseAction{},
		)
		return
	}

	switch resolution.Binding.RuleKind {
	case routesets.KindV1:
		clientIP, extractDecision, state := h.extractClientIP(r)
		if extractDecision != nil {
			h.finish(w, r, requestID, service, "", ipctx.Context{}, *extractDecision, start, state, routeMeta, responseAction{})
			return
		}
		grantResult := h.routeRuntime.ExchangeV1Target(r, resolution.Host, clientIP)
		routeMeta.GrantStatus = string(grantResult.Status)
		if !grantResult.ExpiresAt.IsZero() {
			routeMeta.GrantExpireAt = grantResult.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if grantResult.Rule.ID != "" {
			routeMeta = h.routeContextFromRule(grantResult.Rule)
			routeMeta.GrantStatus = string(grantResult.Status)
			routeMeta.GrantExpireAt = grantResult.ExpiresAt.UTC().Format(time.RFC3339)
			if resolvedService, exists := h.resolver.Service(grantResult.Rule.BackendService); exists {
				service = resolvedService
			}
		}

		switch grantResult.Status {
		case routesets.GrantStatusQueryOK:
			h.finish(
				w,
				r,
				requestID,
				service,
				clientIP,
				ipctx.Context{},
				policy.Decision{Allowed: true, Result: "allow", Reason: "allow_v1_exchange"},
				start,
				state,
				routeMeta,
				responseAction{
					redirectURL:  grantResult.Rule.TargetPublicURL,
					redirectCode: h.routeRuntime.RedirectStatusCode(),
					cookie:       h.routeRuntime.ExchangeCookie(grantResult.Token, grantResult.ExpiresAt),
				},
			)
		case routesets.GrantStatusCookieOK:
			h.finish(
				w,
				r,
				requestID,
				service,
				clientIP,
				ipctx.Context{},
				policy.Decision{Allowed: true, Result: "allow", Reason: "allow_v1_shortcircuit"},
				start,
				state,
				routeMeta,
				responseAction{upstreamHost: grantResult.Rule.BackendHost},
			)
		case routesets.GrantStatusExpired:
			h.finish(
				w,
				r,
				requestID,
				service,
				clientIP,
				ipctx.Context{},
				policy.Decision{Allowed: false, Result: "deny", Reason: "deny_v1_target_expired"},
				start,
				state,
				routeMeta,
				responseAction{},
			)
		default:
			h.finish(
				w,
				r,
				requestID,
				service,
				clientIP,
				ipctx.Context{},
				policy.Decision{Allowed: false, Result: "deny", Reason: "deny_v1_target_unauthorized"},
				start,
				state,
				routeMeta,
				responseAction{},
			)
		}
	case routesets.KindV2:
		outcome := h.evaluateFullChain(r, service)
		if outcome.decision.Allowed {
			h.finish(
				w,
				r,
				requestID,
				service,
				outcome.clientIP,
				outcome.ipContext,
				outcome.decision,
				start,
				outcome.state,
				routeMeta,
				responseAction{upstreamHost: resolution.Binding.BackendHost},
			)
			return
		}
		h.finish(w, r, requestID, service, outcome.clientIP, outcome.ipContext, outcome.decision, start, outcome.state, routeMeta, responseAction{})
	default:
		h.finish(
			w,
			r,
			requestID,
			service,
			"",
			ipctx.Context{},
			policy.Decision{Allowed: false, Result: "deny", Reason: "deny_route_not_found"},
			start,
			h.newFlowState(),
			routeMeta,
			responseAction{},
		)
	}
}

func (h *GatewayHandler) newFlowState() flowState {
	mode := storage.ModeLocal
	if h.controller != nil {
		mode = h.controller.Mode()
	}
	return flowState{
		cacheSource:        ipctx.CacheSourceNone,
		ipinfoLookupAction: "disabled",
		shortCircuitSource: "none",
		dataSourceMode:     string(mode),
	}
}

func (h *GatewayHandler) extractClientIP(r *http.Request) (string, *policy.Decision, flowState) {
	state := h.newFlowState()
	clientIP, err := h.realIPExtractor.Extract(r)
	if err != nil {
		decision := policy.Decision{Allowed: false, Result: "deny", Reason: "deny_real_ip_extract_failed"}
		return "", &decision, state
	}
	return clientIP, nil, state
}

func (h *GatewayHandler) evaluateBypassChain(r *http.Request, service config.ServiceConfig) evaluationResult {
	state := h.newFlowState()
	clientIP := ""
	if extracted, err := h.realIPExtractor.Extract(r); err == nil {
		clientIP = extracted
	} else if h.logger != nil {
		h.logger.Warn("bypass_real_ip_extract_failed",
			"event", "bypass_real_ip_extract_failed",
			"route_set_kind", "bypass",
			"host", r.Host,
			"path", r.URL.Path,
			"error", err,
		)
	}

	if requestDecision := h.policyEngine.EvaluateRequest(r, service.Name); requestDecision != nil {
		return evaluationResult{
			service:  service,
			clientIP: clientIP,
			decision: *requestDecision,
			state:    state,
		}
	}

	if clientIP == "" {
		return evaluationResult{
			service:  service,
			clientIP: "",
			decision: policy.Decision{Allowed: true, Result: "allow", Reason: "allow_bypass_no_real_ip"},
			state:    state,
		}
	}

	if h.lookupService != nil && h.cfg.IPInfo.Enabled {
		state.ipinfoLookupAction = "start"
		ipContext, cacheSource, lookupAction, lookupErr := h.lookupService.Lookup(r.Context(), clientIP)
		state.cacheSource = cacheSource
		state.ipinfoLookupAction = lookupAction
		if lookupErr != nil {
			return evaluationResult{
				service:   service,
				clientIP:  clientIP,
				ipContext: ipContext,
				decision:  policy.Decision{Allowed: true, Result: "allow", Reason: "allow_bypass_ipinfo_error"},
				state:     state,
			}
		}
		return evaluationResult{
			service:   service,
			clientIP:  clientIP,
			ipContext: ipContext,
			decision:  policy.Decision{Allowed: true, Result: "allow", Reason: "allow_bypass_route"},
			state:     state,
		}
	}

	return evaluationResult{
		service:  service,
		clientIP: clientIP,
		decision: policy.Decision{Allowed: true, Result: "allow", Reason: "allow_bypass_route"},
		state:    state,
	}
}

func (h *GatewayHandler) evaluateV3Chain(r *http.Request, service config.ServiceConfig, rule routesets.CompiledRule) (evaluationResult, routesets.V3PoolTarget, bool) {
	if rule.V3SecurityFilterEnabled {
		outcome := h.evaluateFullChain(r, service)
		if !outcome.decision.Allowed {
			return outcome, routesets.V3PoolTarget{}, false
		}
		selected, err := h.routeRuntime.SelectV3Target(rule, outcome.clientIP)
		if err != nil {
			outcome.decision = policy.Decision{Allowed: false, Result: "deny", Reason: "deny_v3_no_healthy_target"}
			return outcome, routesets.V3PoolTarget{}, false
		}
		outcome.decision.Reason = "allow_v3_redirect"
		return outcome, selected.Target, selected.BindingReused
	}

	state := h.newFlowState()
	clientIP := ""
	if extracted, err := h.realIPExtractor.Extract(r); err == nil {
		clientIP = extracted
	} else if h.logger != nil {
		h.logger.Warn("v3_real_ip_extract_failed",
			"event", "v3_real_ip_extract_failed",
			"route_set_kind", "v3",
			"route_id", rule.ID,
			"host", r.Host,
			"path", r.URL.Path,
			"error", err,
		)
	}

	ipContext := ipctx.Context{}
	reason := "allow_v3_redirect"
	if clientIP == "" {
		reason = "allow_v3_redirect_no_real_ip"
	} else if h.lookupService != nil && h.cfg.IPInfo.Enabled {
		state.ipinfoLookupAction = "start"
		lookupContext, cacheSource, lookupAction, lookupErr := h.lookupService.Lookup(r.Context(), clientIP)
		ipContext = lookupContext
		state.cacheSource = cacheSource
		state.ipinfoLookupAction = lookupAction
		if lookupErr != nil {
			reason = "allow_v3_redirect_with_ipinfo_error"
		}
	}

	selected, err := h.routeRuntime.SelectV3Target(rule, clientIP)
	if err != nil {
		return evaluationResult{
			service:   service,
			clientIP:  clientIP,
			ipContext: ipContext,
			decision:  policy.Decision{Allowed: false, Result: "deny", Reason: "deny_v3_no_healthy_target"},
			state:     state,
		}, routesets.V3PoolTarget{}, false
	}

	return evaluationResult{
		service:   service,
		clientIP:  clientIP,
		ipContext: ipContext,
		decision:  policy.Decision{Allowed: true, Result: "allow", Reason: reason},
		state:     state,
	}, selected.Target, selected.BindingReused
}

func (h *GatewayHandler) evaluateFullChain(r *http.Request, service config.ServiceConfig) evaluationResult {
	clientIP, extractDecision, state := h.extractClientIP(r)
	if extractDecision != nil {
		return evaluationResult{
			service:  service,
			clientIP: "",
			decision: *extractDecision,
			state:    state,
		}
	}

	if requestDecision := h.policyEngine.EvaluateRequest(r, service.Name); requestDecision != nil {
		return evaluationResult{
			service:  service,
			clientIP: clientIP,
			decision: *requestDecision,
			state:    state,
		}
	}

	if h.lookupService != nil && h.cfg.IPInfo.Enabled {
		state.ipinfoLookupAction = "start"
	}

	if h.shortCircuit != nil {
		if record, source, ok := h.shortCircuit.Lookup(r.Context(), clientIP); ok {
			state.shortCircuitHit = true
			state.shortCircuitSource = string(source)
			state.shortCircuitDecision = record.LastDecision
			record = h.shortCircuit.RememberShortCircuitHit(record)
			state.ipinfoLookupAction = "short_circuit_hit"
			if h.metrics != nil {
				h.metrics.ShortCircuit.Inc(metrics.Labels{
					"source":   state.shortCircuitSource,
					"decision": state.shortCircuitDecision,
				})
			}
			return evaluationResult{
				service:   service,
				clientIP:  clientIP,
				ipContext: h.shortCircuit.IPContext(record),
				decision:  h.shortCircuit.Decision(record),
				state:     state,
			}
		}
	}

	var (
		ipContext ipctx.Context
		lookupErr error
	)
	if h.lookupService != nil {
		ipContext, state.cacheSource, state.ipinfoLookupAction, lookupErr = h.lookupService.Lookup(r.Context(), clientIP)
	}

	decision := policy.Decision{Allowed: true, Result: "allow", Reason: "allow_prechecks_passed"}
	if h.cfg.IPInfo.Enabled {
		decision = h.policyEngine.EvaluateIP(ipContext, lookupErr)
	}

	if h.shortCircuit != nil {
		record := h.shortCircuit.RememberDecision(clientIP, r.Host, safeURL(r, h.cfg.Logging.RedactQuery), r.UserAgent(), decision, &ipContext)
		state.shortCircuitDecision = record.LastDecision
	}

	return evaluationResult{
		service:   service,
		clientIP:  clientIP,
		ipContext: ipContext,
		decision:  decision,
		state:     state,
	}
}

func (h *GatewayHandler) finish(w http.ResponseWriter, req *http.Request, requestID string, service config.ServiceConfig, clientIP string, ipContext ipctx.Context, decision policy.Decision, start time.Time, state flowState, routeMeta routeContext, action responseAction) {
	if h.controller != nil {
		state.dataSourceMode = string(h.controller.Mode())
	}
	if decision.AlertType != "" {
		h.enqueueAlert(req, requestID, service.Name, clientIP, state.cacheSource, decision, &ipContext)
	}
	latency := time.Since(start)
	h.observe(service.Name, decision, start)

	record := h.auditRecord(req, requestID, service, clientIP, state.cacheSource, decision, &ipContext, latency, state, routeMeta)
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
	if action.cookie != nil {
		http.SetCookie(w, action.cookie)
	}
	if action.redirectURL != "" {
		status := action.redirectCode
		if status == 0 {
			status = http.StatusFound
		}
		http.Redirect(w, req, action.redirectURL, status)
		return
	}
	h.proxyManager.ServeHTTP(w, req, service, clientIP, &ipContext, action.upstreamHost)
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
		RouteSetKind:         record.RouteSetKind,
		RouteID:              record.RouteID,
		SourceHost:           record.SourceHost,
		TargetHost:           record.TargetHost,
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
		V3SecurityFilterEnabled: record.V3SecurityFilterEnabled,
		V3SelectedTargetID:      record.V3SelectedTargetID,
		V3SelectedTargetHost:    record.V3SelectedTargetHost,
		V3StrategyMode:          record.V3StrategyMode,
		V3BindingReused:         record.V3BindingReused,
		IPInfoLookupAction:      record.IPInfoLookupAction,
		DataSourceMode:          record.DataSourceMode,
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

func (h *GatewayHandler) auditRecord(req *http.Request, requestID string, service config.ServiceConfig, clientIP string, cacheSource ipctx.CacheSource, decision policy.Decision, ipContext *ipctx.Context, latency time.Duration, state flowState, routeMeta routeContext) model.AuditRecord {
	record := model.AuditRecord{
		RequestID:              requestID,
		ClientIP:               clientIP,
		ServiceName:            service.Name,
		UpstreamURL:            service.TargetURL,
		Host:                   req.Host,
		Method:                 req.Method,
		Path:                   req.URL.Path,
		RequestURL:             safeURL(req, h.cfg.Logging.RedactQuery),
		Allowed:                decision.Allowed,
		Result:                 decision.Result,
		ReasonCode:             decision.Reason,
		CacheSource:            cacheSource,
		DataSourceMode:         state.dataSourceMode,
		ShortCircuitHit:        state.shortCircuitHit,
		ShortCircuitSource:     state.shortCircuitSource,
		ShortCircuitDecision:   state.shortCircuitDecision,
		IPInfoLookupAction:     state.ipinfoLookupAction,
		RouteSetKind:           routeMeta.RouteSetKind,
		RouteID:                routeMeta.RouteID,
		SourceHost:             routeMeta.SourceHost,
		SourcePathPrefix:       routeMeta.SourcePathPrefix,
		TargetHost:             routeMeta.TargetHost,
		TargetPublicURL:        routeMeta.TargetPublicURL,
		BackendService:         routeMeta.BackendService,
		BackendHost:            routeMeta.BackendHost,
		GrantStatus:            routeMeta.GrantStatus,
		GrantExpireAt:          routeMeta.GrantExpireAt,
		V3SecurityFilterEnabled: routeMeta.V3SecurityFilterEnabled,
		V3SelectedTargetID:      routeMeta.V3SelectedTargetID,
		V3SelectedTargetHost:    routeMeta.V3SelectedTargetHost,
		V3StrategyMode:          routeMeta.V3StrategyMode,
		V3BindingReused:         routeMeta.V3BindingReused,
		LatencyMS:              float64(latency.Milliseconds()),
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

func (h *GatewayHandler) routeContextFromResolution(resolution routesets.Resolution) routeContext {
	switch resolution.MatchType {
	case routesets.MatchSource:
		return h.routeContextFromRule(resolution.Rule)
	case routesets.MatchTarget:
		return routeContext{
			RouteSetKind:     string(resolution.Binding.RuleKind),
			RouteID:          resolution.Binding.RuleID,
			SourceHost:       resolution.Binding.SourceHost,
			SourcePathPrefix: resolution.Binding.SourcePathPrefix,
			TargetHost:       resolution.Host,
			BackendService:   resolution.Binding.BackendService,
			BackendHost:      resolution.Binding.BackendHost,
			TargetPublicURL:  resolution.Binding.PublicURL,
		}
	default:
		return routeContext{}
	}
}

func (h *GatewayHandler) routeContextFromRule(rule routesets.CompiledRule) routeContext {
	return routeContext{
		RouteSetKind:     string(rule.Kind),
		RouteID:          rule.ID,
		SourceHost:       rule.SourceHost,
		SourcePathPrefix: rule.SourcePathPrefix,
		TargetHost:       rule.TargetHost,
		TargetPublicURL:  rule.TargetPublicURL,
		BackendService:   rule.BackendService,
		BackendHost:      rule.BackendHost,
		V3SecurityFilterEnabled: rule.V3SecurityFilterEnabled,
		V3StrategyMode:          rule.V3StrategyMode,
	}
}

func workerID() string {
	if value := runtimex.WorkerScope(); value != "" {
		return value
	}
	if value := os.Getenv("POD_NAME"); value != "" {
		return value
	}
	if value, err := os.Hostname(); err == nil && value != "" {
		return value
	}
	return "gw-ipinfo-nginx-worker"
}

func resolveLocalStoragePath(path string) string {
	scope := runtimex.WorkerScope()
	if scope == "" {
		return path
	}

	clean := filepath.Clean(path)
	if strings.Contains(clean, scope) {
		return clean
	}

	dir := filepath.Dir(clean)
	base := filepath.Base(clean)
	if dir == "." || dir == "" {
		return filepath.Join(scope, base)
	}
	return filepath.Join(dir, scope, base)
}
