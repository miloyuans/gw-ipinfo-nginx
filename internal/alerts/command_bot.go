package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipinfo"
	"gw-ipinfo-nginx/internal/storage"
	v4query "gw-ipinfo-nginx/internal/v4/query"
)

type CommandBot struct {
	cfg             config.TelegramCommandBotConfig
	logger          *slog.Logger
	client          *telegramBotClient
	lookupService   *ipinfo.LookupService
	queryCounter    *queryOrdinalTracker
	routesQuery     *v4query.Service
	routesCfg       config.V4TelegramConfig
	stateStore      *commandBotStateStore
	instanceID      string
	allowedChatID   int64
	allowedUserIDs  map[int64]struct{}
}

type telegramBotClient struct {
	baseURL   *url.URL
	botToken  string
	parseMode string
	client    *http.Client
}

type updateResponse struct {
	OK     bool         `json:"ok"`
	Result []botUpdate  `json:"result"`
}

type botUpdate struct {
	UpdateID int         `json:"update_id"`
	Message  *botMessage `json:"message"`
}

type botMessage struct {
	MessageID int      `json:"message_id"`
	Text      string   `json:"text"`
	Chat      botChat  `json:"chat"`
	From      *botUser `json:"from"`
}

type botChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type botUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type sendMessageRequest struct {
	ChatID                int64  `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
	ReplyToMessageID      int    `json:"reply_to_message_id,omitempty"`
}

type commandQueryResult struct {
	ip               string
	details          ipinfo.LookupDetails
	cacheSource      string
	lookupAction     string
	dataSourceMode   string
	queryOrdinal     uint64
	err              error
}

type queryOrdinalTracker struct {
	values sync.Map
}

type queryOrdinalValue struct {
	value uint64
}

func NewCommandBot(cfg config.TelegramCommandBotConfig, logger *slog.Logger, lookupService *ipinfo.LookupService, controller *storage.Controller, statePath string, instanceID string) (*CommandBot, error) {
	baseURL, err := url.Parse(cfg.APIBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse telegram command bot api base url: %w", err)
	}
	chatID, err := strconv.ParseInt(strings.TrimSpace(cfg.ChatID), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse telegram command bot chat id: %w", err)
	}
	httpTimeout := cfg.Timeout
	if cfg.PollTimeout+5*time.Second > httpTimeout {
		httpTimeout = cfg.PollTimeout + 5*time.Second
	}

	allowedUserIDs := make(map[int64]struct{}, len(cfg.AllowedUserIDs))
	for _, userID := range cfg.AllowedUserIDs {
		allowedUserIDs[userID] = struct{}{}
	}

	return &CommandBot{
		cfg:    cfg,
		logger: logger,
		client: &telegramBotClient{
			baseURL:   baseURL,
			botToken:  cfg.BotToken,
			parseMode: cfg.ParseMode,
			client:    &http.Client{Timeout: httpTimeout},
		},
		lookupService:  lookupService,
		queryCounter:   newQueryOrdinalTracker(),
		stateStore:     newCommandBotStateStore(controller, statePath, cfg.LeaseName),
		instanceID:     instanceID,
		allowedChatID:  chatID,
		allowedUserIDs: allowedUserIDs,
	}, nil
}

func (b *CommandBot) AttachV4Query(cfg config.V4TelegramConfig, service *v4query.Service) {
	if b == nil {
		return
	}
	b.routesCfg = cfg
	b.routesQuery = service
}

func (b *CommandBot) Run(ctx context.Context) error {
	if b == nil || b.client == nil || b.lookupService == nil || !b.cfg.Enabled {
		return nil
	}
	if b.logger != nil {
		b.logger.Info("telegram_command_bot_started",
			"event", "telegram_command_bot_started",
			"command", b.cfg.Command,
			"allowed_chat_id", b.allowedChatID,
			"poll_timeout", b.cfg.PollTimeout,
			"timeout", b.cfg.Timeout,
			"lease_name", b.cfg.LeaseName,
			"lease_ttl", b.cfg.LeaseTTL,
			"renew_interval", b.cfg.RenewInterval,
		)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		lease, acquired, err := b.stateStore.TryAcquire(ctx, b.instanceID, time.Now().UTC(), b.cfg.LeaseTTL)
		if err != nil {
			if b.logger != nil {
				b.logger.Warn("telegram_command_bot_lease_error",
					"event", "telegram_command_bot_lease_error",
					"lease_name", b.cfg.LeaseName,
					"error", err,
				)
			}
			if !sleepContext(ctx, b.cfg.ErrorBackoff) {
				return nil
			}
			continue
		}
		if !acquired {
			if !sleepContext(ctx, b.cfg.RenewInterval) {
				return nil
			}
			continue
		}

		if b.logger != nil {
			b.logger.Info("telegram_command_bot_leader_acquired",
				"event", "telegram_command_bot_leader_acquired",
				"lease_name", b.cfg.LeaseName,
				"instance_id", b.instanceID,
				"offset", lease.Offset,
			)
		}

		offset := lease.Offset
		effectivePollTimeout := b.cfg.PollTimeout
		if b.cfg.RenewInterval > 0 && b.cfg.RenewInterval < effectivePollTimeout {
			effectivePollTimeout = b.cfg.RenewInterval
		}
		for {
			select {
			case <-ctx.Done():
				_ = b.stateStore.Release(context.Background(), b.instanceID)
				return nil
			default:
			}

			loopCtx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
			updates, err := b.client.getUpdates(loopCtx, effectivePollTimeout, offset)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					_ = b.stateStore.Release(context.Background(), b.instanceID)
					return nil
				}
				if b.logger != nil {
					b.logger.Warn("telegram_command_bot_get_updates_error",
						"event", "telegram_command_bot_get_updates_error",
						"error", err,
						"instance_id", b.instanceID,
					)
				}
				ok, renewErr := b.stateStore.Refresh(ctx, b.instanceID, offset, time.Now().UTC(), b.cfg.LeaseTTL)
				if renewErr != nil || !ok {
					if b.logger != nil {
						b.logger.Warn("telegram_command_bot_leader_lost",
							"event", "telegram_command_bot_leader_lost",
							"instance_id", b.instanceID,
							"error", renewErr,
						)
					}
					break
				}
				if !sleepContext(ctx, b.cfg.ErrorBackoff) {
					_ = b.stateStore.Release(context.Background(), b.instanceID)
					return nil
				}
				continue
			}

			for _, update := range updates {
				offset = update.UpdateID + 1
				if update.Message == nil {
					continue
				}
				b.handleMessage(ctx, update.Message)
			}

			ok, renewErr := b.stateStore.Refresh(ctx, b.instanceID, offset, time.Now().UTC(), b.cfg.LeaseTTL)
			if renewErr != nil || !ok {
				if b.logger != nil {
					b.logger.Warn("telegram_command_bot_leader_lost",
						"event", "telegram_command_bot_leader_lost",
						"instance_id", b.instanceID,
						"error", renewErr,
					)
				}
				break
			}
		}
	}
}

func (b *CommandBot) handleMessage(ctx context.Context, message *botMessage) {
	if message == nil {
		return
	}
	if message.Chat.Type == "private" && b.cfg.DisablePrivateChat {
		return
	}
	if message.Chat.ID != b.allowedChatID {
		if b.cfg.ReplyUnauthorizedChat {
			if err := b.client.sendHTML(ctx, message.Chat.ID, wrapPre(b.cfg.Templates.UnauthorizedChat), 0); err != nil && b.logger != nil {
				b.logger.Warn("telegram_command_bot_send_error",
					"event", "telegram_command_bot_send_error",
					"chat_id", message.Chat.ID,
					"error", err,
				)
			}
		}
		return
	}
	if len(b.allowedUserIDs) > 0 {
		if message.From == nil {
			return
		}
		if _, ok := b.allowedUserIDs[message.From.ID]; !ok {
			_ = b.client.sendHTML(ctx, b.allowedChatID, wrapPre(b.cfg.Templates.UnauthorizedUser), message.MessageID)
			return
		}
	}

	text := strings.TrimSpace(message.Text)
	if text == "" {
		return
	}
	queryCtx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	if b.routesQuery != nil && b.routesCfg.Enabled && matchesCommand(text, b.routesCfg.Command) {
		b.handleRoutesQuery(queryCtx, message)
		return
	}
	if !matchesCommand(text, b.cfg.Command) {
		return
	}

	ips := parseIPsFromCommand(text)
	if len(ips) == 0 {
		usage := fmt.Sprintf(b.cfg.Templates.Usage, b.cfg.Command, b.cfg.Command, b.cfg.Command)
		_ = b.client.sendHTML(queryCtx, b.allowedChatID, wrapPre(usage), message.MessageID)
		return
	}

	notice := ""
	if len(ips) > b.cfg.MaxIPsPerRequest {
		ips = ips[:b.cfg.MaxIPsPerRequest]
		notice = fmt.Sprintf(b.cfg.Templates.TooManyIPs, b.cfg.MaxIPsPerRequest)
	}

	output := b.handleQuery(queryCtx, ips)
	if notice != "" {
		output = wrapPre(notice) + "\n\n" + output
	}
	if strings.TrimSpace(output) == "" {
		output = wrapPre(b.cfg.Templates.EmptyResult)
	}

	chunks := chunkForTelegramHTML(output, b.cfg.MessageChunkSize)
	for idx, chunk := range chunks {
		replyTo := 0
		if idx == 0 {
			replyTo = message.MessageID
		}
		if err := b.client.sendHTML(queryCtx, b.allowedChatID, chunk, replyTo); err != nil {
			if b.logger != nil {
				b.logger.Warn("telegram_command_bot_send_error",
					"event", "telegram_command_bot_send_error",
					"chat_id", b.allowedChatID,
					"error", err,
				)
			}
			return
		}
	}
}

func (b *CommandBot) handleRoutesQuery(ctx context.Context, message *botMessage) {
	if b.routesQuery == nil {
		return
	}
	result, err := b.routesQuery.BuildRoutesSummary(ctx)
	if err != nil {
		_ = b.client.sendHTML(ctx, b.allowedChatID, wrapPre("路由摘要查询失败。\nRoute summary query failed.\n"+err.Error()), message.MessageID)
		return
	}
	replyTo := message.MessageID
	if strings.TrimSpace(result.SummaryHTML) != "" {
		if err := b.client.sendHTML(ctx, b.allowedChatID, result.SummaryHTML, replyTo); err != nil {
			if b.logger != nil {
				b.logger.Warn("telegram_command_bot_send_error", "event", "telegram_command_bot_send_error", "chat_id", b.allowedChatID, "error", err)
			}
			return
		}
		replyTo = 0
	}
	if len(result.FileContent) > 0 && result.FileName != "" {
		if err := b.client.sendDocument(ctx, b.allowedChatID, result.FileName, result.ContentType, result.FileContent, "V4 routes summary", replyTo); err != nil && b.logger != nil {
			b.logger.Warn("telegram_command_bot_send_error", "event", "telegram_command_bot_send_error", "chat_id", b.allowedChatID, "error", err)
		}
	}
}

func (b *CommandBot) handleQuery(ctx context.Context, ips []string) string {
	maxConcurrent := b.cfg.MaxConcurrentLookups
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	sem := make(chan struct{}, maxConcurrent)
	results := make([]commandQueryResult, len(ips))
	var wg sync.WaitGroup

	for idx, ipValue := range ips {
		wg.Add(1)
		go func(index int, rawIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ip := net.ParseIP(strings.TrimSpace(rawIP))
			if ip == nil {
				results[index] = commandQueryResult{
					ip:  rawIP,
					err: fmt.Errorf("非法 IP：%s", rawIP),
				}
				return
			}

			normalizedIP := ip.String()
			queryOrdinal := b.queryCounter.Next(normalizedIP)
			details, cacheSource, lookupAction, err := b.lookupService.LookupDetails(ctx, normalizedIP)
			mode := "localdisk"
			if b.stateStore != nil && b.stateStore.controller != nil {
				mode = string(b.stateStore.controller.Mode())
			}
			results[index] = commandQueryResult{
				ip:             normalizedIP,
				details:        details,
				cacheSource:    string(cacheSource),
				lookupAction:   lookupAction,
				dataSourceMode: mode,
				queryOrdinal:   queryOrdinal,
				err:            err,
			}
		}(idx, ipValue)
	}

	wg.Wait()

	var output strings.Builder
	for _, result := range results {
		output.WriteString("\n")
		output.WriteString("<b>IP:</b> ")
		output.WriteString(html.EscapeString(result.ip))
		output.WriteString("\n")

		if result.err != nil {
			output.WriteString(wrapPre("ERROR: " + result.err.Error()))
			output.WriteString("\n")
			continue
		}

		output.WriteString(formatLookupDetailsHTML(result.details))
		if result.lookupAction != "" || result.cacheSource != "" {
			output.WriteString(formatLookupSummaryHTML(result.cacheSource, result.lookupAction, result.dataSourceMode, result.queryOrdinal))
		}
		output.WriteString("\n")
	}

	return strings.TrimSpace(output.String())
}

func newQueryOrdinalTracker() *queryOrdinalTracker {
	return &queryOrdinalTracker{}
}

func (t *queryOrdinalTracker) Next(ip string) uint64 {
	if t == nil {
		return 0
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return 0
	}
	value, _ := t.values.LoadOrStore(ip, &queryOrdinalValue{})
	counter := value.(*queryOrdinalValue)
	return atomic.AddUint64(&counter.value, 1)
}

func formatLookupSummaryHTML(cacheSource, lookupAction, dataSourceMode string, ordinal uint64) string {
	zhSource, enSource, zhAction, enAction := classifyLookupSummary(cacheSource, lookupAction)
	zhMode, enMode := describeLookupMode(dataSourceMode)
	zhOrdinal, enOrdinal := formatQueryOrdinal(ordinal)

	zhLine := fmt.Sprintf("数据来源 %s，%s，%s%s", zhSource, zhOrdinal, zhMode, zhAction)
	enLine := fmt.Sprintf("Source: %s, %s, %s %s", enSource, enOrdinal, enMode, enAction)

	return fmt.Sprintf(
		"<b>%s</b>\n%s\n%s\n",
		html.EscapeString("查询摘要 / Lookup Summary"),
		html.EscapeString(zhLine),
		html.EscapeString(enLine),
	)
}

func classifyLookupSummary(cacheSource, lookupAction string) (string, string, string, string) {
	action := strings.TrimSpace(strings.ToLower(lookupAction))
	source := strings.TrimSpace(strings.ToLower(cacheSource))

	switch {
	case action == "cache_hit_l1" || source == "l1":
		return "L1 缓存", "L1 cache", "缓存命中", "cache hit"
	case action == "cache_hit_mongo" || action == "cache_hit_localdisk" || source == "mongo" || source == "localdisk":
		return "DB 缓存", "DB cache", "数据库命中", "database hit"
	case action == "remote_success" || action == "remote_error" || source == "ipinfo":
		return "IPinfo", "IPinfo", "API", "API"
	default:
		return "DB 缓存", "DB cache", "缓存命中", "cache hit"
	}
}

func describeLookupMode(mode string) (string, string) {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "localdisk":
		return "本地模式", "Local mode"
	case "mongo":
		return "DB 模式", "DB mode"
	default:
		return "混合模式", "Hybrid mode"
	}
}

func formatQueryOrdinal(n uint64) (string, string) {
	if n <= 1 {
		return "首次查询", "First query"
	}
	return fmt.Sprintf("第 %d 次查询", n), fmt.Sprintf("%s query", englishOrdinal(n))
}

func englishOrdinal(n uint64) string {
	if n%100 >= 11 && n%100 <= 13 {
		return fmt.Sprintf("%dth", n)
	}
	switch n % 10 {
	case 1:
		return fmt.Sprintf("%dst", n)
	case 2:
		return fmt.Sprintf("%dnd", n)
	case 3:
		return fmt.Sprintf("%drd", n)
	default:
		return fmt.Sprintf("%dth", n)
	}
}

func formatLookupDetailsHTML(details ipinfo.LookupDetails) string {
	country := "-"
	region := "-"
	city := "-"
	asName := "-"
	hostname := "-"
	asn := "-"
	asType := "-"
	asDomain := "-"

	if strings.TrimSpace(details.Hostname) != "" {
		hostname = details.Hostname
	}
	if details.Geo != nil {
		if details.Geo.Country != "" {
			if details.Geo.CountryCode != "" {
				country = fmt.Sprintf("%s (%s)", details.Geo.Country, details.Geo.CountryCode)
			} else {
				country = details.Geo.Country
			}
		}
		if details.Geo.Region != "" {
			region = details.Geo.Region
		}
		if details.Geo.City != "" {
			city = details.Geo.City
		}
	}
	if details.AS != nil {
		if details.AS.Name != "" {
			asName = details.AS.Name
		}
		if details.AS.ASN != "" {
			asn = details.AS.ASN
		}
		if details.AS.Type != "" {
			asType = details.AS.Type
		}
		if details.AS.Domain != "" {
			asDomain = details.AS.Domain
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("• Country（国家）: %s\n", html.EscapeString(country)))
	sb.WriteString(fmt.Sprintf("• Region（地区）: %s\n", html.EscapeString(region)))
	sb.WriteString(fmt.Sprintf("• City（城市）: %s\n", html.EscapeString(city)))
	sb.WriteString(fmt.Sprintf("• AS Name（网络组织）: %s\n", html.EscapeString(asName)))

	if hostname != "-" {
		sb.WriteString(fmt.Sprintf("• Hostname（主机名）: %s\n", html.EscapeString(hostname)))
	}
	if asn != "-" {
		sb.WriteString(fmt.Sprintf("• ASN（自治系统号）: %s\n", html.EscapeString(asn)))
	}
	if asType != "-" {
		sb.WriteString(fmt.Sprintf("• AS Type（网络类型）: %s\n", html.EscapeString(asType)))
	}
	if asDomain != "-" {
		sb.WriteString(fmt.Sprintf("• AS Domain（组织域名）: %s\n", html.EscapeString(asDomain)))
	}

	if details.Anonymous != nil {
		if strings.TrimSpace(details.Anonymous.Name) != "" {
			sb.WriteString(fmt.Sprintf("• Anonymous Provider（匿名服务商）: %s\n", html.EscapeString(details.Anonymous.Name)))
		}
		if strings.TrimSpace(details.Anonymous.LastSeen) != "" {
			sb.WriteString(fmt.Sprintf("• Anonymous Last Seen（最近发现时间）: %s\n", html.EscapeString(details.Anonymous.LastSeen)))
		}
		if details.Anonymous.PercentDaysSeen > 0 {
			sb.WriteString(fmt.Sprintf("• Anonymous Percent Days Seen（出现天数占比）: %d%%\n", details.Anonymous.PercentDaysSeen))
		}
		if details.Anonymous.IsProxy {
			sb.WriteString("• Proxy（代理）: Yes\n")
		}
		if details.Anonymous.IsRelay {
			sb.WriteString("• Relay（中继）: Yes\n")
		}
		if details.Anonymous.IsTor {
			sb.WriteString("• Tor（洋葱网络出口）: Yes\n")
		}
		if details.Anonymous.IsVPN {
			sb.WriteString("• VPN（虚拟专用网络）: Yes\n")
		}
		if details.Anonymous.IsResProxy {
			sb.WriteString("• Residential Proxy（住宅代理）: Yes\n")
		}
	}

	if details.IsAnonymous {
		sb.WriteString("• Anonymous（匿名流量）: Yes\n")
	}
	if details.IsAnycast {
		sb.WriteString("• Anycast（全球广播）: Yes\n")
	}
	if details.IsHosting {
		sb.WriteString("• Hosting（机房/托管）: Yes\n")
	}
	if details.IsMobile {
		sb.WriteString("• Mobile（移动网 IP）: Yes\n")
	}
	if details.IsSatellite {
		sb.WriteString("• Satellite（卫星网络）: Yes\n")
	}

	return sb.String()
}

func matchesCommand(text, command string) bool {
	command = strings.TrimSpace(command)
	if command == "" || !strings.HasPrefix(command, "/") {
		return false
	}
	if !strings.HasPrefix(text, command) {
		return false
	}
	if len(text) == len(command) {
		return true
	}
	rest := text[len(command):]
	if rest == "" {
		return true
	}
	switch rest[0] {
	case '@', ' ', '\n', '\t', '\r':
		return true
	default:
		return false
	}
}

func parseIPsFromCommand(text string) []string {
	parts := strings.Fields(strings.TrimSpace(text))
	if len(parts) == 0 {
		return nil
	}
	candidates := parts[1:]
	ips := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.Trim(strings.TrimSpace(candidate), ",;")
		if candidate == "" {
			continue
		}
		ips = append(ips, candidate)
	}
	return ips
}

func chunkForTelegramHTML(value string, max int) []string {
	if max <= 0 || len(value) <= max {
		return []string{value}
	}

	plain := strings.TrimSpace(stripHTMLVeryRough(value))
	if plain == "" {
		return []string{value}
	}

	chunks := make([]string, 0, (len(plain)/max)+1)
	for len(plain) > 0 {
		size := max
		if len(plain) < size {
			size = len(plain)
		}
		part := plain[:size]
		plain = plain[size:]
		chunks = append(chunks, wrapPre(part))
	}
	return chunks
}

func stripHTMLVeryRough(value string) string {
	replacer := strings.NewReplacer(
		"<b>", "", "</b>", "",
		"<pre>", "", "</pre>", "",
		"<code>", "", "</code>", "",
	)
	return replacer.Replace(value)
}

func wrapPre(value string) string {
	return "<pre>" + html.EscapeString(value) + "</pre>"
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *telegramBotClient) getUpdates(ctx context.Context, timeout time.Duration, offset int) ([]botUpdate, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/bot%s/getUpdates", c.botToken),
	})
	query := requestURL.Query()
	query.Set("timeout", strconv.Itoa(int(timeout.Seconds())))
	query.Set("offset", strconv.Itoa(offset))
	requestURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build getUpdates request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send getUpdates request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("read getUpdates response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("getUpdates http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var decoded updateResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode getUpdates response: %w", err)
	}
	if !decoded.OK {
		return nil, fmt.Errorf("getUpdates returned ok=false")
	}
	return decoded.Result, nil
}

func (c *telegramBotClient) sendHTML(ctx context.Context, chatID int64, htmlText string, replyTo int) error {
	requestURL := c.baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/bot%s/sendMessage", c.botToken),
	})
	payload := sendMessageRequest{
		ChatID:                chatID,
		Text:                  htmlText,
		ParseMode:             c.parseMode,
		DisableWebPagePreview: true,
	}
	if replyTo != 0 {
		payload.ReplyToMessageID = replyTo
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal sendMessage request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build sendMessage request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send sendMessage request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sendMessage http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *telegramBotClient) sendDocument(ctx context.Context, chatID int64, fileName, contentType string, data []byte, caption string, replyTo int) error {
	requestURL := c.baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/bot%s/sendDocument", c.botToken),
	})
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if err := writer.WriteField("chat_id", strconv.FormatInt(chatID, 10)); err != nil {
		return fmt.Errorf("write document chat_id: %w", err)
	}
	if caption != "" {
		if err := writer.WriteField("caption", caption); err != nil {
			return fmt.Errorf("write document caption: %w", err)
		}
	}
	if c.parseMode != "" {
		if err := writer.WriteField("parse_mode", c.parseMode); err != nil {
			return fmt.Errorf("write document parse_mode: %w", err)
		}
	}
	if replyTo != 0 {
		if err := writer.WriteField("reply_to_message_id", strconv.Itoa(replyTo)); err != nil {
			return fmt.Errorf("write document reply_to: %w", err)
		}
	}
	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", fmt.Sprintf(`form-data; name="document"; filename="%s"`, fileName))
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}
	headers.Set("Content-Type", contentType)
	part, err := writer.CreatePart(headers)
	if err != nil {
		return fmt.Errorf("create document part: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("write document data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close document body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), body)
	if err != nil {
		return fmt.Errorf("build sendDocument request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send sendDocument request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sendDocument http %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}
