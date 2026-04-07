package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"net/textproto"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
)

type Sender struct {
	apiBaseURL *url.URL
	botToken   string
	chatID     string
	parseMode  string
	client     *http.Client
}

func NewSender(cfg config.TelegramConfig) (*Sender, error) {
	baseURL, err := url.Parse(cfg.APIBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse telegram api base url: %w", err)
	}
	return &Sender{
		apiBaseURL: baseURL,
		botToken:   cfg.BotToken,
		chatID:     cfg.ChatID,
		parseMode:  cfg.ParseMode,
		client:     &http.Client{Timeout: cfg.Timeout},
	}, nil
}

func (s *Sender) Send(ctx context.Context, payload Payload) error {
	requestURL := s.apiBaseURL.ResolveReference(&url.URL{Path: fmt.Sprintf("/bot%s/sendMessage", s.botToken)})
	body := telegramRequest{
		ChatID:                s.chatID,
		Text:                  formatTelegramMessage(payload),
		ParseMode:             s.parseMode,
		DisableWebPagePreview: true,
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal telegram request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("telegram http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (s *Sender) SendDocument(ctx context.Context, fileName, contentType string, data []byte, caption string) error {
	requestURL := s.apiBaseURL.ResolveReference(&url.URL{Path: fmt.Sprintf("/bot%s/sendDocument", s.botToken)})
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if err := writer.WriteField("chat_id", s.chatID); err != nil {
		return fmt.Errorf("write telegram chat_id: %w", err)
	}
	if caption != "" {
		if err := writer.WriteField("caption", caption); err != nil {
			return fmt.Errorf("write telegram caption: %w", err)
		}
	}
	if s.parseMode != "" {
		if err := writer.WriteField("parse_mode", s.parseMode); err != nil {
			return fmt.Errorf("write telegram parse_mode: %w", err)
		}
	}
	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", fmt.Sprintf(`form-data; name="document"; filename="%s"`, fileName))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	headers.Set("Content-Type", contentType)
	part, err := writer.CreatePart(headers)
	if err != nil {
		return fmt.Errorf("create telegram document part: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("write telegram document: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close telegram multipart: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), body)
	if err != nil {
		return fmt.Errorf("build telegram document request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram document request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("telegram document http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

type telegramRequest struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func formatTelegramMessage(payload Payload) string {
	lines := []string{
		fmt.Sprintf("notify_type: %s", payload.NotifyType),
		fmt.Sprintf("severity: %s", payload.Severity),
		fmt.Sprintf("action: %s", payload.FinalAction),
		fmt.Sprintf("reason: %s", payload.Reason),
		fmt.Sprintf("client_ip: %s", payload.ClientIP),
		fmt.Sprintf("service: %s", payload.ServiceName),
		fmt.Sprintf("method: %s", payload.Method),
		fmt.Sprintf("url: %s", payload.URL),
		fmt.Sprintf("country: %s", payload.CountryCode),
		fmt.Sprintf("city: %s", payload.City),
		fmt.Sprintf("cache_source: %s", payload.CacheSource),
		fmt.Sprintf("request_id: %s", payload.RequestID),
		fmt.Sprintf("timestamp: %s", payload.Timestamp.Format(time.RFC3339)),
		fmt.Sprintf("privacy: vpn=%t proxy=%t tor=%t relay=%t hosting=%t resproxy=%t service=%s",
			payload.Privacy.VPN,
			payload.Privacy.Proxy,
			payload.Privacy.Tor,
			payload.Privacy.Relay,
			payload.Privacy.Hosting,
			payload.Privacy.ResidentialProxy,
			payload.Privacy.Service,
		),
	}
	if payload.UserAgent != "" {
		lines = append(lines, fmt.Sprintf("user_agent: %s", payload.UserAgent))
	}
	return strings.Join(lines, "\n")
}
