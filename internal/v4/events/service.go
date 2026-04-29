package events

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/v4/repository"
	v4model "gw-ipinfo-nginx/internal/v4/model"
)

type Service struct {
	cfg    config.V4TelegramConfig
	repo   *repository.EventRepository
	sender *alerts.Sender
	logger *slog.Logger
}

func NewService(cfg config.V4TelegramConfig, repo *repository.EventRepository, sender *alerts.Sender, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, repo: repo, sender: sender, logger: logger}
}

func (s *Service) Emit(ctx context.Context, event v4model.Event) error {
	if s == nil || s.repo == nil {
		return nil
	}
	if event.SilentUntil.IsZero() && s.cfg.SilentWindow > 0 {
		event.SilentUntil = time.Now().UTC().Add(s.cfg.SilentWindow)
	}
	storedEvent, err := s.repo.Emit(ctx, event)
	if err != nil {
		return err
	}
	if !s.cfg.Enabled || s.sender == nil || !shouldNotify(storedEvent.Type) {
		return nil
	}
	allowed, reason, err := s.repo.ShouldNotify(ctx, storedEvent, s.cfg.DedupeWindow)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_event_notify_state_error", "event", "v4_event_notify_state_error", "type", storedEvent.Type, "host", storedEvent.Host, "error", err)
		}
		return nil
	}
	if !allowed {
		if err := s.repo.MarkNotificationSuppressed(ctx, storedEvent, reason); err != nil && s.logger != nil {
			s.logger.Warn("v4_event_notify_mark_suppressed_error", "event", "v4_event_notify_mark_suppressed_error", "type", storedEvent.Type, "host", storedEvent.Host, "error", err)
		}
		return nil
	}
	go func(event v4model.Event) {
		sendCtx, cancel := context.WithTimeout(context.Background(), s.senderTimeout())
		sendErr := s.sender.SendText(sendCtx, formatEventMessage(event))
		cancel()
		if sendErr != nil {
			if markErr := s.markNotificationFailed(event, sendErr); markErr != nil && s.logger != nil {
				s.logger.Warn("v4_event_notify_mark_failed_error", "event", "v4_event_notify_mark_failed_error", "type", event.Type, "host", event.Host, "error", markErr)
			}
			if s.logger != nil {
				s.logger.Warn("v4_event_notify_error", "event", "v4_event_notify_error", "type", event.Type, "host", event.Host, "error", sendErr)
			}
			return
		}
		if err := s.markNotificationSent(event); err != nil && s.logger != nil {
			s.logger.Warn("v4_event_notify_mark_sent_error", "event", "v4_event_notify_mark_sent_error", "type", event.Type, "host", event.Host, "error", err)
		}
	}(storedEvent)
	return nil
}

func (s *Service) ListRecent(ctx context.Context, limit int) ([]v4model.Event, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.ListRecent(ctx, limit)
}

func (s *Service) senderTimeout() time.Duration {
	return 5 * time.Second
}

func (s *Service) markNotificationSent(event v4model.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.senderTimeout())
	defer cancel()
	return s.repo.MarkNotificationSent(ctx, event)
}

func (s *Service) markNotificationFailed(event v4model.Event, notifyErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.senderTimeout())
	defer cancel()
	return s.repo.MarkNotificationFailed(ctx, event, notifyErr)
}

func shouldNotify(eventType string) bool {
	switch eventType {
	case v4model.EventTrafficSwitchedToRedirect, v4model.EventTrafficRestoredPassthrough, v4model.EventSnapshotSyncFailed:
		return true
	default:
		return false
	}
}

func formatEventMessage(event v4model.Event) string {
	if text := formatCompactRouteEvent(event); text != "" {
		return text
	}
	lines := []string{
		fmt.Sprintf("Type: %s", event.Type),
		fmt.Sprintf("Host: %s", event.Host),
		fmt.Sprintf("Level: %s", event.Level),
		fmt.Sprintf("Title: %s", event.Title),
		fmt.Sprintf("Message: %s", event.Message),
	}
	return strings.Join(lines, "\n")
}

func formatCompactRouteEvent(event v4model.Event) string {
	switch event.Type {
	case v4model.EventDomainUnhealthy, v4model.EventTrafficSwitchedToRedirect:
		return buildRouteEventMessage(
			"[V4 路由切换 / V4 Route Switch]",
			event.Host,
			"切换到故障跳转 / Switch to failover",
			"已生效 / Applied",
			metadataString(event.Metadata, "source_url"),
			metadataString(event.Metadata, "redirect_url"),
			metadataStrings(event.Metadata, "failed_urls", "target_urls"),
			metadataString(event.Metadata, "reason"),
		)
	case v4model.EventDomainRecovered, v4model.EventTrafficRestoredPassthrough:
		return buildRouteEventMessage(
			"[V4 路由恢复 / V4 Route Restore]",
			event.Host,
			"恢复原始透传 / Restore passthrough",
			"已恢复 / Restored",
			metadataString(event.Metadata, "source_url"),
			metadataString(event.Metadata, "redirect_url"),
			metadataStrings(event.Metadata, "target_urls", "failed_urls"),
			firstNonEmptyText(metadataString(event.Metadata, "reason"), "探测恢复正常 / Health check recovered"),
		)
	default:
		return ""
	}
}

func buildRouteEventMessage(header, host, action, result, sourceURL, redirectURL string, targetURLs []string, reason string) string {
	lines := []string{header}
	lines = append(lines, fmt.Sprintf("域名 / Host: %s", strings.TrimSpace(host)))
	lines = append(lines, fmt.Sprintf("动作 / Action: %s", strings.TrimSpace(action)))
	lines = append(lines, fmt.Sprintf("结果 / Result: %s", strings.TrimSpace(result)))
	if sourceURL != "" {
		lines = append(lines, fmt.Sprintf("原始URL / Source URL: %s", sourceURL))
	}
	if redirectURL != "" {
		lines = append(lines, fmt.Sprintf("故障跳转 / Failover URL: %s", redirectURL))
	}
	if len(targetURLs) > 0 {
		lines = append(lines, fmt.Sprintf("目标URL / Target URL: %s", strings.Join(limitStrings(targetURLs, 3), " | ")))
	}
	if reason != "" {
		lines = append(lines, fmt.Sprintf("原因 / Reason: %s", reason))
	}
	return strings.Join(lines, "\n")
}

func metadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	switch value := metadata[key].(type) {
	case string:
		return strings.TrimSpace(value)
	}
	return ""
}

func metadataStrings(metadata map[string]any, keys ...string) []string {
	for _, key := range keys {
		values := collectMetadataStrings(metadata[key])
		if len(values) > 0 {
			return values
		}
	}
	return nil
}

func collectMetadataStrings(value any) []string {
	switch current := value.(type) {
	case []string:
		return limitStrings(current, 3)
	case []any:
		values := make([]string, 0, len(current))
		for _, item := range current {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				values = append(values, strings.TrimSpace(text))
			}
		}
		return limitStrings(values, 3)
	default:
		return nil
	}
}

func limitStrings(values []string, limit int) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		cleaned = append(cleaned, value)
		if limit > 0 && len(cleaned) >= limit {
			break
		}
	}
	return cleaned
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
