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
	inserted, err := s.repo.Emit(ctx, event, s.cfg.DedupeWindow)
	if err != nil {
		return err
	}
	if !inserted || !s.cfg.Enabled || s.sender == nil {
		return nil
	}
	go func() {
		sendCtx, cancel := context.WithTimeout(context.Background(), s.senderTimeout())
		defer cancel()
		if err := s.sender.SendText(sendCtx, formatEventMessage(event)); err != nil && s.logger != nil {
			s.logger.Warn("v4_event_notify_error", "event", "v4_event_notify_error", "type", event.Type, "host", event.Host, "error", err)
		}
	}()
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

func formatEventMessage(event v4model.Event) string {
	lines := []string{
		fmt.Sprintf("type: %s", event.Type),
		fmt.Sprintf("host: %s", event.Host),
		fmt.Sprintf("level: %s", event.Level),
		fmt.Sprintf("title: %s", event.Title),
		fmt.Sprintf("message: %s", event.Message),
	}
	if len(event.Metadata) > 0 {
		lines = append(lines, fmt.Sprintf("metadata: %v", event.Metadata))
	}
	return strings.Join(lines, "\n")
}
