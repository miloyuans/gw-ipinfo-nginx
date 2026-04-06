package alerts

import (
	"context"
	"log/slog"
	"math"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/metrics"
)

type Worker struct {
	logger   *slog.Logger
	repo     *Repository
	sender   *Sender
	cfg      config.DeliveryConfig
	metrics  *metrics.GatewayMetrics
	workerID string
}

func NewWorker(logger *slog.Logger, repo *Repository, sender *Sender, cfg config.DeliveryConfig, metricsSet *metrics.GatewayMetrics, workerID string) *Worker {
	return &Worker{
		logger:   logger,
		repo:     repo,
		sender:   sender,
		cfg:      cfg,
		metrics:  metricsSet,
		workerID: workerID,
	}
}

func (w *Worker) Run(ctx context.Context) error {
	if w.repo == nil || w.sender == nil {
		return nil
	}

	pollTicker := time.NewTicker(w.cfg.PollInterval)
	defer pollTicker.Stop()

	var rateLimiter <-chan time.Time
	if w.cfg.RateLimitPerSecond > 0 {
		interval := time.Second / time.Duration(w.cfg.RateLimitPerSecond)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pollTicker.C:
			messages, err := w.repo.Claim(ctx, w.workerID, w.cfg.BatchSize, w.cfg.MaxAttempts, w.cfg.ClaimLease)
			if err != nil {
				w.logger.Error("claim alerts", "error", err)
				continue
			}
			for _, message := range messages {
				if rateLimiter != nil {
					select {
					case <-ctx.Done():
						return nil
					case <-rateLimiter:
					}
				}

				sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := w.sender.Send(sendCtx, message.Payload)
				cancel()
				if err == nil {
					if markErr := w.repo.MarkSent(ctx, message.ID); markErr != nil {
						w.logger.Error("mark alert sent", "error", markErr, "message_id", message.ID.Hex())
					}
					if w.metrics != nil {
						w.metrics.AlertDelivery.Inc(metrics.Labels{"type": labelType(message), "status": "sent"})
					}
					continue
				}

				attempts := message.Attempts + 1
				dead := attempts >= w.cfg.MaxAttempts
				if markErr := w.repo.MarkRetry(ctx, message.ID, attempts, time.Now().UTC().Add(backoff(w.cfg, attempts)), err.Error(), dead); markErr != nil {
					w.logger.Error("mark alert retry", "error", markErr, "message_id", message.ID.Hex())
				}
				if w.metrics != nil {
					status := "retry"
					if dead {
						status = "dead"
					}
					w.metrics.AlertDelivery.Inc(metrics.Labels{"type": labelType(message), "status": status})
				}
			}
		}
	}
}

func backoff(cfg config.DeliveryConfig, attempt int) time.Duration {
	value := float64(cfg.BaseBackoff) * math.Pow(2, float64(attempt-1))
	delay := time.Duration(value)
	if delay > cfg.MaxBackoff {
		return cfg.MaxBackoff
	}
	return delay
}

func labelType(message OutboxMessage) string {
	if message.NotifyType != "" {
		return message.NotifyType
	}
	return message.Type
}
