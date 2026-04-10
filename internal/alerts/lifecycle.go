package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/runtimestate"
)

type LifecycleManager struct {
	cfg       config.TelegramConfig
	sender    *Sender
	logger    *slog.Logger
	instanceID string
	hostname  string
	stateFile *runtimestate.File
}

func NewLifecycleManager(cfg config.TelegramConfig, sender *Sender, logger *slog.Logger, instanceID, hostname, statePath string) *LifecycleManager {
	return &LifecycleManager{
		cfg:        cfg,
		sender:     sender,
		logger:     logger,
		instanceID: instanceID,
		hostname:   hostname,
		stateFile:  runtimestate.New(statePath),
	}
}

func (m *LifecycleManager) Startup(ctx context.Context, reportsEnabled, alertsEnabled bool) {
	if m == nil {
		return
	}
	previous, err := m.stateFile.Load()
	unclean := err == nil && !previous.CleanShutdown
	if unclean && m.logger != nil {
		m.logger.Warn("telegram_unclean_exit_detected",
			"event", "telegram_unclean_exit_detected",
			"hostname", m.hostname,
			"instance_id", m.instanceID,
			"path", m.stateFile.Path(),
		)
	}

	_ = m.stateFile.Save(runtimestate.Snapshot{
		StartedAt:     time.Now().UTC(),
		Hostname:      m.hostname,
		PID:           pid(),
		InstanceID:    m.instanceID,
		CleanShutdown: false,
	})

	if !m.cfg.Enabled || m.sender == nil {
		return
	}

	if m.cfg.Lifecycle.SelfCheckOnStart {
		go m.selfCheck(reportsEnabled, alertsEnabled)
	} else if m.cfg.Lifecycle.StartupNotify {
		go m.sendStartupNotify(reportsEnabled, alertsEnabled)
	}

	if unclean && m.cfg.Lifecycle.UncleanExitNotify && m.cfg.Lifecycle.NotifyMode == "notify" {
		go m.sendTextWithLog(
			"telegram_unclean_exit_notify_sent",
			"telegram_unclean_exit_notify_error",
			m.formatMessage("Recovered After Unclean Exit", reportsEnabled, alertsEnabled),
		)
	}

	if m.cfg.Lifecycle.HeartbeatEnabled {
		go m.runHeartbeat(ctx, reportsEnabled, alertsEnabled)
	}
}

func (m *LifecycleManager) Shutdown(ctx context.Context) {
	if m == nil {
		return
	}
	_ = m.stateFile.Save(runtimestate.Snapshot{
		StartedAt:     time.Now().UTC(),
		StoppedAt:     time.Now().UTC(),
		Hostname:      m.hostname,
		PID:           pid(),
		InstanceID:    m.instanceID,
		CleanShutdown: true,
	})

	if !m.cfg.Enabled || m.sender == nil || !m.cfg.Lifecycle.ShutdownNotify || m.cfg.Lifecycle.NotifyMode != "notify" {
		return
	}

	sendCtx, cancel := context.WithTimeout(ctx, minDuration(m.cfg.Timeout, 3*time.Second))
	defer cancel()
	if err := m.sender.SendText(sendCtx, m.formatMessage("Shutdown", false, m.cfg.Enabled)); err != nil {
		if m.logger != nil {
			m.logger.Warn("telegram_shutdown_notify_error", "event", "telegram_shutdown_notify_error", "hostname", m.hostname, "instance_id", m.instanceID, "error", err)
		}
		return
	}
	if m.logger != nil {
		m.logger.Info("telegram_shutdown_notify_sent", "event", "telegram_shutdown_notify_sent", "hostname", m.hostname, "instance_id", m.instanceID)
	}
}

func (m *LifecycleManager) selfCheck(reportsEnabled, alertsEnabled bool) {
	if m.logger != nil {
		m.logger.Info("telegram_healthcheck_started", "event", "telegram_healthcheck_started", "hostname", m.hostname, "instance_id", m.instanceID, "notify_mode", m.cfg.Lifecycle.NotifyMode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	if err := m.sender.SelfCheck(ctx); err != nil {
		if m.logger != nil {
			m.logger.Warn("telegram_healthcheck_error", "event", "telegram_healthcheck_error", "hostname", m.hostname, "instance_id", m.instanceID, "error", err)
		}
		return
	}
	if m.logger != nil {
		m.logger.Info("telegram_healthcheck_ok", "event", "telegram_healthcheck_ok", "hostname", m.hostname, "instance_id", m.instanceID)
	}
	if m.cfg.Lifecycle.StartupNotify && m.cfg.Lifecycle.NotifyMode == "notify" {
		m.sendStartupNotify(reportsEnabled, alertsEnabled)
	}
}

func (m *LifecycleManager) sendStartupNotify(reportsEnabled, alertsEnabled bool) {
	if m.cfg.Lifecycle.NotifyMode != "notify" {
		return
	}
	text := m.formatMessage("Startup", reportsEnabled, alertsEnabled)
	m.sendTextWithLog("telegram_startup_notify_sent", "telegram_startup_notify_error", text)
}

func (m *LifecycleManager) runHeartbeat(ctx context.Context, reportsEnabled, alertsEnabled bool) {
	ticker := time.NewTicker(m.cfg.Lifecycle.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.cfg.Lifecycle.NotifyMode == "notify" {
				m.sendTextWithLog("telegram_heartbeat_ok", "telegram_heartbeat_error", m.formatMessage("Heartbeat", reportsEnabled, alertsEnabled))
				continue
			}
			if m.logger != nil {
				m.logger.Info("telegram_heartbeat_ok", "event", "telegram_heartbeat_ok", "hostname", m.hostname, "instance_id", m.instanceID)
			}
		}
	}
}

func (m *LifecycleManager) formatMessage(status string, reportsEnabled, alertsEnabled bool) string {
	displayName := strings.TrimSpace(m.cfg.DisplayName)
	if displayName == "" {
		displayName = "gw-ipinfo-nginx"
	}
	title := strings.TrimSpace(m.cfg.TitlePrefix)
	if title == "" {
		title = displayName
	}
	return fmt.Sprintf(
		"%s %s\napp: %s\ninstance_id: %s\nhostname: %s\nreports_enabled: %t\nalerts_enabled: %t\ntelegram_enabled: %t\ntime: %s",
		title,
		status,
		displayName,
		m.instanceID,
		m.hostname,
		reportsEnabled,
		alertsEnabled,
		m.cfg.Enabled,
		time.Now().UTC().Format(time.RFC3339),
	)
}

func (m *LifecycleManager) sendTextWithLog(okEvent, errEvent, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	if err := m.sender.SendText(ctx, text); err != nil {
		if m.logger != nil {
			m.logger.Warn(errEvent, "event", errEvent, "hostname", m.hostname, "instance_id", m.instanceID, "error", err)
		}
		return
	}
	if m.logger != nil {
		m.logger.Info(okEvent, "event", okEvent, "hostname", m.hostname, "instance_id", m.instanceID)
	}
}

func pid() int {
	return os.Getpid()
}

func minDuration(left, right time.Duration) time.Duration {
	if left <= 0 {
		return right
	}
	if left < right {
		return left
	}
	return right
}
