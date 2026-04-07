package storage

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
)

type Mode string

const (
	ModeMongo  Mode = "mongo"
	ModeLocal  Mode = "localdisk"
	ModeHybrid Mode = "hybrid"
)

type Replayer interface {
	Name() string
	Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error)
}

type Controller struct {
	cfg      config.StorageConfig
	mongoCfg config.MongoConfig
	logger   *slog.Logger
	local    *localdisk.Store

	mode     atomic.Value
	degraded atomic.Bool

	mu        sync.RWMutex
	mongo     *mongostore.Client
	replayers []Replayer

	connector func(ctx context.Context, cfg config.MongoConfig) (*mongostore.Client, error)
	ping      func(ctx context.Context, client *mongostore.Client) error
}

func NewController(cfg config.StorageConfig, mongoCfg config.MongoConfig, local *localdisk.Store, logger *slog.Logger) *Controller {
	c := &Controller{
		cfg:       cfg,
		mongoCfg:  mongoCfg,
		logger:    logger,
		connector: mongostore.Connect,
		local:     local,
	}
	c.ping = func(ctx context.Context, client *mongostore.Client) error {
		if client == nil {
			return errors.New("nil mongo client")
		}
		return client.Ping(ctx)
	}
	c.mode.Store(ModeLocal)
	return c
}

func (c *Controller) RegisterReplayer(replayer Replayer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.replayers = append(c.replayers, replayer)
}

func (c *Controller) Local() *localdisk.Store {
	return c.local
}

func (c *Controller) Mode() Mode {
	value, _ := c.mode.Load().(Mode)
	if value == "" {
		return ModeLocal
	}
	return value
}

func (c *Controller) Client() *mongostore.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mongo
}

func (c *Controller) SetMongoClient(client *mongostore.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mongo = client
	if client == nil {
		c.degraded.Store(true)
		c.mode.Store(ModeLocal)
		return
	}

	c.degraded.Store(false)
	c.mode.Store(ModeHybrid)
}

func (c *Controller) HandleMongoError(err error) {
	if err == nil {
		return
	}
	if c.degraded.CompareAndSwap(false, true) {
		c.mode.Store(ModeLocal)
		if c.logger != nil {
			c.logger.Warn(
				"mongo_degraded_to_local",
				"event", "mongo_degraded_to_local",
				"error", err,
				"mode", c.Mode(),
			)
		}
	}
}

func (c *Controller) Start(ctx context.Context) {
	probeTicker := time.NewTicker(c.cfg.MongoProbeInterval)
	replayTicker := time.NewTicker(c.cfg.ReplayInterval)
	defer probeTicker.Stop()
	defer replayTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-probeTicker.C:
			if c.degraded.Load() {
				if err := c.recoverAndReplay(ctx); err != nil && c.logger != nil {
					c.logger.Warn("mongo_replay_error", "event", "mongo_replay_error", "error", err)
				}
			}

		case <-replayTicker.C:
			if !c.degraded.Load() && c.Client() != nil {
				if _, err := c.replayOnce(ctx); err != nil && c.logger != nil {
					c.logger.Warn("mongo_replay_error", "event", "mongo_replay_error", "error", err)
				}
			}
		}
	}
}

func (c *Controller) recoverAndReplay(ctx context.Context) error {
	client := c.Client()
	if client == nil {
		connectCtx, cancel := context.WithTimeout(ctx, c.mongoCfg.ConnectTimeout+c.mongoCfg.OperationTimeout)
		defer cancel()

		connected, err := c.connector(connectCtx, c.mongoCfg)
		if err != nil {
			return err
		}

		client = connected
		c.mu.Lock()
		c.mongo = connected
		c.mu.Unlock()
	}

	pingCtx, cancel := context.WithTimeout(ctx, c.mongoCfg.OperationTimeout)
	defer cancel()
	if err := c.ping(pingCtx, client); err != nil {
		return err
	}

	recovered := c.degraded.CompareAndSwap(true, false)
	c.mode.Store(ModeHybrid)

	if recovered && c.logger != nil {
		c.logger.Info(
			"mongo_recovered_replaying_local",
			"event", "mongo_recovered_replaying_local",
			"mode", c.Mode(),
		)
	}

	total, err := c.replayOnce(ctx)
	if err != nil {
		return err
	}

	if total > 0 && c.logger != nil {
		c.logger.Info(
			"mongo_replay_done",
			"event", "mongo_replay_done",
			"mode", c.Mode(),
			"replayed_records", total,
		)
	}

	return nil
}

func (c *Controller) replayOnce(ctx context.Context) (int, error) {
	c.mu.RLock()
	replayers := append([]Replayer(nil), c.replayers...)
	client := c.mongo
	c.mu.RUnlock()

	total := 0
	for _, replayer := range replayers {
		count, err := replayer.Replay(ctx, client, c.cfg.ReplayBatchSize)
		if err != nil {
			return total, errors.Join(errors.New(replayer.Name()), err)
		}
		total += count
	}

	return total, nil
}