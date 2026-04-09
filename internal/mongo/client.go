package mongostore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Client struct {
	client           *mongo.Client
	database         *mongo.Database
	operationTimeout time.Duration
}

func Connect(ctx context.Context, cfg config.MongoConfig) (*Client, error) {
	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetConnectTimeout(cfg.ConnectTimeout)
	if cfg.Timeout > 0 {
		clientOptions.SetTimeout(cfg.Timeout)
	}
	if cfg.MaxPoolSize > 0 {
		clientOptions.SetMaxPoolSize(cfg.MaxPoolSize)
	}
	if cfg.MinPoolSize > 0 {
		clientOptions.SetMinPoolSize(cfg.MinPoolSize)
	}
	if cfg.MaxConnecting > 0 {
		clientOptions.SetMaxConnecting(cfg.MaxConnecting)
	}
	if cfg.MaxConnIdleTime > 0 {
		clientOptions.SetMaxConnIdleTime(cfg.MaxConnIdleTime)
	}

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, wrapMongoError("connect mongo", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.OperationTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, wrapMongoError("ping mongo", err)
	}

	return &Client{
		client:           client,
		database:         client.Database(cfg.Database),
		operationTimeout: cfg.OperationTimeout,
	}, nil
}

func (c *Client) Database() *mongo.Database {
	return c.database
}

func (c *Client) Ping(ctx context.Context) error {
	child, cancel := c.WithTimeout(ctx)
	defer cancel()
	return c.client.Ping(child, nil)
}

func (c *Client) Disconnect(ctx context.Context) error {
	return c.client.Disconnect(ctx)
}

func (c *Client) WithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.operationTimeout)
}

func wrapMongoError(operation string, err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "AuthenticationFailed") || strings.Contains(message, "unable to authenticate") {
		return fmt.Errorf("%s: %w; hint: check mongo uri, authSource, username and password. If the user was created in the admin database, use authSource=admin", operation, err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
