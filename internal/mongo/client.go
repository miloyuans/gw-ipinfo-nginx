package mongostore

import (
	"context"
	"fmt"
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

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("connect mongo: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.OperationTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
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
