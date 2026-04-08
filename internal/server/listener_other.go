//go:build !linux

package server

import (
	"context"
	"fmt"
	"net"

	"gw-ipinfo-nginx/internal/config"
)

func NewListener(ctx context.Context, cfg config.ServerConfig) (net.Listener, error) {
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.ListenAddress, err)
	}
	return listener, nil
}
