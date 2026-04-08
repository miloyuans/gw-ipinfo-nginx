//go:build linux

package server

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"gw-ipinfo-nginx/internal/config"
)

func NewListener(ctx context.Context, cfg config.ServerConfig) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				if cfg.Prefork.Enabled {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); err != nil {
						controlErr = err
						return
					}
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					controlErr = err
				}
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	listener, err := lc.Listen(ctx, "tcp", cfg.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.ListenAddress, err)
	}
	return listener, nil
}
