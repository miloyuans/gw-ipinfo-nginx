package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gw-ipinfo-nginx/internal/app"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/config.example.yaml", "path to YAML config")
	flag.Parse()
	if configPath == "configs/config.example.yaml" {
		if value := os.Getenv("GW_GATEWAY_CONFIG"); value != "" {
			configPath = value
		} else if value := os.Getenv("GW_IPINFO_NGINX_CONFIG"); value != "" {
			configPath = value
		}
	}

	application, err := app.New(configPath)
	if err != nil {
		log.Fatalf("build app: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := application.Run(ctx); err != nil {
		log.Fatalf("run app: %v", err)
	}
}
