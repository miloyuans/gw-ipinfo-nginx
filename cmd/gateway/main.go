package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"gw-ipinfo-nginx/internal/app"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/server"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/config.yaml", "path to YAML config")
	flag.Parse()
	if configPath == "configs/config.yaml" {
		if value := os.Getenv("GW_GATEWAY_CONFIG"); value != "" {
			configPath = value
		} else if value := os.Getenv("GW_IPINFO_NGINX_CONFIG"); value != "" {
			configPath = value
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.Server.Prefork.Enabled && os.Getenv("GW_PREFORK_CHILD") == "" && cfg.Server.Prefork.Processes > 1 {
		if runtime.GOOS != "linux" {
			log.Fatalf("prefork requires linux when processes > 1")
		}
		if err := runPreforkMaster(ctx, configPath, cfg.Server.Prefork.Processes); err != nil {
			log.Fatalf("run prefork master: %v", err)
		}
		return
	}

	if err := runWorker(ctx, configPath, cfg); err != nil {
		log.Fatalf("run app: %v", err)
	}
}

func runWorker(ctx context.Context, configPath string, cfg *config.Config) error {
	application, err := app.New(configPath)
	if err != nil {
		return fmt.Errorf("build app: %w", err)
	}
	if cfg.Server.Prefork.Enabled {
		listener, err := server.NewListener(ctx, cfg.Server)
		if err != nil {
			return err
		}
		defer listener.Close()
		return application.RunWithListener(ctx, listener)
	}
	return application.Run(ctx)
}

func runPreforkMaster(ctx context.Context, configPath string, processCount int) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	podName := os.Getenv("POD_NAME")
	children := make([]*exec.Cmd, 0, processCount)
	errCh := make(chan error, processCount)

	for idx := 0; idx < processCount; idx++ {
		cmd := exec.Command(executable, "-config", configPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		workerID := fmt.Sprintf("gw-worker-%d", idx)
		if podName != "" {
			workerID = fmt.Sprintf("%s-%d", podName, idx)
		}

		cmd.Env = append(os.Environ(),
			"GW_PREFORK_CHILD=1",
			fmt.Sprintf("GW_PREFORK_CHILD_INDEX=%d", idx),
			fmt.Sprintf("GW_RUNTIME_WORKER_ID=%s", workerID),
		)
		if idx == 0 {
			cmd.Env = append(cmd.Env, "GW_PREFORK_PRIMARY=1")
		} else {
			cmd.Env = append(cmd.Env, "GW_PREFORK_PRIMARY=0")
		}

		if err := cmd.Start(); err != nil {
			stopChildren(children)
			return fmt.Errorf("start prefork child %d: %w", idx, err)
		}
		children = append(children, cmd)

		go func(child *exec.Cmd) {
			errCh <- child.Wait()
		}(cmd)
	}

	select {
	case <-ctx.Done():
		stopChildren(children)
		return nil
	case err := <-errCh:
		stopChildren(children)
		if err != nil {
			return err
		}
		return nil
	}
}

func stopChildren(children []*exec.Cmd) {
	for _, child := range children {
		if child == nil || child.Process == nil {
			continue
		}
		_ = child.Process.Signal(syscall.SIGTERM)
	}
}
