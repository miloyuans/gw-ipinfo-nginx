package runtimex

import (
	"os"
	"strings"
)

func WorkerScope() string {
	if value := strings.TrimSpace(os.Getenv("GW_RUNTIME_WORKER_ID")); value != "" {
		return value
	}
	if podName := strings.TrimSpace(os.Getenv("POD_NAME")); podName != "" {
		if childIndex := strings.TrimSpace(os.Getenv("GW_PREFORK_CHILD_INDEX")); childIndex != "" {
			return podName + "-" + childIndex
		}
		return podName
	}
	if childIndex := strings.TrimSpace(os.Getenv("GW_PREFORK_CHILD_INDEX")); childIndex != "" {
		return "prefork-" + childIndex
	}
	return ""
}

func IsPrimaryProcess() bool {
	value := strings.TrimSpace(os.Getenv("GW_PREFORK_PRIMARY"))
	if value == "" {
		return true
	}
	return value == "1" || strings.EqualFold(value, "true")
}
