SHELL := /bin/sh

.PHONY: up down logs debug-up debug-down debug-logs prod-up prod-down prod-logs

up:
	sh ./scripts/up.sh

down:
	sh ./scripts/down.sh

logs:
	sh ./scripts/logs.sh

debug-up: up
debug-down: down
debug-logs: logs
prod-up: up
prod-down: down
prod-logs: logs
