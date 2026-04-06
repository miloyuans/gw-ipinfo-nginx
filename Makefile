SHELL := /bin/sh

.PHONY: debug-up debug-down debug-logs prod-up prod-down prod-logs

debug-up:
	sh ./scripts/dev-up.sh

debug-down:
	sh ./scripts/dev-down.sh

debug-logs:
	sh ./scripts/dev-logs.sh

prod-up:
	sh ./scripts/prod-up.sh

prod-down:
	sh ./scripts/prod-down.sh

prod-logs:
	sh ./scripts/prod-logs.sh
