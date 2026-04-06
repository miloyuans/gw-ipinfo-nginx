# gw-ipinfo-nginx

`gw-ipinfo-nginx` is a Go gateway designed for Kubernetes sidecar deployment with nginx.
It extracts the real client IP from trusted proxy headers, applies request and IP risk policy,
optionally looks up IP intelligence from IPinfo, persists shared cache and alert state in MongoDB,
and forwards approved traffic to the nginx sidecar running in the same Pod.

## Architecture

- The gateway listens on `:8080`.
- The nginx sidecar listens on `127.0.0.1:8081` inside the Pod.
- Requests pass through:
  1. request id middleware
  2. real client IP extraction
  3. UA and `Accept-Language` checks
  4. optional IPinfo + cache lookup
  5. geo / privacy policy evaluation
  6. async alert enqueue when needed
  7. reverse proxy to nginx
- L1 cache is local to one process.
- MongoDB is the shared source of truth for L2 cache and alert outbox state.
- EFS/PVC is only for shared config, logs, and debug artifacts. Correctness does not depend on file locks.

## Directory Layout

```text
cmd/gateway
cmd/gw-ipinfo-nginx
configs
deployments/nginx
examples
internal/alerts
internal/app
internal/audit
internal/cache
internal/config
internal/health
internal/httpx
internal/ipctx
internal/ipinfo
internal/logging
internal/metrics
internal/middleware
internal/model
internal/mongo
internal/policy
internal/proxy
internal/realip
internal/routing
internal/server
k8s
```

## Stage Mapping

### Stage 1

- Use [config.phase1.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/examples/config.phase1.yaml)
- `ipinfo.enabled=false`
- `alerts.telegram.enabled=false`
- MongoDB is not required

### Stage 2

- Use [config.phase2.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/examples/config.phase2.yaml)
- IPinfo + L1 + Mongo L2 cache are enabled
- Geo and privacy policy are enforced with shared Mongo state

### Stage 3

- Use [config.example.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.example.yaml)
- Mongo outbox + Telegram worker + Kubernetes manifests are enabled

## Local Development

### One-click debug stack

This is the fastest local path when you only want to debug the gateway request path.
It starts:

- gateway
- nginx sidecar backend

It does not require IPinfo or MongoDB.

Files:

- [config.debug.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.debug.yaml)
- [docker-compose.debug.yml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/docker-compose.debug.yml)
- [.env.debug.example](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/.env.debug.example)
- [dev-up.ps1](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/scripts/dev-up.ps1)
- [dev-down.ps1](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/scripts/dev-down.ps1)

Windows PowerShell:

```powershell
.\scripts\dev-up.ps1
```

Windows PowerShell with live logs:

```powershell
.\scripts\dev-up.ps1 -Logs
```

Linux/macOS shell:

```bash
sh ./scripts/dev-up.sh
```

Stop the debug stack:

```powershell
.\scripts\dev-down.ps1
```

Debug endpoints:

- gateway: `http://127.0.0.1:8080`
- health: `http://127.0.0.1:8080/healthz`
- readiness: `http://127.0.0.1:8080/readyz`
- metrics: `http://127.0.0.1:8080/metrics`

### Run stage 1 without Mongo

1. Start nginx with the example config:

```bash
docker run --rm -p 8081:8081 \
  -v "$PWD/examples/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/examples/index.html:/usr/share/nginx/html/index.html:ro" \
  nginx:1.27-alpine
```

2. Start the gateway:

```bash
go run ./cmd/gateway -config ./examples/config.phase1.yaml
```

### Run stage 2 or stage 3 with Docker Compose

```bash
docker compose up --build
```

The bundled compose file starts:

- gateway on `http://localhost:8080`
- nginx on `http://localhost:8081`
- MongoDB on `mongodb://localhost:27017`

### Full local stack close to production

Use the production-style compose when you want to debug IPinfo, Mongo cache, and later Telegram worker behavior:

```bash
cp .env.prod.example .env.prod
docker compose -f docker-compose.prod.yml --env-file .env.prod up --build
```

Files:

- [config.prod.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.prod.yaml)
- [docker-compose.prod.yml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/docker-compose.prod.yml)
- [.env.prod.example](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/.env.prod.example)

## Validation

### Non-trusted proxy

Temporarily change `trusted_proxy_cidrs` in the stage 1 config so it does not include `127.0.0.0/8`,
then restart the gateway and run:

```bash
curl -i http://localhost:8080/ \
  -H 'CF-Connecting-IP: 1.1.1.1' \
  -H 'Accept-Language: en-US' \
  -H 'User-Agent: Mozilla/5.0'
```

Expected:

- `403`
- JSON body contains `deny_real_ip_extract_failed`

### Bot UA

```bash
curl -i http://localhost:8080/ \
  -H 'CF-Connecting-IP: 1.1.1.1' \
  -H 'Accept-Language: en-US' \
  -H 'User-Agent: Googlebot/2.1' \
  --resolve localhost:8080:127.0.0.1
```

Expected:

- `403`
- JSON body contains `deny_ua_keyword`

### Empty Accept-Language

```bash
curl -i http://localhost:8080/ \
  -H 'CF-Connecting-IP: 1.1.1.1' \
  -H 'User-Agent: Mozilla/5.0'
```

Expected:

- `403`
- JSON body contains `deny_missing_accept_language`

### Successful proxying

```bash
curl -i http://localhost:8080/ \
  -H 'CF-Connecting-IP: 1.1.1.1' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'User-Agent: Mozilla/5.0'
```

Expected:

- `200`
- response body from nginx sidecar
- upstream receives `X-Client-Real-IP` and `X-Gateway-Service`

### Stage 2 cache behavior

Use the same real IP twice with IPinfo enabled. The first lookup should be served from `ipinfo`,
and later requests should show `cache_source` as `l1` or `mongo` in audit logs.

### Stage 3 async alerts

Enable Telegram config and allow one privacy risk via `allow_types`.
Requests that are allowed with risk should enqueue Mongo outbox records immediately and be sent by workers asynchronously.

## Mongo Cache Document

Collection: `ip_risk_cache`

Fields:

- `_id`: client IP string
- `ip_context`: normalized IP intelligence result
- `failure`: cached lookup error text for negative cache entries
- `geo_expires_at`
- `privacy_expires_at`
- `resproxy_expires_at`
- `failure_expires_at`
- `expires_at`
- `created_at`
- `updated_at`

Indexes:

- TTL index on `expires_at`

Notes:

- `expires_at` is computed as the max of geo/privacy/resproxy TTLs for successful lookups
- negative cache entries use `error_ttl`
- concurrent multi-Pod updates are handled via Mongo upsert

## Alerts Outbox

Collection: `alerts_outbox`

Fields:

- `status`
- `notify_type`
- `severity`
- `payload`
- `attempts`
- `retry_count`
- `next_attempt_at`
- `next_retry_at`
- `lease_expires_at`
- `claimed_by`
- `last_error`
- `created_at`
- `updated_at`
- `sent_at`

Supporting collection: `alerts_dedupe`

Indexes:

- claim scan index on `status`, `next_attempt_at`, `lease_expires_at`
- TTL index on dedupe `expires_at`

## Metrics

Important metrics include:

- `gw_gateway_requests_total`
- `gw_gateway_deny_reasons_total`
- `gw_gateway_request_duration_seconds`
- `gw_gateway_lookup_results_total`
- `gw_gateway_ipinfo_requests_total`
- `gw_gateway_ipinfo_request_duration_seconds`
- `gw_gateway_mongo_lookup_duration_seconds`
- `gw_gateway_alerts_outbox_total`
- `gw_gateway_alert_delivery_total`

## Kubernetes

Main manifests:

- [deployment.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/deployment.yaml)
- [service.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/service.yaml)
- [configmap.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/configmap.yaml)
- [secret.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/secret.yaml)
- [pvc.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/pvc.yaml)
- [pdb.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/pdb.yaml)
- [hpa.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/hpa.yaml)
- [nginx-configmap.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/k8s/nginx-configmap.yaml)

The Deployment uses a two-container Pod:

- `gw-ipinfo-nginx-gateway`
- `nginx-sidecar`

Shared storage is mounted at `/data/shared`.

## Build

```bash
docker build -t gw-ipinfo-nginx:latest .
```

## Tests

```bash
go test ./...
```

To run Mongo integration tests as well:

```bash
GW_MONGO_TEST_URI='mongodb://localhost:27017' go test ./...
```

## Troubleshooting

- If stage 1 fails at startup with Mongo errors, make sure you are using `examples/config.phase1.yaml`.
- If stage 2 fails at startup, verify `MONGO_URI` and `IPINFO_TOKEN`.
- If alerts are not sent, check Mongo outbox documents first, then Telegram token/chat id, then worker logs.
- If real IP extraction fails behind a CDN, confirm the CDN egress CIDRs are present in `trusted_proxy_cidrs`.
- If `/readyz` fails in full mode, verify Mongo connectivity and indexes.

## Security Notes

- Only trust proxy headers from configured CIDRs.
- Do not treat private, loopback, or reserved addresses as client public IPs.
- Keep Telegram secrets and IPinfo tokens in Kubernetes `Secret`, not in Git.
- Mask query strings in alerts unless there is a strong reason not to.

## Future Extensions

- service-level overrides for geo/privacy policy
- richer IPinfo schema versioning
- OpenTelemetry export
- Helm chart packaging
- admin endpoints for cache introspection
