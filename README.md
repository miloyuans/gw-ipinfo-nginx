# gw-ipinfo-nginx

`gw-ipinfo-nginx` 是一个 Go 网关服务。它会从请求头里提取真实客户端公网 IP，执行 UA、`Accept-Language`、IPinfo、geo、privacy 等检查，放行后再反向代理到配置好的 nginx 入口；如果未通过检查，则直接返回固定静态拦截页。

## 主线文件

- 配置: [config.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.yaml)
- 中文配置参考: [config.reference.zh.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.reference.zh.yaml)
- 中文说明: [config-reference.zh-CN.md](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/docs/config-reference.zh-CN.md)
- 本地编排: [docker-compose.yml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/docker-compose.yml)
- 环境变量模板: [.env.example](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/.env.example)
- 启动脚本: [up.sh](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/scripts/up.sh)
- 停止脚本: [down.sh](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/scripts/down.sh)
- 日志脚本: [logs.sh](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/scripts/logs.sh)

## 当前行为

- 默认接受所有来源流量，不再先校验 CDN / 代理来源网段
- 按 `CF-Connecting-IP`、`True-Client-IP`、`X-Real-IP`、`X-Forwarded-For` 顺序提取真实公网 IP
- 找不到合法公网 IP 时直接返回固定拦截页
- 放行后代理到 `routing.services[].target_url`
- `target_url` 可以是同 Pod nginx，也可以是外部 nginx 地址
- 日志统一输出 `event/request_id/client_ip/service_name/upstream_url/result/reason_code/cache_source/latency_ms`

## 一键启动

```bash
cp .env.example .env
chmod +x ./scripts/*.sh
sh ./scripts/up.sh
```

或：

```bash
make up
make logs
```

默认入口：

- gateway: `http://127.0.0.1:8080`
- health: `http://127.0.0.1:8080/healthz`
- ready: `http://127.0.0.1:8080/readyz`
- metrics: `http://127.0.0.1:8080/metrics`

## 最常改的配置

### 1. nginx 入口地址

在 `.env` 中改：

```dotenv
NGINX_TARGET_URL=http://nginx:8081
```

如果你要代理到外部 nginx：

```dotenv
NGINX_TARGET_URL=http://your-nginx.example.com:8080
```

### 2. 启用 IPinfo

在 [config.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.yaml) 里改：

```yaml
ipinfo:
  enabled: true
```

并在 `.env` 中补：

```dotenv
IPINFO_TOKEN=your-token
MONGO_URI=mongodb://gw_ipinfo_app:password@mongo:27017/gw_ipinfo_nginx?authSource=gw_ipinfo_nginx
MONGO_APP_DATABASE=gw_ipinfo_nginx
```

### 3. 启用 Telegram 告警

在 [config.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.yaml) 里改：

```yaml
alerts:
  telegram:
    enabled: true
  delivery:
    worker_enabled: true
```

并在 `.env` 中补：

```dotenv
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id
```

## 验证

带真实公网 IP 头通过网关：

```bash
curl -i http://127.0.0.1:8080/ \
  -H 'CF-Connecting-IP: 1.1.1.1' \
  -H 'User-Agent: Mozilla/5.0' \
  -H 'Accept-Language: en-US,en;q=0.9'
```

命中 bot UA，会返回固定拦截页：

```bash
curl -i http://127.0.0.1:8080/ \
  -H 'CF-Connecting-IP: 1.1.1.1' \
  -H 'User-Agent: Googlebot/2.1'
```

查看实时日志：

```bash
sh ./scripts/logs.sh
```

## 测试

```bash
go test ./...
```

Mongo 集成测试：

```bash
GW_MONGO_TEST_URI='mongodb://localhost:27017' go test ./...
```
