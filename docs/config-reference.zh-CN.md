# 配置文件中文参考

本文档对应项目里的配置结构体定义：

- [config.go](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/internal/config/config.go)
- [config.reference.zh.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.reference.zh.yaml)
- [config.debug.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.debug.yaml)
- [config.prod.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.prod.yaml)

## 最常见的启动报错

### 1. `ipinfo.token is required when ipinfo.enabled is true`

含义：

- 你把 `ipinfo.enabled` 打开了
- 但没有配置 `ipinfo.token`

解决：

- 本地只想调试网关和 nginx：把 `ipinfo.enabled: false`
- 本地要联调 IPinfo：把 `IPINFO_TOKEN` 放进环境变量，并在 YAML 里写 `token: "${IPINFO_TOKEN}"`

### 2. `mongo.uri is required when ipinfo or alerts are enabled`

含义：

- 只要以下任意一个开关为 `true`，Mongo 就必须配置
- `ipinfo.enabled`
- `alerts.telegram.enabled`
- `alerts.delivery.worker_enabled`

解决：

- 本地简化调试：把上面几个功能都关掉
- 要测完整链路：补 `mongo.uri` 和 `mongo.database`

### 3. `alerts.telegram.bot_token/chat_id is required when alerts.telegram.enabled is true`

含义：

- 你打开了 Telegram 告警
- 但没有填 `bot_token` / `chat_id`

解决：

- 不测告警：`alerts.telegram.enabled: false`
- 要测告警：补全 `bot_token` 和 `chat_id`

## 建议的三种配置模式

### 模式 A：最小本地调试模式

目标：

- 只验证请求进网关后能不能通过基础校验并代理到 nginx

建议：

- 直接使用 [config.debug.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.debug.yaml)

关键开关：

- `ipinfo.enabled: false`
- `alerts.telegram.enabled: false`
- `alerts.delivery.worker_enabled: false`
- `security.accept_language.require_header: false`
- `real_ip.untrusted_proxy_action: "use_remote_addr"`

### 模式 B：本地全链路联调模式

目标：

- 调试 IPinfo、Mongo 缓存、策略判定

建议：

- 使用 [config.prod.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.prod.yaml)
- 同时准备 `.env.prod`

至少需要：

- `IPINFO_TOKEN`
- `MONGO_URI`
- `MONGO_APP_DATABASE`

### 模式 C：含告警的完整联调模式

目标：

- 连同 Telegram outbox worker 一起调

额外需要：

- `alerts.telegram.enabled: true`
- `alerts.delivery.worker_enabled: true`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

## 各配置段说明

### `server`

- `listen_address`：网关监听地址，默认 `:8080`
- `read_timeout`：读取请求超时
- `write_timeout`：写响应超时
- `idle_timeout`：keep-alive 空闲连接超时
- `shutdown_timeout`：优雅停机等待时间
- `deny_status_code`：拦截时返回码，建议 `403`

### `real_ip`

- `trusted_proxy_cidrs`：只有请求来源落在这些网段内，才信任透传头
- `header_priority`：真实 IP 提取顺序
- `untrusted_proxy_action`
  - `deny`：来源不可信就直接拒绝
  - `use_remote_addr`：回退到 TCP 对端地址，适合本地调试

说明：

- 生产环境应尽量使用 `deny`
- 本地 Docker 调试建议使用 `use_remote_addr`

### `ipinfo`

- `enabled`：是否启用 IPinfo 查询
- `base_url`：API 地址
- `lookup_path_template`：请求路径模板
- `token`：IPinfo token
- `timeout`：单次请求超时
- `max_retries`：最大重试次数
- `retry_backoff`：重试退避
- `include_residential_proxy`：是否读取住宅代理字段

### `mongo`

- `uri`：Mongo 连接串
- `database`：数据库名
- `connect_timeout`：连接超时
- `operation_timeout`：单次操作超时

说明：

- 只有启用 IPinfo/alerts 时才需要

### `cache`

#### `l1`

- `enabled`：是否启用进程内缓存
- `max_entries`：最大缓存条目数
- `cleanup_interval_sec`：清理周期

#### `ttl`

- `geo`：地理信息缓存 TTL
- `privacy`：隐私/代理信息缓存 TTL
- `residential_proxy`：住宅代理缓存 TTL

#### `failure_ttl`

- lookup 失败时的负缓存时长

#### `mongo_collections`

- `ip_cache`：L2 IP 缓存集合
- `alert_outbox`：告警 outbox 集合
- `alert_dedupe`：告警去重集合

### `security.ua`

- `enabled`：是否启用 UA 拦截
- `deny_keywords`：关键字匹配，大小写不敏感
- `deny_patterns`：自定义正则

### `security.accept_language`

- `require_header`：是否强制要求存在 `Accept-Language`
- `service_overrides`：按 service 覆盖

示例：

```yaml
security:
  accept_language:
    require_header: true
    service_overrides:
      default:
        allow_missing: false
```

### `security.geo`

- `default_action`：当前只支持 `deny`
- `whitelist`：国家/城市白名单

语义：

```yaml
whitelist:
  US: {}
  JP:
    cities: ["Tokyo", "Osaka"]
```

表示：

- 美国全部放行
- 日本只放行东京和大阪

### `security.privacy`

- `deny_by_default`：是否默认拒绝风险类型
- `allow_types`：哪些风险类型允许放行
- `enable_residential_proxy`：是否启用住宅代理判定

支持值：

- `vpn`
- `proxy`
- `tor`
- `relay`
- `hosting`
- `residential_proxy`

### `routing`

- `default_service`：默认 service 名称
- `services`：路由服务列表

常见目标地址：

- Docker Compose：`http://nginx:8081`
- K8s sidecar：`http://127.0.0.1:8081`

### `alerts.telegram`

- `enabled`：是否启用 Telegram 告警
- `bot_token`：Bot token
- `chat_id`：聊天 ID
- `api_base_url`：Telegram API 地址
- `timeout`：发送超时
- `parse_mode`：Telegram parse mode
- `mask_query`：是否隐藏 URL query
- `include_user_agent`：是否在告警中包含 UA

### `alerts.delivery`

- `worker_enabled`：是否启用 outbox worker
- `poll_interval`：轮询周期
- `batch_size`：每次拉取数量
- `claim_lease`：消费租约时长
- `max_attempts`：最大重试次数
- `base_backoff`：基础退避
- `max_backoff`：最大退避
- `rate_limit_per_second`：每秒发送上限

### `alerts.dedupe`

- `window`：相同告警的去重窗口

### `logging`

- `level`：日志级别
- `format`：`json` 或 `text`
- `redact_query`：是否隐藏 query
- `access_log`：是否记录访问日志

### `metrics`

- `enabled`：是否暴露 Prometheus 指标
- `path`：指标路径，默认 `/metrics`

## 推荐配置片段

### 本地最小调试

```yaml
ipinfo:
  enabled: false

alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
```

### 本地调试真实 IP

```yaml
real_ip:
  trusted_proxy_cidrs:
    - "127.0.0.1/32"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  untrusted_proxy_action: "use_remote_addr"
```

### 生产环境建议

```yaml
real_ip:
  trusted_proxy_cidrs:
    - "你的 CDN / WAF / SLB 出口网段"
  untrusted_proxy_action: "deny"
```

## 为什么你现在会看到那组报错

你贴出来的报错只会在“完整模式配置”下出现，也就是至少满足下面之一：

- `ipinfo.enabled: true`
- `alerts.telegram.enabled: true`
- `alerts.delivery.worker_enabled: true`

而 [config.debug.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.debug.yaml) 这几个值默认都是关闭的。  
如果你执行的是 `sh ./scripts/dev-up.sh` 却仍然看到这些报错，优先检查下面几项：

1. 是否实际启动的是调试 compose：
   `docker compose -f docker-compose.debug.yml config`

2. 是否还有旧的同名容器在重启：
   `docker ps -a`

3. 是否之前启动过生产栈，没有先停掉：
   `docker compose -f docker-compose.prod.yml down --remove-orphans`

4. 是否当前容器里挂进去的真的是调试配置：
   `docker compose -f docker-compose.debug.yml exec gateway cat /app/configs/config.debug.yaml`

## 建议你现在怎么做

如果你只是想先把 gateway + nginx 跑通，直接用这一组：

```bash
docker compose -f docker-compose.prod.yml down --remove-orphans || true
docker compose -f docker-compose.debug.yml down --remove-orphans || true
sh ./scripts/dev-up.sh
```

如果还报配置相关错误，把下面两段输出贴出来，我继续帮你对：

```bash
docker compose -f docker-compose.debug.yml config
docker compose -f docker-compose.debug.yml logs gateway
```
