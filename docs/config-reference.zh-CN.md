# 配置文件中文说明

主线入口文件：

- [config.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.yaml)
- [config.reference.zh.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.reference.zh.yaml)
- [.env.example](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/.env.example)

## 当前主线行为

### 1. 不再先校验 CDN / 代理来源

当前默认配置：

```yaml
real_ip:
  trust_all_sources: true
```

含义：

- 网关先接受所有进入流量
- 直接从头部里尝试提取真实公网客户端 IP
- 不再先看请求是否来自某个可信 CDN 网段

如果以后你想恢复“只信任指定代理来源”，改成：

```yaml
real_ip:
  trust_all_sources: false
  trusted_proxy_cidrs:
    - "你的代理出口网段"
```

### 2. 真实客户端 IP 的提取顺序

按以下顺序取：

1. `CF-Connecting-IP`
2. `True-Client-IP`
3. `X-Real-IP`
4. `X-Forwarded-For`

其中：

- `X-Forwarded-For` 会取第一个合法公网 IP
- 私网、回环、保留地址不会被当作真实客户端公网 IP
- 如果头部都拿不到合法公网 IP，再尝试 `remote addr`
- 仍然拿不到公网 IP，则直接进入固定拦截页

### 3. 未通过检查时不再返回 JSON，改为固定静态页

现在所有策略拦截都会返回统一静态页。

页面内容可在 [config.yaml](/C:/Users/mylo/Documents/milo2025/go/gw-ipinfo-nginx/configs/config.yaml) 中修改：

```yaml
deny_page:
  title: "Access Unavailable"
  heading: "Request Blocked"
  message: "Your request did not pass the gateway security checks."
  hint: "If you believe this is a mistake, contact support and provide the request ID."
```

### 4. nginx 目标地址只看配置

这部分已经支持两种方式：

- 同容器组 / 同 Compose 网络：`http://nginx:8081`
- 外部 nginx：`http://your-nginx.example.com:8080`

推荐直接改 `.env`：

```dotenv
NGINX_TARGET_URL=http://nginx:8081
```

YAML 中读取：

```yaml
routing:
  services:
    - name: "default"
      target_url: "${NGINX_TARGET_URL}"
```

## 最常见启动报错

### `ipinfo.token is required when ipinfo.enabled is true`

说明你打开了 IPinfo，但没有提供 token。

解决：

- 不测 IPinfo：`ipinfo.enabled: false`
- 要测 IPinfo：在 `.env` 里填 `IPINFO_TOKEN`

### `mongo.uri is required when ipinfo or alerts are enabled`

说明你打开了 IPinfo 或 alerts，但没有配置 Mongo。

解决：

- 不测这些功能：关掉对应开关
- 要测完整链路：补 `MONGO_URI` 和 `MONGO_APP_DATABASE`

### `alerts.telegram.bot_token is required when alerts.telegram.enabled is true`

说明你打开了 Telegram 告警，但没有配 token / chat id。

解决：

- 不测告警：`alerts.telegram.enabled: false`
- 要测告警：在 `.env` 里补 `TELEGRAM_BOT_TOKEN` 和 `TELEGRAM_CHAT_ID`

## 推荐调试方式

### 最小调试

目标：

- 只验证 gateway 到 nginx 的代理链路

建议开关：

```yaml
ipinfo:
  enabled: false

alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false

security:
  accept_language:
    require_header: false
```

### 联调 IPinfo / Mongo

建议：

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

### 联调 Telegram 告警

建议：

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

## 日志说明

当前主线日志会统一输出这些核心字段：

- `event`
- `request_id`
- `client_ip`
- `service_name`
- `upstream_url`
- `result`
- `reason_code`
- `cache_source`
- `latency_ms`

默认建议：

```yaml
logging:
  format: "text"
  level: "info"
```

这样在 Linux 终端里直接看更顺手。
