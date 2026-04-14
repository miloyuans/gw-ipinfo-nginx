# gw-ipinfo-nginx

完整中文使用文档：

- [docs/usage.zh-CN.md](./docs/usage.zh-CN.md)
- [docs/config-reference.zh-CN.md](./docs/config-reference.zh-CN.md)

`gw-ipinfo-nginx` 是一个 Go 网关服务。它先从请求头中提取真实公网客户端 IP，再执行请求级规则、IPinfo、Geo、Privacy 和短路缓存判定；放行后反向代理到配置好的 nginx 入口，未通过时返回固定静态拦截页。

当前主线版本重点补齐了：

- 高可用：Mongo 优先，但 Mongo 故障时自动降级到本地磁盘。
- 高并发：L1 分片缓存、短路缓存、异步写队列、可配置反向代理连接池。
- 可短路：命中最近的 IP 决策后直接复用，减少重复 IPinfo / Mongo /策略判定。
- 可降级：IP 缓存、短路缓存、告警 outbox、日报聚合都能落到本地磁盘。
- 可报表：异步聚合每日去重 IP 报告，并可通过 Telegram 发送 HTML + CSV。

## 核心目录

- `cmd/gateway/main.go`
- `configs/config.yaml`
- `configs/config.reference.zh.yaml`
- `internal/app`
- `internal/cache`
- `internal/shortcircuit`
- `internal/storage`
- `internal/localdisk`
- `internal/reporting`
- `internal/alerts`
- `docker-compose.yml`

## 高并发高可用架构

主请求链路顺序：

1. 提取真实公网客户端 IP。
2. 执行请求级规则：UA、`Accept-Language`。
3. 读取 IP 级短路缓存。
4. 短路未命中时，读取 IPinfo L1 / Mongo / 本地磁盘缓存，必要时才访问 IPinfo。
5. 执行 Geo / Privacy 策略。
6. 记录审计日志，异步写短路缓存、告警队列、日报聚合。
7. 代理到 `routing.services[].target_url`。

为什么短路缓存放在请求级规则之后：

- 这样不会绕过 UA / `Accept-Language` 这些本来就应该每次执行的安全边界。
- 只有 IP 级判断结果才会被短路复用，避免把一次 bot UA 误伤成同 IP 的长期 deny。

## Mongo 降级机制

Mongo 是共享缓存和共享 outbox 的首选存储，但不是主链路可用性的单点。

### 单机 Mongo、单节点副本集和 `retryWrites`

`retryWrites=false` 不是“不能高并发”，而是“对单机普通 mongod 更稳”的默认建议。

- 如果你是单机普通 Mongo：
  - 推荐 URI 使用 `directConnection=true&retryWrites=false`
  - `authSource` 必须写“用户实际创建在哪个数据库”；很多管理员账号实际在 `admin`
  - 因为它不是副本集，`replicaSet=...` 和 `w=majority` 没有实际收益，反而更容易在拓扑发现异常时触发 `ReplicaSetNoPrimary`
- 如果你是单节点副本集：
  - 只有在 `rs.status()` 明确显示 `PRIMARY`
  - 且 `rs.conf()` 中成员地址不是 `127.0.0.1/localhost`
  - 且网关 Pod 能访问该成员地址
  - 才建议使用 `replicaSet=mongodb-rs&retryWrites=true&w=majority`

当前代码已经支持这些 Mongo 连接池参数：

- `mongo.connect_timeout`
- `mongo.operation_timeout`
- `mongo.timeout`
- `mongo.maxOpenConns`，会映射为 Mongo Driver 的 `maxPoolSize`
- `mongo.maxIdleConns`，作为兼容别名，近似映射为 `minPoolSize`
- `mongo.minPoolSize`
- `mongo.maxConnecting`
- `mongo.connMaxLifetime`，作为兼容别名，近似映射为 `maxConnIdleTime`
- `mongo.maxConnIdleTime`

注意：`maxIdleConns` 和 `connMaxLifetime` 仍然只是兼容别名，不是 Mongo Go Driver 的原生参数。生产里更建议直接用：

- `maxPoolSize`
- `minPoolSize`
- `maxConnecting`
- `maxConnIdleTime`

当 Mongo 不可用时：

- 网关继续服务，不因为 Mongo 连接失败退出。
- 自动切换为 `data_source_mode=localdisk`。
- 本地 `bbolt` 文件继续承载：
  - IPinfo 缓存
  - 决策短路缓存
  - 告警 outbox
  - 日报聚合数据

当 Mongo 恢复时：

- 后台探测线程自动重连。
- 本地 dirty 数据异步回放到 Mongo。
- 回放成功后清理本地 dirty 标记。

关键日志：

- `mongo_degraded_to_local`
- `mongo_recovered_replaying_local`
- `mongo_replay_done`
- `mongo_replay_error`

## 短路缓存机制

短路缓存按真实客户端 IP 维度保存最近决策，默认 TTL 为 `10h`。

缓存字段包括：

- `client_ip`
- `last_decision`
- `last_reason_code`
- `country_code/country_name/region/city`
- `privacy flags`
- `first_seen_at/last_seen_at`
- `allow_count/deny_count`
- `short_circuit_allow_count/short_circuit_deny_count`
- `host/path`
- `user_agent_hash`

审计日志会明确记录：

- `short_circuit_hit`
- `short_circuit_source`
- `short_circuit_decision`
- `ipinfo_lookup_action`
- `data_source_mode`

## 日报说明

日报模块异步聚合去重 IP 统计，不阻塞请求路径。

每天定时发送两个附件：

- HTML 报告
- CSV 报表

报告按去重真实客户端 IP 汇总，包含：

- 放行次数 / 拦截次数
- 放行原因 / 拦截原因
- 国家 / 地区 / 城市
- Host / Path / URL 摘要
- UA 摘要
- 短路放行次数 / 短路拦截次数

聚合部分还会包含：

- 总请求数
- 去重 IP 数
- 放行总数 / 拦截总数
- TopN 拦截原因
- TopN 放行原因
- TopN 国家
- TopN Host
- TopN UA

## 本地运行

1. 准备环境变量：

```bash
cp .env.example .env
```

2. 启动：

```bash
chmod +x ./scripts/*.sh
sh ./scripts/up.sh
```

3. 查看日志：

```bash
sh ./scripts/logs.sh
```

4. 停止：

```bash
sh ./scripts/down.sh
```

默认入口：

- `http://127.0.0.1:8080`
- `http://127.0.0.1:8080/healthz`
- `http://127.0.0.1:8080/readyz`
- `http://127.0.0.1:8080/metrics`

本地持久化目录：

- Docker Compose 会把 `/data/shared` 挂到独立 volume
- 本地降级数据库默认路径：`/data/shared/gw-ipinfo-nginx.db`

## Docker 构建

```bash
docker compose up --build -d
```

## 配置说明

主配置文件：

- `configs/config.yaml`

中文注释版：

- `configs/config.reference.zh.yaml`

重点配置：

- `cache.short_circuit_ttl`
- `cache.local_fallback_ttl`
- `storage.local_path`
- `storage.mongo_probe_interval`
- `alerts.delivery.*`
- `alerts.telegram.command_bot.*`
- `reports.*`
- `performance.*`

## Telegram 指令查询

主线已内置一个可选的 Telegram 群交互查询机器人，配置入口在：

- `alerts.telegram.command_bot`

用途：

- 在指定群内通过命令查询一个或多个 IP 的 IPinfo `/lookup` 结果
- 保留中文交互提示和格式化输出
- 支持命令名自定义，默认是 `/q`
- 支持独立机器人配置；留空时自动回落到 `alerts.telegram` 的默认机器人配置
- 支持独立 `ipinfo_token`；留空时自动回落到全局 `ipinfo.token`
- 默认复用主程序相同的 IPinfo 缓存命中链、singleflight 去重和持久化缓存；只有独立 token 不同时才会拆出独立查询客户端
- 支持 `allowed_user_ids` 用户白名单；留空表示允许所有用户
- 支持多进程 / 多副本共享租约，只有持有租约的实例会真正轮询 Telegram，避免冲突

典型命令：

```text
/q 114.114.114.114 8.8.8.8
/q 2001:4860:4860::8888
```

## Kubernetes 与 Mongo 副本集

生产推荐：

- MongoDB Community Operator 管理的 3 节点副本集
- 网关多副本部署
- 每个 Pod 挂载共享目录到 `/data/shared`

代码层面已经按“Mongo 优先 + 本地降级”设计：

- Mongo 正常时，多个 Pod 共享 Mongo 中的 IP 缓存、短路缓存、告警 outbox
- Mongo 异常时，每个 Pod 仍可使用本地磁盘继续工作
- Mongo 恢复后，各 Pod 再异步回放自己的本地 dirty 数据

## QPS 资源建议

下面是工程经验建议值，不是压测承诺值。上线前请按你的规则集、日志量、IPinfo 开启比例和 nginx 后端特征做压测。

### 1k QPS

- CPU：2 vCPU
- 内存：2 GiB
- 网络：100 Mbps
- 磁盘：普通 SSD 即可
- Mongo：3 节点副本集，低配即可
- 本地目录：单独挂载一个持久目录给 `/data/shared`

### 5k QPS

- CPU：4 vCPU
- 内存：4 GiB
- 网络：300 Mbps
- 磁盘：SSD，保证低延迟 fsync
- Mongo：3 节点副本集，建议独立磁盘
- 建议：`cache.l1.shards=64`，保留默认代理连接池

### 10k QPS

- CPU：8 vCPU
- 内存：8 GiB
- 网络：1 Gbps
- 磁盘：NVMe 或高 IOPS SSD
- Mongo：3 节点副本集，建议专用节点和独立存储
- 建议：开启短路缓存、控制日志采样、提高 `async_write_queue_size`

### 20k QPS

- CPU：16 vCPU
- 内存：16 GiB 以上
- 网络：1-2 Gbps
- 磁盘：NVMe
- Mongo：3 节点副本集 + 更高连接池预算
- 建议：多 Pod 横向扩容，并减少不必要的高频日志字段输出

## 测试

如果本机已安装 Go：

```bash
go test ./...
```

这轮新增测试覆盖了：

- 短路命中 allow / deny
- 短路 TTL 过期
- 短路并发读取
- Mongo 降级与恢复回放控制器
- 日报 HTML + CSV 生成
- 告警入队失败不影响主流程
- 审计日志字段完整性

## 常见问题

### 1. Mongo 启动失败会不会导致网关退出

不会。当前主线会记录降级日志并继续使用本地磁盘模式运行。

### 2. 为什么日志里有 `short_circuit_hit=false`

这表示该请求没有命中最近的 IP 级决策，需要继续走 IPinfo / Geo / Privacy 链路。

### 3. 为什么 `cache_source=none` 但请求仍然放行

这通常表示请求没有走 IPinfo 缓存，而是命中了短路缓存或者当前 `ipinfo.enabled=false`。

### 4. 为什么报告里是去重 IP 视角

因为日报要求按真实客户端 IP 聚合，重点看“同一个 IP 的累计放行/拦截/短路情况”。
## Localdisk Notes

When the gateway runs in Kubernetes with multiple Pods sharing the same PVC, do not let different Pods open the same `bbolt` file.

This project now auto-scopes the local fallback database path at runtime when `POD_NAME` or prefork worker metadata is present:

- `/data/shared/<pod-name>/gw-ipinfo-nginx.db`

Each Pod only writes its own shard file, but the degraded-mode read path will scan peer shard files under the shared directory.
That means local fallback is no longer "all Pods write one file", but it is also not "each Pod is fully isolated and cannot see peer data".

This avoids `open localdisk db: timeout` during rolling updates or multi-replica deployments where old and new Pods briefly overlap.

## Prefork

Linux deployments can optionally enable `server.prefork.enabled=true` and set `server.prefork.processes`.

- Mongo healthy: normal concurrent Mongo read/write path stays unchanged.
- Mongo degraded: each worker writes only its own local shard and reads peer shards from the shared directory.
- Daily reports run only in the primary prefork worker, and also use a shared leader lease across pods, so each report is sent once globally.

## Route Sets

The gateway can now compile five route-set files in parallel:

- `configs/bypassroute.yaml`
- `configs/defaultroute.yaml`
- `configs/passroute_v1.yaml`
- `configs/passroute_v2.yaml`
- `configs/passroute_v3.yaml`

Main config lives in `configs/config.yaml` under `route_sets`.
V4 fallback runtime lives under the top-level `v4` config block. Its host-level overlay file is `configs/passroute_v4.yaml`, but it is not compiled into the `bypass/default/v1/v2/v3` route-set compiler.

Behavior:

- `bypass`: still runs request-level bot / crawler checks and optional IPinfo lookup, then skips the later Geo / Privacy deny chain and proxies directly to the configured backend service.
- `default`: only declares which `host + path_prefix` entries may use the existing default gateway flow.
- `v1`: source host/path runs the full detection flow, then issues a signed grant and redirects to `target.public_url`.
- `v2`: source host/path runs the full detection flow, then redirects to `target.public_url` without grant lifecycle.
- `v3`: source host/path can choose a healthy target from a pool and redirect to that target URL. It supports `random`, `round_robin`, and `weighted_round_robin`, per-target health checks, and temporary client-IP binding.
- `v4`: only runs after `route_sets` did not match. It uses a last-good snapshot compiled from nginx `server_name` plus `configs/passroute_v4.yaml` host entries, and then chooses `passthrough` or `degraded_redirect` from runtime state. Legacy `v4.overrides` is still read during the compatibility window, but is deprecated.

### Functional Modes

- `default`
  - Used when you want an explicit `host + path_prefix` to keep using the existing full gateway chain.
  - No redirect and no grant lifecycle.
  - If every `route_sets.*.enabled=false`, the whole gateway also falls back to the legacy default flow.

- `bypass`
  - Used for lightweight direct pass scenarios.
  - Still keeps request-level UA / crawler / `Accept-Language` checks and optional IPinfo lookup.
  - Skips later Geo / Privacy deny logic and proxies directly to the selected backend service.

- `v1`
  - Source host/path runs the full detection flow.
  - After allow, gateway issues a signed grant and redirects to `target.public_url`.
  - Target host later validates query/cookie grant and short-circuits to backend.

- `v2`
  - Source host/path runs the full detection flow.
  - After allow, gateway redirects directly to `target.public_url`.
  - Target host is allowed to re-enter the gateway and continue the full chain.

- `v3`
  - Source host/path selects a healthy target from a pool.
  - Supports `random`, `round_robin`, `weighted_round_robin`, per-target health checks, and temporary client-IP binding reuse.
  - Can run in lightweight redirect mode or full security-filter mode before redirect.

- `v4`
  - Not part of the strong route-set compiler.
  - Only runs after `route_sets` did not match.
  - Builds a shared last-good snapshot from nginx `server_name` plus `configs/passroute_v4.yaml`.
  - Default behavior is passthrough, default security checks are off, and enrichment defaults to `disabled`.
  - Probe is opt-in per host. Only hosts with `probe.enabled=true` are actively probed.
  - Probe can discover jump URLs from a remote HTML page, local HTML files, or local JS files.
  - Multiple discovered jump URLs are deduplicated, written into the probe workspace, and checked one by one.
  - Default probe behavior is `3s` interval, `404` treated as unhealthy, and `3` consecutive failures before switching to degraded redirect.

### Default And Deny Behavior

- Legacy default mode
  - When all `route_sets.*.enabled=false`, requests use the original full gateway chain and proxy to `routing.default_service`.

- Blacklist / deny mode
  - Any request denied by UA / Accept-Language / Geo / Privacy / route miss / v1 grant validation enters the existing global deny path.
  - The deny path can either render the built-in block page, reverse-proxy to `deny_page.target_url`, or 302 redirect to `deny_page.target_url` when `deny_page.redirect_enabled=true`.

### V4 Runtime Notes

- `route_sets.shared_manifest_enabled`
  - The compiled `bypass/default/v1/v2/v3` route-set manifest is persisted to shared storage first, with Mongo as the global source of truth.
  - Replicas load the shared manifest instead of relying on per-pod local compiler output.
  - Localdisk only keeps the degraded copy and replay buffer.

- `route_sets.v4`
  - Only provides the file path for `configs/passroute_v4.yaml`.
  - It does not make v4 part of the strong route compiler.

- `v4.ingress.config_paths`
  - Supports files, directories, and glob paths.
  - Directories are scanned recursively for `*.conf`.

- `v4` snapshot leader
  - Only one leader instance periodically parses nginx conf and writes the shared snapshot.
  - Other replicas only refresh and read the last-good snapshot from shared storage.

- `v4` storage model
  - Mongo is the source of truth for snapshot, runtime state, and recent events.
  - Localdisk remains fallback and replay buffer.

- `v4` last-good behavior
  - Parse or sync failure emits an event and log, but does not clear the previous last-good snapshot.
  - If no snapshot is available, the gateway logs `v4_fallback_to_legacy=true` and falls back to legacy routing where applicable.

- `v4` probe behavior
  - `probe.url` fetches a remote HTML entry page and only analyzes inline JS plus same-host `script src` JS assets.
  - `probe.html_paths` reads one or more local absolute HTML files and extracts candidate jump URLs from inline JS plus referenced local JS files.
  - `probe.js_paths` reads one or more local absolute JS files and extracts candidate jump URLs directly.
  - `probe.link_url` is an explicit target matcher with higher priority than `probe.patterns`.
  - `probe.patterns` uses plain substring match first and regexp as fallback.
  - `probe.redirect_urls` defines the fixed failover destinations that traffic switches to after the host becomes unhealthy; when multiple destinations are configured, the runtime prefers a random healthy target.
  - `probe.unhealthy_status_codes` defines which HTTP statuses are considered unhealthy; default is `404`.
  - Probe discoveries and failures are written to `v4.probe_defaults.workspace_dir`.
  - Default extraction is intentionally bounded to explicit redirect patterns such as `linkUrl`, `iosUrl`, `androidUrl`, `redirectUrl`, `window.location`, and `location.href`; generic page anchors are ignored.
  - Telegram notifications only send the actual switch and restore actions; the lower-level `domain_unhealthy` and `domain_recovered` events are still persisted but not pushed as duplicate chat messages.

- `v4` Telegram `/routes`
  - Only reads persisted snapshot / sync state / runtime state / recent events.
  - It does not parse nginx conf live.
  - The message body is intentionally short and defaults to Top 3 hosts.
  - `v4.telegram.max_hosts` controls the summary host count.
  - Full route details are sent as an HTML attachment.
  - The HTML attachment includes a bilingual field guide for each route column.
  - When a last-good snapshot is still available but the latest sync failed, `/routes` reports `degraded` instead of treating the whole runtime as unavailable.
  - Route switch notifications use a compact bilingual template and only show host, source URL, failover URL, target URL, action, result, and reason.

Compiler rules:

- startup loads every enabled file together
- all source routes are normalized into one global unique `host + path_prefix` table
- duplicate source keys across `bypass / default / v1 / v2 / v3` fail startup
- same target host must keep the same `rule_kind + backend_service + backend_host`
- `target.public_url` must be absolute `http/https`
- `backend_service` must exist in `routing.services`

Runtime rules:

- `bypass` source rules are matched before the other source rule kinds
- source matching uses exact host + longest path prefix
- `v1` target host validates query grant first, then cookie grant
- `v2` target host can directly enter the full detection flow
- `v3` source rules can run in lightweight redirect mode or full-security-filter mode before choosing a target
- `v4` is a fallback overlay only; it does not change the semantics of `bypass / default / v1 / v2 / v3`
- `v4` with `security_checks_enabled=false` skips request-level security checks and Geo / Privacy deny, keeps best-effort real IP extraction, logging, reporting, and direct proxying
- `v4` IP enrichment modes are `disabled`, `cache_only`, and `full`
- `v4` probes only run for hosts with explicit `probe.enabled=true`
- Telegram `/routes` queries only read persisted snapshot / runtime state / events; they do not parse nginx conf live
- when `route_sets.strict_host_control=true`, only compiled source/target hosts are accepted
- unmatched requests are denied with `deny_route_not_found`

## Report Delivery

Daily reports now keep a persistent delivery ledger per day.

- sink delivery state is tracked independently for Telegram HTML, Telegram CSV, file HTML, and file CSV
- scheduler leadership is coordinated by `reports.leader_lease_name`, `reports.leader_lease_ttl`, and `reports.leader_renew_interval`
- scheduler retries failed or partially delivered days using `reports.retry_interval`
- scheduler backfills previous days inside `reports.max_backfill_days`
- repeated `daily_report_skipped_before_time` log spam is suppressed
- HTML title and Telegram caption use `reports.title`

## Telegram Lifecycle

Telegram lifecycle notifications now support:

- `alerts.telegram.display_name`
- `alerts.telegram.title_prefix`
- chat reachability verification during self-check
- clearer lifecycle events such as `telegram_healthcheck_started`, `telegram_healthcheck_ok`, and `telegram_healthcheck_error`

New audit fields:

- `route_set_kind`
- `route_id`
- `source_host`
- `source_path_prefix`
- `target_host`
- `target_public_url`
- `backend_service`
- `backend_host`
- `grant_status`
- `grant_expire_at`
