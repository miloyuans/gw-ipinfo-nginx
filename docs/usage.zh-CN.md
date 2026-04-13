# gw-ipinfo-nginx 中文使用文档

## 1. 项目定位

`gw-ipinfo-nginx` 是一个部署在 Nginx 前面的 Go 网关。它负责：

- 从请求头中提取真实客户端 IP
- 执行 UA、`Accept-Language`、Geo、Privacy、短路缓存等判定
- 按不同路由模式决定透传、跳转、短路授权或故障切换
- 通过 Telegram 发送告警、日报和交互查询结果
- 在 Mongo 不可用时自动降级到本地磁盘继续运行

主程序默认监听 `:8080`，放行后代理到 `routing.services[].target_url` 指定的 Nginx 或其它上游。

---

## 2. 核心运行流程

### 2.1 基础主链路

在未命中特殊路由模式时，请求大致按以下顺序处理：

1. 旁路系统路径  
   `/healthz`、`/readyz`、`/metrics` 等内部路径直接返回
2. 提取真实客户端 IP
3. 执行请求级拦截
   - UA bot/crawler 关键字
   - UA deny 正则
   - `Accept-Language`
4. 执行短路缓存 / IPinfo / Geo / Privacy 判定
5. 记录审计日志、统计、报表原始事件
6. 放行则反代到上游，拒绝则返回 deny 页面或 deny 反代地址

### 2.2 路由优先级

当前主线优先级是：

1. 系统保留路径
2. `route_sets` 命中的规则
   - `bypass`
   - `default`
   - `v1`
   - `v2`
   - `v3`
   - `v1/v2` target host
3. `v4` fallback runtime
4. legacy 默认链路或未命中拒绝

`v4` 不参与 `route_sets` 五类强规则编译，它只在前面都没命中时作为 fallback overlay 介入。

---

## 3. 六类功能模式简介

这里按你实际运维最关心的维度总结：默认、黑名单、安全直通、v1、v2、v3、v4。

### 3.1 默认路由模式 `default`

用途：

- 让指定域名 / 路径走当前仓库“完整默认安全链路”
- 不做跳转
- 不做 grant
- 通过后直接代理到默认 backend service

配置文件：

- `configs/defaultroute.yaml`

典型场景：

- 某些稳定站点仍希望沿用老的 Geo / Privacy / short-circuit 判定

### 3.2 黑名单 / 安全拦截模式

这不是单独的 route set，而是默认安全链本身的能力，主要包括：

- UA deny keyword
- UA deny pattern
- `Accept-Language` 检查
- Geo 白名单
- Privacy deny
- deny page / deny target

配置位置：

- `security.ua`
- `security.accept_language`
- `security.geo`
- `security.privacy`
- `deny_page`

典型场景：

- 拦截 bot、爬虫、无语言头流量
- 只允许某些国家或城市访问
- 拦截 VPN / proxy / tor / hosting / residential proxy

### 3.3 轻量直通模式 `bypass`

用途：

- 命中后只保留前置请求级检查
- 保留 best-effort real IP 提取
- 保留 IPinfo 缓存 / 查询
- 跳过后续 Geo / Privacy deny 和安全决策短路缓存
- 直接代理到配置的 backend service

特点：

- real IP 提取失败不拒绝
- IPinfo 失败不拒绝
- 仍然会被 UA / `Accept-Language` 拦截

配置文件：

- `configs/bypassroute.yaml`

典型场景：

- 广告页、活动页、下载页，只希望保留最低限度机器人过滤，不希望被后期 Geo / Privacy 拦截误伤

### 3.4 一次授权跳转模式 `v1`

用途：

- source host 先走完整检测链
- 通过后签发 grant token，并 302 跳转到 target public URL
- target host 首次通过 query 中的 grant 完成授权交换，写 cookie
- 后续 target host 请求只做 grant、UA、IP 段复验与审计，不再重走完整安全链

特点：

- 适合“入口域名做重风控，目标域名做短路授权”的方案
- grant 过期后必须重新从 source 域名进入

配置文件：

- `configs/passroute_v1.yaml`

典型场景：

- A 域做风控，放行后跳 B 域继续承接落地页

### 3.5 二次检测跳转模式 `v2`

用途：

- source host 先走完整检测链
- 通过后直接 302 到 target public URL
- target host 允许直接进入网关
- target host 继续走完整检测链

特点：

- 不做 grant
- 不做 target host 的短路授权
- target host 仍然按完整安全链判断

配置文件：

- `configs/passroute_v2.yaml`

典型场景：

- 需要入口和目标都保留完整风控判定

### 3.6 目标池与绑定模式 `v3`

用途：

- 一个 source host 绑定一个 target pool
- 按策略选择目标
- 允许健康检查、绑定复用、目标切换

特点：

- 适合多目标站点池切换
- 比 v2 多了“选池”和“绑定”语义

配置文件：

- `configs/passroute_v3.yaml`

典型场景：

- 同一入口域名后面挂多组目标站点，需要按策略分发或切换

### 3.7 自动 host fallback 模式 `v4`

用途：

- 不加入 `route_sets` 五类编译器
- 通过解析 Nginx `server_name` 自动生成 host 路由快照
- 当前面所有强规则都未命中时，v4 接管
- 默认透传，默认关闭安全检查
- 只对显式开启 probe 的 host 做故障探测与切换

特点：

- `passroute_v4.yaml` 只做 host 级 overlay，不替代自动生成路由表
- v4 正常态是 passthrough 反代
- v4 故障态是 302 跳转到 failover URL
- Mongo 是全局事实源，本地磁盘只是 fallback 和 replay buffer

配置文件：

- 主配置：`v4`
- host overlay：`configs/passroute_v4.yaml`

典型场景：

- Nginx 上已有大量 `server_name` 站点，希望自动纳管
- 只有部分站点需要启用 HTML/JS 跳转探测和故障切换

---

## 4. 配置文件说明

### 4.1 主配置

主配置文件：

- `configs/config.yaml`

中文注释参考：

- `configs/config.reference.zh.yaml`
- `docs/config-reference.zh-CN.md`

### 4.2 路由文件

- `configs/defaultroute.yaml`
- `configs/bypassroute.yaml`
- `configs/passroute_v1.yaml`
- `configs/passroute_v2.yaml`
- `configs/passroute_v3.yaml`
- `configs/passroute_v4.yaml`

### 4.3 路由文件之间的关系

- `default / bypass / v1 / v2 / v3` 会参与全局冲突校验
- `(host, path_prefix)` 在这些强规则中必须唯一
- `v4` 不加入上述编译器
- `v4` 以 Nginx `server_name` 自动快照为主，`passroute_v4.yaml` 只做覆盖和增强

---

## 5. 默认模式下的最小运行方式

如果所有 `route_sets.*.enabled=false`，系统行为是：

1. 所有业务请求走默认完整安全链
2. 通过后按 `routing.default_service` 代理到 Nginx
3. 拒绝时走 `deny_page`

这时你可以把它理解成：

- 放行：一个域名或多个域名统一通过默认后端 Nginx
- 拦截：返回静态拦截页或反代到指定 deny 地址

---

## 6. `route_sets` 使用说明

### 6.1 开启 route_sets 后的行为

只要任意一个 `route_sets.*.enabled=true`，系统就会进入“显式路由模式”：

- 请求必须命中某条 `bypass/default/v1/v2/v3` 规则
- 或命中 `v1/v2` target host
- 否则就会：
  - `deny_host_not_allowed`
  - 或 `deny_route_not_found`

这意味着：

- **不会自动回退到旧默认链路**
- 如果你希望某些域名继续走老的完整默认链路，必须同时启用 `route_sets.default`

### 6.2 `strict_host_control`

当 `route_sets.strict_host_control=true` 时：

- 只有被收录进已编译路由表的 host 才允许进入业务链路
- 其它 host 会直接 `deny_host_not_allowed`

### 6.3 `fail_fast_on_conflict`

当 `route_sets.fail_fast_on_conflict=true` 时：

- 配置冲突将直接导致启动失败
- 常见冲突：
  - 同一个 `(host, path_prefix)` 被多个强规则重复定义
  - `v1/v2/v3` target backend 映射不一致

---

## 7. V4 使用说明

### 7.1 V4 的两层配置

#### 第一层：自动生成路由表

来源：

- `v4.ingress.config_paths`

系统会后台解析 Nginx `server_name`：

- 支持单文件
- 支持目录递归扫描 `*.conf`
- 支持 glob

生成 last-good snapshot 后：

- 所有 Pod 都读同一份 Mongo 中的 snapshot
- Mongo 不可用时退到本地 last-good snapshot

#### 第二层：host overlay

来源：

- `configs/passroute_v4.yaml`

这个文件只负责覆盖 host 的：

- backend service / host
- security checks
- IP enrichment mode
- probe / failover

没有写进 `passroute_v4.yaml` 的 host，只要在 snapshot 里，也仍然会继续走 v4 自动路由。

### 7.2 V4 默认语义

默认值：

- `passthrough` 模式
- `security_checks_enabled=false`
- `ip_enrichment.mode=disabled`
- 只有显式开启 `probe.enabled=true` 的 host 才探测

也就是说，v4 默认是：

- 最短链路透传
- 最少安全阻断
- 只保留日志、指标、best-effort client IP、反代

### 7.3 V4 的三种 enrichment 模式

- `disabled`
  - 默认关闭 enrichment
  - 优先 cache-only
  - 不主动打远程 IPinfo
- `cache_only`
  - 只查缓存，不走远程
- `full`
  - 允许走完整 IP enrichment 链

### 7.4 V4 probe 的业务逻辑

你要求的 v4 探测逻辑已经按以下方式收敛：

1. 只对显式启用 probe 的 host 生效
2. 从以下来源提取跳转目标
   - 远程 HTML 页面
   - 本地 HTML 文件
   - 本地 JS 文件
3. 只抓显式跳转变量或语句
   - `linkUrl`
   - `iosUrl`
   - `androidUrl`
   - `jumpUrl`
   - `redirectUrl`
   - `downloadUrl`
   - `targetUrl`
   - `window.location`
   - `location.href`
   - `window.open`
4. 去重后写入工作区
5. 对这些 URL 进行健康探测
6. 命中 `unhealthy_status_codes` 时记为异常
7. 默认每 `3s` 探测一次，连续 `3` 次异常后切换
8. 恢复后自动把流量切回原始 passthrough

### 7.5 V4 probe 配置字段中文解释

以 `passroute_v4.yaml` 中某个 host 为例：

```yaml
routes:
  - id: "freespin-diy"
    host: "game.freespin.diy"
    enabled: true
    backend:
      service: "luodiye"
      host: "game.freespin.diy"
    security_checks_enabled: false
    ip_enrichment_mode: "disabled"
    probe:
      enabled: true
      mode: "html_discovery"
      url: "https://game.freespin.diy/0927/index.html"
      html_paths: []
      js_paths: []
      link_url: ""
      patterns:
        - "vpbet"
      redirect_urls:
        - "https://vpbet.com"
        - "https://vpbet.net"
      unhealthy_status_codes:
        - 404
      interval: 3s
      timeout: 3s
      healthy_threshold: 2
      unhealthy_threshold: 3
      min_switch_interval: 2m
```

字段解释：

- `host`
  - v4 匹配维度是 host 级，不是 host+path 级
- `backend.service`
  - 正常态透传时使用的后端 service
- `backend.host`
  - 正常态透传时覆盖给上游的 Host
- `security_checks_enabled`
  - 是否开启完整安全链
- `ip_enrichment_mode`
  - `disabled / cache_only / full`
- `probe.enabled`
  - 是否对该 host 启用探测
- `probe.mode`
  - `html_discovery` 或 `local_js`
- `probe.url`
  - 远程探测入口 URL，可带路径
- `probe.html_paths`
  - 本地 HTML 绝对路径列表
- `probe.js_paths`
  - 本地 JS 绝对路径列表
- `probe.link_url`
  - 期望匹配的明确跳转地址
- `probe.patterns`
  - 目标 URL 匹配规则，普通字符串优先，正则兜底
- `probe.redirect_urls`
  - 故障切换时可跳转的目标 URL 列表
- `probe.unhealthy_status_codes`
  - 命中这些状态码就视为异常
- `probe.interval`
  - 探测周期，默认 `3s`
- `probe.unhealthy_threshold`
  - 连续异常次数，默认 `3`
- `probe.healthy_threshold`
  - 恢复判定连续成功次数
- `probe.min_switch_interval`
  - 最短切换间隔，防抖

### 7.6 V4 正常态和故障态

#### 正常态

- 运行模式：`passthrough`
- 网关行为：反代到 `backend.service`

#### 故障态

- 运行模式：`degraded_redirect`
- 网关行为：`302` 跳转到 `redirect_urls` 中选出的健康目标

当前主线里，v4 故障切换是 **跳转**，不是反代。

### 7.7 V4 与路径的关系

当前 v4 是 **host 级 runtime state**，不是 path 级。

这意味着：

- `probe.url` 可以带路径，比如 `/9527/index.html`
- 但探测结果控制的是整个 host 的流量模式
- 不会只对某个 path 生效

例如：

- 你用 `https://freegame.ink/9527/index.html` 做探测入口
- 一旦探测异常，切换的是整个 `freegame.ink` 的流量行为

---

## 8. Telegram 功能说明

### 8.1 告警通知

支持：

- 启动 / 关闭通知
- 不干净退出通知
- 健康检查
- 业务告警
- v4 route 事件

### 8.2 `/q` 交互查询机器人

作用：

- 在指定群内查询一个或多个 IP 的 `/lookup` 结果

特点：

- 支持独立机器人配置，留空时回落到全局 Telegram 配置
- 复用主程序相同的缓存命中链
- 默认只允许指定群使用
- 支持用户 ID 白名单
- 多 Pod / 多进程下通过租约避免重复轮询

查询次数说明：

- 对同一个被查询 IP，按**当前服务运行期内**递增展示
- 例如：
  - 首次查询 / First query
  - 第 2 次查询 / 2nd query
- 服务重启后计数会重置
- 这是轻量交互计数，不是精确审计计数

### 8.3 `/routes` 路由状态查询

作用：

- 查询 v4 快照、运行态和最近事件

特点：

- 只查数据库 / 本地持久化
- 不现场解析 conf
- 正文只显示摘要和 Top Hosts
- 全量详情通过 HTML 附件发送

---

## 9. 缓存与存储说明

### 9.1 L1 缓存

- 进程内分片缓存
- 主要承接热点 IPinfo 结果和短路结果
- 目标是降低锁竞争和对象分配

### 9.2 Mongo

Mongo 正常时，它是共享事实源，负责：

- IPinfo 缓存
- 短路缓存
- alerts outbox
- reports 原始聚合
- v4 snapshot
- v4 runtime state
- v4 recent events

### 9.3 localdisk

Mongo 异常时自动降级到本地磁盘，继续承接：

- IP cache
- decision short-circuit cache
- alerts outbox
- reports aggregates
- v4 snapshot / runtime / events fallback

恢复后自动 replay 回 Mongo。

---

## 10. 日报说明

系统支持异步日报：

- HTML 报告
- CSV 报表

日报支持：

- Telegram 发送
- 本地落文件
- 单实例 leader lease，避免多 Pod 重复发送

统计维度包括：

- 去重 IP
- allow / deny 次数
- reason topN
- 国家 / 地区 / 城市
- Host / Path
- UA 摘要
- `route_set_kind`
- `route_id`
- `v4` 运行模式相关维度

---

## 11. 典型部署方式

### 11.1 本地 Docker / Compose

适合：

- 单机联调
- 本地验证 Nginx sidecar
- 本地验证 Telegram / 报表 / v4

常用命令：

```bash
sh ./scripts/up.sh
sh ./scripts/down.sh
```

### 11.2 Kubernetes

适合：

- 多副本网关
- 共享 Mongo
- 共享 PVC
- sidecar Nginx 或外部 Nginx 上游

建议：

- Gateway 对外端口 `8080`
- Nginx sidecar 仅 Pod 内访问
- `/data/shared` 作为共享持久化目录
- Mongo 优先使用副本集

---

## 12. 常见问题

### 12.1 为什么启用了某个 route set 后，未配置的域名不能自动走默认规则

因为只要任意 `route_sets.*.enabled=true`，系统就进入显式路由模式。

未命中时不会自动回退到旧默认链路。  
如果你希望某些 host 继续走默认完整链路，需要显式开启：

- `route_sets.default.enabled=true`

并把这些 host 写进 `defaultroute.yaml`。

### 12.2 为什么查询结果看起来像缓存异常

不一定是缓存坏了。常见原因是：

- 上游对特殊/保留地址返回的是稀疏结果
- 机器人以前只把空字段显示成 `-`

当前主线已经会明确显示：

- `Special IP（特殊地址）`
- `Lookup Note（查询说明）`

### 12.3 为什么同一天会收到多份日报

正常情况下不会。当前主线已经加了：

- 日报全局 leader lease

多 Pod / 多进程下只有一个实例会真正执行日报发送。

### 12.4 为什么 v4 host 没有进入自动路由

检查：

1. `v4.enabled=true`
2. `v4.ingress.config_paths` 是否覆盖到实际 Nginx conf
3. conf 里是否真的有对应 `server_name`
4. `/routes` 里是否能看到该 host

---

## 13. 推荐阅读顺序

1. [README.md](../README.md)
2. [docs/config-reference.zh-CN.md](./config-reference.zh-CN.md)
3. [configs/config.reference.zh.yaml](../configs/config.reference.zh.yaml)
4. 你的实际 `configs/config.yaml`
5. 如使用 v4，再看 `configs/passroute_v4.yaml`

