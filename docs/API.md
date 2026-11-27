# acmesh-panel HTTP API 参考

本文描述 acmesh-panel v0.1.73 的全部 HTTP 接口。面板是单二进制服务，默认监听容器内 `0.0.0.0:8080`，通常由 nginx / Caddy 反向代理对外提供 HTTPS。所有路径均以 `/api` 开头。

> 仅限管理你拥有或已获明确授权的域名与服务器。详见 [DISCLAIMER.md](../DISCLAIMER.md)。

## 1. 认证方式

面板支持两种认证方式，**不可混用**：

| 方式 | 适用范围 | 凭据 | 状态变更 |
|---|---|---|---|
| 会话 Cookie | 前端全部接口 | 登录后下发 `HttpOnly` Cookie；写操作另需 `X-CSRF-Token` | 允许 |
| 只读 API Token | 标记的 GET 端点 | `X-API-Token: acmp_...` | **禁止** |

### 1.1 会话登录

```http
POST /api/login
Content-Type: application/json

{"username": "admin", "password": "..."}
```

响应包含 `csrf` 字段。后续所有状态变更请求（POST / DELETE）都必须在请求头携带 `X-CSRF-Token: <csrf>`。未登录访问受保护接口返回 `401`，CSRF 缺失或错误返回 `403`。登录失败按 IP + 用户名指数退避锁定。

会话存放在内存中，面板重启后失效；空闲超时与最长有效期双重限制。可在「安全中心 → 会话管理」强制下线。

### 1.2 只读 Token

在「安全中心 → 只读令牌」创建。Token 明文**仅在创建响应中显示一次**，服务端只保存 SHA-256 哈希。

```bash
curl -H "X-API-Token: acmp_xxxxxxxx" https://acme.example.com/api/certs
```

Token 仅允许 `GET` / `HEAD`，且必须落在授权的 scope 内：

| Scope | 可访问的只读端点 |
|---|---|
| `certs` | `/api/certs`、`/api/certs/{name}` |
| `jobs` | `/api/jobs` |
| `sync` | `/api/sync/*`、`/api/remote/*`（仅 GET） |
| `audit` | `/api/audit` |
| `overview` | `/api/overview`、`/api/storage`、`/api/health/report` |

创建时不选 scope 表示允许全部只读端点。Token 不能访问令牌管理、改密、备份导出、私钥读取等敏感端点；即使携带会话 Cookie，只要请求头出现 `X-API-Token`，就按 Token 权限判定，避免会话掩盖越权。Token 同时受 IP 白名单与「仅允许 HTTPS」策略约束。

### 1.3 通用响应格式

成功返回 JSON；失败返回：

```json
{"error": "错误描述"}
```

常用状态码：`400` 参数错误、`401` 未认证、`403` 无权限 / CSRF 失败、`404` 资源不存在、`409` 状态冲突、`429` 请求过于频繁、`202` 任务已排队。

## 2. 总览与证书

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/health` | 无 | 容器健康检查；即使开启 HTTPS-only 也放行 |
| GET | `/api/overview` | 读 | 首页概览统计 |
| GET | `/api/storage` | 读 | 存储使用量 |
| GET | `/api/certs` | 读 | 证书列表 |
| GET | `/api/certs/{name}` | 会话 | 证书详情（含 SAN、签发者、有效期、文件清单） |
| GET | `/api/certs/{name}/pem/{kind}` | 会话 | 读取证书 PEM；`kind` 为 `cert` / `chain` / `fullchain` / `key` |
| POST | `/api/certs/{name}/key` | 会话 | 查看私钥，需二次确认；60 秒后前端清屏并记审计 |
| POST | `/api/certs/{name}/renew` | 会话 | 续期单张；body `{"force": false}` |
| POST | `/api/certs/{name}/revoke` | 会话 | 吊销证书 |
| POST | `/api/certs/{name}/remove` | 会话 | 移除证书；body `{"purge": false}` 可同时清理目录 |
| POST | `/api/certs/{name}/install` | 会话 | 部署证书到配置的目录 |
| POST | `/api/certs/{name}/email` | 会话 | 设置该域名专属 ACME 邮箱 |
| POST | `/api/certs/{name}/verify` | 会话 | 校验链、私钥匹配、有效期与 OCSP 状态 |
| POST | `/api/issue` | 会话 | 签发单张证书 |
| POST | `/api/issue/batch` | 会话 | 批量签发，最多 50 个域名 |
| POST | `/api/renew-all` | 会话 | 运行 `acme.sh --cron` 检查全部续期 |

### 2.1 批量签发

```http
POST /api/issue/batch
Content-Type: application/json

{
  "domains": ["example.com", "*.example.com", "www.example.com"],
  "credential": "my-dns",
  "keylength": "ec-256",
  "ca": "letsencrypt",
  "email": "admin@example.com",
  "dns_sleep": 0,
  "force": false
}
```

`credential` 为已保存的凭证名；留空时用 `code` + `env` 临时填写。`keylength` 支持 `ec-256`、`ec-384`、`2048`、`4096`。同一主域的裸域与泛域（如 `example.com` 与 `*.example.com`，去掉 `*.` 前缀后相同）会合并为一张证书、一个任务——它们共用同一条 `_acme-challenge` TXT 记录，并行签发在 DuckDNS 等服务商上会互相覆盖；其余域名各自独立排队。返回 `{"jobs": [{"id", "domain", "domains", "cert_name"}], "count": 任务数, "queued": true}`，`domains` 为该任务覆盖的完整域名列表。

### 2.2 批量续期

```http
POST /api/expiry/renew
Content-Type: application/json

{"names": ["example.com", "example.com_ecc"], "force": false}
```

`names` 为到期看板返回的证书 `name` 字段；自动去重、最多 50 个、非法证书名直接拒绝。不存在的证书会被跳过并在 `skipped` 中列出。返回 `202` 与 `{"jobs": [{"id": "...", "domain": "...", "name": "..."}], "queued": 2, "skipped": []}`。

## 3. 任务

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/jobs` | 读 | 任务列表 |
| GET | `/api/jobs/{id}` | 会话 | 任务详情 |
| GET | `/api/jobs/{id}/events` | 会话 | 实时日志（SSE） |
| POST | `/api/jobs/{id}/cancel` | 会话 | 取消任务 |
| POST | `/api/jobs/{id}/retry` | 会话 | 手动重试 |
| GET | `/api/retry/policy` | 会话 | 查询指数退避策略 |
| POST | `/api/retry/policy` | 会话 | 修改退避策略；body 含 `enabled`、`max_attempts`、`base_delay`、`max_delay` |
| GET | `/api/retry/queue` | 会话 | 当前等待自动重试的任务 |

## 4. 凭证与 CA

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/providers` | 会话 | DNS provider 目录与已保存凭证（仅掩码） |
| POST | `/api/providers` | 会话 | 保存凭证 |
| DELETE | `/api/providers/{name}` | 会话 | 删除凭证 |
| GET | `/api/catalog` | 会话 | CA、密钥类型、DNS provider 目录；含 `default_ca`、`ca_locked`、`ca_options` |
| GET | `/api/acme/accounts` | 会话 | acme.sh 账户摘要，不回显账户私钥 |
| POST | `/api/acme/accounts/default` | 会话 | 切换面板默认 CA；body `{"ca": "zerossl"}`。环境变量 `ACME_PANEL_CA` 锁定时返回 `409` |
| POST | `/api/acme/accounts/key` | 会话 | 导出账户私钥；body `{"id": "...", "password": "当前登录密码"}`。返回 PEM 附件，写入审计 |

## 5. 通知

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/notify/catalog` | 会话 | 可订阅事件、渠道类型、静默窗口配置 |
| GET | `/api/notify` | 会话 | 通知渠道列表（凭证掩码）与默认邮箱 |
| POST | `/api/notify` | 会话 | 新增 / 修改渠道 |
| DELETE | `/api/notify/{id}` | 会话 | 删除渠道 |
| POST | `/api/notify/{id}/test` | 会话 | 发送测试消息；**不受静默窗口影响** |
| POST | `/api/notify/default-email` | 会话 | 设置全局默认 ACME 邮箱 |
| GET | `/api/notify/quiet` | 会话 | 静默窗口配置与 `active` 状态 |
| POST | `/api/notify/quiet` | 会话 | 保存静默窗口 |

静默窗口 body：

```json
{
  "enabled": true,
  "start_hour": 22,
  "end_hour": 7,
  "days": [1, 2, 3, 4, 5],
  "allow_critical": true
}
```

`days` 为 `0`（周日）至 `6`（周六），空数组表示每天。`start_hour > end_hour` 表示跨午夜窗口。`allow_critical` 为 `true` 时，安全告警与签发 / 续期失败仍会推送。

## 6. 运维中心

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/api/health/check` | 会话 | 立即执行健康自检并保存快照 |
| GET | `/api/health/report` | 读 | 最近 20 次自检结果 |
| GET | `/api/expiry` | 读 | 到期看板四档分组与计数 |
| GET | `/api/backups/config` | 会话 | 自动备份策略 |
| POST | `/api/backups/config` | 会话 | 保存备份策略 |
| GET | `/api/backups` | 会话 | 备份记录列表 |
| POST | `/api/backups/run` | 会话 | 立即备份 |
| GET | `/api/backups/{id}/content` | 会话 | 读取备份内容摘要（不下载文件） |
| DELETE | `/api/backups/{id}` | 会话 | 删除备份 |
| GET | `/api/schedules` | 会话 | 统一计划任务与下次执行时间 |
| GET | `/api/export.csv?kind=audit\|jobs\|sync\|diff` | 会话 | CSV 导出，带 UTF-8 BOM |

## 7. 安全中心

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/sessions` | 会话 | 活跃会话列表 |
| DELETE | `/api/sessions/{id}` | 会话 | 强制下线指定会话 |
| POST | `/api/sessions/revoke-others` | 会话 | 下线其它全部会话 |
| GET | `/api/ip-allowlist` | 会话 | 查询 IP/CIDR 白名单 |
| POST | `/api/ip-allowlist` | 会话 | 保存白名单；非法配置保守拒绝非回环来源 |
| POST | `/api/ip-allowlist/test` | 会话 | 测试来源 IP 是否允许 |
| GET | `/api/tokens` | 会话 | 只读令牌列表（仅前缀与哈希） |
| POST | `/api/tokens` | 会话 | 创建令牌；body `{"name": "监控", "scopes": ["certs"]}` |
| DELETE | `/api/tokens/{id}` | 会话 | 吊销令牌，立即生效 |
| GET | `/api/tokens/usage` | 会话 | 令牌最近使用时间 |
| GET | `/api/config-diffs` | 读 | 配置变更 Diff，敏感字段已打码 |

## 8. 证书同步

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/sync/catalog` | 会话 | 同步目录与事件目录 |
| GET | `/api/sync/rules` | 会话 | 同步规则列表 |
| POST | `/api/sync/rules` | 会话 | 保存规则 |
| DELETE | `/api/sync/rules/{id}` | 会话 | 删除规则 |
| GET | `/api/sync/events` | 会话 | 同步记录（已合并为批次） |
| DELETE | `/api/sync/events` | 会话 | 清空同步记录 |
| POST | `/api/sync/run` | 会话 | 执行本地同步 |
| POST | `/api/sync/preview` | 会话 | 预览匹配结果，不写文件 |
| GET | `/api/remote/hosts` | 会话 | 远程主机列表 |
| POST | `/api/remote/hosts` | 会话 | 保存远程主机 |
| DELETE | `/api/remote/hosts/{id}` | 会话 | 删除远程主机 |
| POST | `/api/remote/test` | 会话 | 测试 SSH 连接 |
| POST | `/api/remote/files` | 会话 | 列出远程目录 |
| POST | `/api/remote/push` | 会话 | 手动推送到远程主机 |

## 9. 账号与系统

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/session` | 会话 | 当前会话信息（用户名、CSRF、凭据来源等） |
| POST | `/api/logout` | 会话 | 登出 |
| POST | `/api/password` | 会话 | 修改密码（12 位以上，含大小写与数字），会下线其它会话 |
| POST | `/api/username` | 会话 | 修改用户名 |
| POST | `/api/cron/schedule` | 会话 | 设置每日检测时间 |
| POST | `/api/retention` | 会话 | 设置记录保留天数 |
| POST | `/api/https/settings` | 会话 | 切换「仅允许 HTTPS」 |
| POST | `/api/cleanup` | 会话 | 按保留天数立即清理 |
| GET | `/api/update/check` | 会话 | 检查新版本；`?force=1` 忽略缓存 |
| POST | `/api/update/settings` | 会话 | 自动检测设置 |
| GET | `/api/backup` | 会话 | 导出完整配置备份（含凭证密文） |
| POST | `/api/backup` | 会话 | 导入配置备份 |
| POST | `/api/locale` | 会话 | 切换界面语言 `zh` / `en` / `ja` |
| GET | `/api/audit` | 读 | 审计日志 |

## 10. 示例：使用只读 Token 做监控

```bash
# 1. 创建只读令牌（在页面操作，明文只显示一次）
# 2. 查询证书列表
curl -sS -H "X-API-Token: acmp_xxxx" \
  https://acme.example.com/api/certs | jq '.certs[] | {domain, days_left}'

# 3. 查询到期看板
curl -sS -H "X-API-Token: acmp_xxxx" \
  https://acme.example.com/api/expiry | jq '.counts'

# 4. 验证令牌越权被拒（应返回 401）
curl -sS -i -H "X-API-Token: acmp_xxxx" \
  https://acme.example.com/api/tokens
```

## 11. 注意事项

- 所有写操作都需要 CSRF Token；只读 Token 无法绕过。
- HTTP 直连在开启「仅允许 HTTPS」时会被静默断连，等同空端口；`/api/health` 例外。
- 反向代理之后使用 IP 白名单，需设置 `ACME_PANEL_TRUST_PROXY=1`，否则看到的是代理 IP。
- 修改环境变量后必须 `docker compose up -d`；`restart` 不会刷新容器环境。
- 接口路径与参数随版本演进，升级前请阅读 [CHANGELOG.md](../CHANGELOG.md)。
