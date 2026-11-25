# 安全政策

## 支持版本

只有最新的 `0.1.x` 版本会收到安全修复。建议始终使用最新的 Release 或镜像标签。

## 报告漏洞

**请不要公开提交 Issue 披露漏洞。**

私有报告入口：<https://github.com/ForAllCodeSouls/acmesh-panel/security/advisories/new>

使用 GitHub 仓库页面的 `Security → Report a vulnerability` 提交私有报告，包含：

- 受影响版本 / 提交
- 复现步骤或 PoC
- 影响范围（是否能绕过登录、读取私钥、执行任意命令等）
- 建议的修复方式（可选）

维护者会在 72 小时内确认，并在修复发布后与你协调公开时间。

## 本项目的安全边界（已知且刻意保留）

| 项 | 说明 |
|---|---|
| 单账号模型 | 不提供 RBAC / 多租户。拿到账号即拥有全部证书管理权限，包括查看私钥 |
| 私钥可见 | 按设计允许明文查看/复制/下载，但有二次确认、审计与 60 秒自动清除。若不需要，可删除 `handleCertKey` 的响应逻辑 |
| acme.sh 账户文件 | acme.sh 会把 DNS API 凭证写入 `/acme.sh/account.conf`（明文，续期需要），请像保护私钥一样保护该卷 |
| HTTPS / HSTS | 面板只提供 HTTP，HTTPS 由 Caddy/Nginx 终结。Cookie 智能加固：HTTP 下为普通 `HttpOnly` Cookie；反代透传 `X-Forwarded-Proto: https` 或直连 TLS 时自动带 `Secure` + `SameSite=Lax`。HSTS 仅在确认 HTTPS 时下发，纯 HTTP 不下发，无开关 |
| 反代可信度 | `ACME_PANEL_TRUST_PROXY` 仅影响登录限流按哪个 IP 统计，不影响登录本身。仅在反代可控时开启，否则攻击者可伪造 `X-Forwarded-For` 绕过登录限流。`X-Forwarded-Proto` 即使被客户端伪造，也只会让自己拿不到 Cookie，不会越权 |
| Origin / Host | 智能同源校验：按主机名比较 Origin/Referer，忽略端口与协议，兼容 `X-Forwarded-Host`；公网主机名明确时拒绝跨站，反代隐去公网名时不误拦登录。状态变更接口始终由 CSRF Token 保护 |
| Webhook 通知 | 渠道 URL 与 Token 整体加密落盘、接口只回掩码；只接受 http(s) 协议。内网 Gotify 常用明文 http，请自行确保网络可信。通知正文不含私钥、证书与 DNS 凭证 |
| 端口映射 | 容器监听 `0.0.0.0:8080`，compose 映射为宿主 `0.0.0.0:8800`，外网可访问 |

## 禁止提交的内容

真实私钥、证书、DNS API Token、ACME 账户密钥、密码、`.env`、`*.key`、`*.pem`、
`state.json`、`secret.key`、`audit.log`。测试代码里的密码必须是明显的一次性测试值。
