# 更新日志

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.0.2] - 2026-11-25

### 新增

- 证书同步：配置挂载目录（`ACME_PANEL_SYNC_DIR`），签发/续期成功后自动把新证书与私钥覆盖到目录里匹配的文件
- 五种匹配模式：精确域名 / 子域名（含通配 SAN）/ 仅通配符 / 文件名模式 / 现有证书 CN-SAN，支持预设一键创建与自定义规则
- 同步事件可订阅推送（`cert_synced` / `sync_failed`），Web 面板新增「证书同步」页管理规则与查看同步记录
- GitHub Actions 仅当 version.go 版本号变化或手动触发时运行；Release 由 Action 自动创建
- 原创项目图标（assets/logo.png），赞赏码统一放在 assets/ 目录

### 初始版本

- 账号密码登录：PBKDF2-HMAC-SHA256（600k）、会话 Cookie（HttpOnly + SameSite=Strict）、CSRF、登录限流
- 证书总览：扫描 acme.sh home 并解析 x509（SAN、签发者、有效期、密钥类型、剩余天数）
- DNS API 签发：阿里云 / Cloudflare / DNSPod / 腾讯云 / GoDaddy / 华为云 / AWS / Namecheap，支持泛域名
- ECC 256/384、RSA 2048/4096；多 CA（Let's Encrypt / ZeroSSL / Buypass / Google / Staging）
- 按域名自定义 ACME 邮箱，留空回落全局默认
- 私钥查看：二次确认 + 审计 + 前端 60 秒自动清除
- Webhook 通知：Gotify / 通用 Webhook / Server 酱³ / 钉钉 / 飞书 / Bark，11 种事件
- 续期 / 吊销 / 移除；内置调度每 12 小时 `acme.sh --cron`
- 部署输出到 `/data/output/<证书>/`
- 审计日志（JSONL，5 MB 轮转）与 Web 查询
- Docker 镜像（GHCR）、Linux/Windows 预编译二进制、一键安装脚本
- 92 项端到端测试

[0.0.2]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.2
