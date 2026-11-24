# 更新日志

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.1.0] - 2026-11-25

### 修复

- 修复容器首次启动失败：`cp: can't stat '/opt/acme-template/.': Permission denied`。acme.sh 模板目录改为全局可读，复制改用 `cp -R` 并加清晰报错
- 回退 root 启动方案：面板继续以非 root uid 10001 运行（root+su-exec 方案导致部分环境启动失败）
- FAQ 增加该启动失败的原因与处理方式

## [0.0.9] - 2026-11-25

### 修复

- 通知、审计、同步记录里的时间改为跟随容器 `TZ` 时区，不再强制显示 UTC（之前比北京时间差 8 小时）
- 修复 `fullchain.*` 因名称含 `chain` 被误判为证书链的问题，现在正确识别为证书
- 证书同步的文件列表与预览结果按类型用颜色区分：私钥红色、证书绿色、证书链蓝色

## [0.0.8] - 2026-11-25

### 改进

- 容器启动时自动修复挂载目录属主（chown）再降权到 uid 10001 运行，无需再在宿主机手动执行 chown
- `.env.example` 与 `docker-compose.yml` 补全所有可配置项，可选项用注释说明
- README 常见问题扩充：权限、私钥未匹配、续期未到期、通知事件、任务记录、页面刷新等
- README / 文档中不再出现真实域名，全部用 example.com 示例

## [0.0.7] - 2026-11-25

### 改进

- 网页图标统一使用原创 logo.png（浏览器标签 favicon 与登录页/侧栏品牌位）
- 文档与代码里的示例域名全部改为通用的 example.com，不含任何真实域名
- 刷新页面后停留在上次所在的页面，不再总是回到证书首页
- 证书同步改为按匹配到的文件类型分别写入：文件名含 key 写新私钥、含 cert/fullchain 写新证书、含 chain/ca 写新证书链；预览会标明每个文件将写入的内容类型
- 目录文件列表显示每个文件的类型（私钥 / 证书 / 证书链）

## [0.0.6] - 2026-11-25

### 修复与改进

- 同步目录无权限时给出明确解决指引（容器 uid 10001，需 chown/chmod）；Web 显示每个目录的读写状态
- 通知页每次打开都重新拉取事件目录，解决新增的「证书同步成功/失败」事件保存不了的问题
- 任务记录落盘到 `/data/jobs.json`，重启或更新镜像后历史任务与日志不再丢失；中断的任务标记为失败
- 登录新增「保持登录状态」选项：勾选后 Cookie 与会话有效期延长到 90 天（空闲 30 天）
- Web 设置里的赞赏码可点击放大
- 删除维护者替换图片的提示文字；Cookie Secure 增加通俗解释

## [0.0.5] - 2026-11-25

### 改进

- 证书同步页显示挂载目录里现有的证书文件（文件名、域名、大小、是否可解析为证书、CN）
- 匹配规则说明改成人话：每个匹配方式带具体示例，弹窗里选择时实时显示解释
- 新建/编辑规则时点「预览匹配」即可查看会覆盖哪些文件，预览只计算不写入
- 预设规则名称与描述更易理解

## [0.0.4] - 2026-11-25

### 改进

- GitHub Actions 改为每次推送 main/master 即运行（CI / Docker / Release），不再要求 version.go 变化；Release 同名 tag 会自动更新资源
- `ACME_PANEL_SYNC_DIR` 支持多个目录：英文逗号 / 分号分隔，规则会依次在每个目录中匹配并覆盖
- 同步目录写入 Dockerfile `ENV`、docker-compose.yml、.env.example 示例，配置更直观

## [0.0.3] - 2026-11-25

### 改进

- 续期遇到「证书未到续期时间」（acme.sh 返回 exit 2 + Skipping）不再标记为失败：任务状态改为 `skipped`
- 手动续期时显示优雅提示：证书到期时间、距过期、下次可续签时间、距可续签；自动调度保持完全静默
- `skipped` 任务不推送任何通知；通知仍只在续期成功、签发成功、临期、真实失败时发送
- 任务页新增「未到期」状态与提示样式

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

[0.1.0]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.0
[0.0.9]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.9
[0.0.8]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.8
[0.0.7]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.7
[0.0.6]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.6
[0.0.5]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.5
[0.0.4]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.4
[0.0.3]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.3
[0.0.2]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.2
