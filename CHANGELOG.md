# 更新日志

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.1.14] - 2026-11-25

### 文档

- README 按「Docker 部署 / 二进制部署 / 使用说明」三大块重组，前两块再细分 Linux / macOS / Windows 使用方法
- 补充 macOS 二进制下载与运行、Docker Desktop 共享目录、macOS 自带 `sed` 差异等平台细节
- 常见问题新增 `go.sum` 缺失导致 CI 构建失败的排查说明

### 修复

- Dockerfile 构建上下文补上 `go.sum`（这是 CI 报 `missing go.sum entry` 的根因）
- ci.yml / CONTRIBUTING.md 去掉过时的「零第三方依赖 / Go 1.24 / 无需 go.sum」说法
- GitHub Release 增加 `darwin/amd64` 与 `darwin/arm64` 二进制构建

### 说明

- 功能逻辑未改动，仅文档、构建配置与发布矩阵调整

## [0.1.13] - 2026-11-25

### 改进

- 挂载目录文件列表、同步记录、任务列表与审计表格增加限高滚动区域，页面不再被长列表拉得很长
- 统一细滚动条样式与滚动不穿透，按钮 / 卡片 / 输入框 / 导航增加键盘焦点反馈
- CSS 统一间距与字号变量、合并重复的空状态规则、统一过渡时长；小屏适配增强
- `api()` 兼容空响应与非 JSON 响应，避免边界情况下前端报错

### 说明

- 前端的 id、class、事件与业务逻辑保持原样，功能与交互完全对齐

## [0.1.12] - 2026-11-25

### 新增

- 首次注册：系统尚无账号密码时登录页显示注册入口，设置后永久关闭；含用户名/密码强度校验、按 IP 限流与审计
- 远程主机支持 SSH 账号密码认证（与私钥二选一），密码加密落盘、接口只回掩码

### 安全加固

- 远程连接改为纯 Go SSH：凭证只在内存，不写命令行、不落临时文件；不再依赖 `ssh` / `scp` / `sshpass`
- 主机密钥首次连接写入 `known_hosts`（0600），后续变化直接拒绝，防中间人攻击
- 远程主机、用户名、目录与文件名白名单校验，杜绝 shell 与路径注入
- 镜像移除不再需要的 `openssh-client`

### 测试

- 新增真实 SSH server 单测验证密码登录与文件推送、主机密钥防篡改测试、首次注册专项测试

## [0.1.11] - 2026-11-25

### 新增

- 数据统一存入 SQLite（`panel.db`）：配置、加密凭证、任务记录、审计日志与同步记录
- 旧版 `state.json` / `jobs.json` / `audit.log` 启动时自动导入，旧文件改名 `*.imported` 留作备份
- 设置页新增「数据保留天数」（默认 30 天，0 表示不清理）与「立即清理」按钮

### 改进

- SQLite 采用 WAL + `synchronous=FULL` + 事务写入，杜绝 JSON 半写导致的数据丢失
- 引入纯 Go SQLite 驱动（无 CGO），二进制 11 MB → 18 MB，镜像约 45 MB
- 构建与 CI 升级到 Go 1.26

## [0.1.10] - 2026-11-25

### 新增

- 证书同步去重：记录每个目标文件上次写入时的证书内容指纹，证书未续签时不再重复覆盖；续签后或文件首次匹配时才自动同步一次
- 「立即同步」旁新增「强制同步」勾选：忽略指纹记录重写全部匹配文件，并推送到已启用的远程主机
- Dynu DNS 服务商：用控制面板的 OAuth2 Client ID / Secret 签发 Dynu 托管域名证书

### 改进

- 同步记录只保留真正写入或失败的结果，未变化不再刷屏；跳过数量在提示与记录里可见
- README 补充 Dynu 申请步骤与同步去重说明

## [0.1.9] - 2026-11-25

### 新增

- 远程主机证书同步：在本地同步成功后，通过 SSH/SCP 把刚覆盖的文件推送到其他主机
  - Web「证书同步 → 远程主机同步」可添加 / 编辑 / 删除 / 测试连接
  - SSH 私钥 AES-GCM 加密落盘，接口只回掩码，编辑留空沿用原值
  - argv 白名单调用、路径校验、超时控制，不经过 shell
  - 镜像内置 `openssh-client`

### 改进

- 优化同步记录显示：用结构化条目 + 彩色文件 chip 代替长串文件名，成功 / 失败 / 跳过一目了然
- 证书卡片按钮顺序改为「证书 / 私钥 / 续期 / 详情」，点「证书」直接定位到证书链内容
- 点击证书卡片空白处即可打开详情，按钮区域互不干扰
- 弹窗打开自动聚焦首个输入框；刷新按钮加 loading 态
- 优化卡片 hover、同步记录卡片化、远程主机行样式等视觉细节
- README 子章节编号修正，补充远程主机同步使用说明

## [0.1.8] - 2026-11-25

### 改进

- 证书同步页新增「清空记录」按钮，可清掉历史失败记录
- 权限修复是一次性的（改挂载目录属主后永久生效），不会每次同步都要求执行

## [0.1.7] - 2026-11-25

### 修复

- 权限修复命令改为 `docker exec -u root acmesh-panel chown -R 10001:10001 <容器内路径>`，不再让用户把容器内路径 `/certs` 误当宿主机路径执行
- compose 加 `CHOWN` capability，使上述修复命令可用；面板进程仍为非 root
- README FAQ 与同步失败日志同步更新修复指引

## [0.1.6] - 2026-11-25

### 文档

- 重写 Docker 部署章节：补上「先拿到项目文件」步骤，明确命令行与面板两种路径
- Dockge / Portainer 的 Compose 模板改为自包含（密码写在 YAML 里、不依赖 .env），补全所有变量与可选同步目录注释
- Windows / Linux 一键命令不再写死本地路径，改用 `<项目目录>` 占位
- 章节编号与内部链接整理，YAML 模板通过解析校验

## [0.1.5] - 2026-11-25

### 修复

- 回退 0.1.3 的 root 自动 chown 方案（在部分挂载环境导致容器启动失败），恢复非 root uid 10001 直接运行
- 挂载目录权限失败时，容器日志与证书同步记录都会打印可直接复制执行的修复命令（chown 正确写法 + docker run 一键方式）
- 模板复制失败不再直接退出容器，改为打印修复指引后继续启动

## [0.1.4] - 2026-11-25

### 改进

- 自动检测改为每天固定时间执行（默认 03:00），执行日期记录到 state.json，重启容器当天不会重复检测
- 设置页新增「每日自动检测时间」下拉（0-23 点）可修改并保存
- 手动「检查全部续期」与单证书续期不受影响

## [0.1.3] - 2026-11-25

### 修复

- 容器自动修复同步挂载目录权限：root 启动时 chown 目录，成功则降权到 uid 10001 运行，失败则保持 root 运行以保证能写入
- 上次 root 方案启动失败的真因（/opt/acme-template 权限）已在 0.1.0 修复，本版恢复自动权限修复

## [0.1.2] - 2026-11-25

### 修复

- 修复通知渠道点「保存」无反应的问题：保存处理器里 `body` 变量在自身初始化时就被引用（暂时性死区），导致 JS 静默报错
- ui-check.js 增加 JS 语法检查与此类自引用初始化检测，防止回归

## [0.1.1] - 2026-11-25

### 修复

- 镜像安装 tzdata：让 `TZ=Asia/Shanghai` 真正生效，通知/审计/同步记录不再显示 UTC 时间（之前比北京时间慢 8 小时）
- README 删除多余的「快速开始（Docker）」章节，章节编号顺延整理

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
- Cookie Secure 增加通俗解释

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

[0.1.14]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.14
[0.1.13]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.13
[0.1.12]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.12
[0.1.11]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.11
[0.1.10]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.10
[0.1.9]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.9
[0.1.8]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.8
[0.1.7]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.7
[0.1.6]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.6
[0.1.5]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.5
[0.1.4]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.4
[0.1.3]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.3
[0.1.2]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.2
[0.1.1]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.1
[0.1.0]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.0
[0.0.9]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.9
[0.0.8]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.8
[0.0.7]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.7
[0.0.6]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.6
[0.0.5]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.5
[0.0.4]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.4
[0.0.3]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.3
[0.0.2]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.0.2
