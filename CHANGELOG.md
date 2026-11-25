# 更新日志

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.1.36] - 2026-11-25

### 修复

- **CI gofmt 检查失败**：`backup_test.go`（struct 字段对齐）与 `update_test.go`（单行 struct 字面量展开为多行、map 键对齐）已按 `gofmt` 标准格式化；`make check` 与 GitHub Actions 的格式门槛现可通过

## [0.1.35] - 2026-11-25

### 文档

- 按用户要求移除 README（中/英/日）中 0.1.32 新增的「同类开源项目」致谢条目，致谢部分仅保留 acme.sh 与 modernc.org/sqlite

## [0.1.34] - 2026-11-25

### 清理

- **死代码清理**（全项目静态扫描 + 人工逐项核实）：
  - 删除 Go 死函数 `Store.Save()`（零引用，内部 `saveLocked` 仍被所有写路径使用）与 `sortedKeys()`（零引用），连带移除仅为其保活的 `sort` import 与 `var _ = fmt.Sprintf` hack
  - 删除 CSS 死类 `settings-grid` / `field-row` / `filter-tabs` / `filter-tab`（页内分区已改用 `view-tab`，同步记录改用 `sync-filters` 栏）及其媒体查询、focus-visible 列表引用；**保留** `result-ok/fail/skip`——虽被静态扫描误报为未引用，实为 `renderSyncEvents` 动态拼接类
  - 删除 `assets/.gitkeep`（目录已有正式文件）
  - `web_ui_check.js` 过时的「筛选标签字号声明」断言改写为「无畸形 font 简写与已删类残留」，检查总数不变
- 明确保留项：`username_source` / `password_source`（兼容别名）、`docker-compose.build.yml`（README 与 compose 注释引用）、`Makefile` 全部目标（均有文档）、`optimization_test.go` 等全部测试文件

## [0.1.33] - 2026-11-25

### 修复

- **远程推送改为原子替换**：此前直接对远端最终路径覆盖写，极端情况下（上传中途断开 / 并发读）远端会短暂出现截断的证书或私钥文件；现与本地同步的 `writeAtomic` 标准对齐——先写 `<文件名>.acmesh-tmp` 再改名，优先 `posix-rename@openssh.com` 扩展（可覆盖已存在文件），不支持该扩展的服务器退化为先删后改名，任何失败路径都不留下半写文件
- 远程文件浏览列表隐藏 `.acmesh-tmp` 临时文件
- `ssh_push_test.go` 新增断言：推送完成后远端不残留临时文件

## [0.1.32] - 2026-11-25

### 文档

- 致谢新增「同类开源项目」条目（README / README.en / README.ja 三份同步）：收录 [acmesh-ui](https://github.com/brightcolor/acmesh-ui)——同为 Go 单二进制管理 acme.sh 的 Web UI，定位与取舍不同，供按部署习惯对比选用；本条目仅为社区惯例列举，不代表本项目的实现来源

## [0.1.31] - 2026-11-25

### 修复

- 全面复查 v0.1.30：隐私替换逐文件复验无残留、文档关键数字（18 家 DNS 服务商 / PBKDF2 600k 迭代 / Go 1.26 / 端口映射 / env 变量名）逐项与代码核对一致
- 收紧 `tests/web_ui_check.js` 的「改账号走新接口并重新登录」断言：原写法 `A && B || C` 因优先级导致后半检查恒真，改为 `A && (B || C)` 并锁定真实的 `showLogin(\`账号已改为` 调用；其余 58 项断言同步复查无同类问题

## [0.1.30] - 2026-11-25

### 安全

- **隐私信息清理**：测试夹具中残留的真实服务器信息已全部替换为 RFC 5737 / RFC 2606 文档专用占位——
  `tests/web_ui_check.js` 里的真实主机名与公网 IP（原文已脱敏，不再记录于本日志）改为 `remote1.example.net` / `203.0.113.10`，
  `sync_path_test.go` 与 `tests/sync_path_check.py` 里的真实证书域名（同样已脱敏）改为 `demo1.example.net`；全仓库已无真实信息残留

### 变更

- `.env.example` 的示例密码由 `change-me-to-a-long-random-password` 占位串改为随机生成的 16 位强密码（含大小写与数字），并加注释提醒公开部署前自行重新生成；README 两处示例密码同步替换

### 新增

- **多语言文档**：README 顶部新增语言导航，新增精简版英文指南 `README.en.md` 与日文指南 `README.ja.md`（功能一览 / 快速开始 / 配置参考 / 安全模型 / FAQ 摘要），完整细节仍以中文版为准
- `install.sh` 默认安装版本随本次发布更新为 0.1.30

## [0.1.29] - 2026-11-25

### 变更

- **env 不再每次启动强制覆盖账号密码**：`ACME_PANEL_USER` / `ACME_PANEL_PASSWORD` 只在首次启动（数据库里还没有密码时）用于初始化，之后重启不再覆盖
- Web「修改账号 / 修改密码」的结果现在持久生效，重启不会回退到 env 配置值
- 运行信息新增 `cred_source` 凭据来源（env / generated / web），界面按来源显示「仅首次初始化」或「Web 修改（持久生效）」；`username_source` / `password_source` 作为兼容别名保留

### 新增

- `ACME_PANEL_RESET_CREDENTIALS=1`：默认关闭的应急开关，配合 env 账号密码在启动时**显式重置一次**凭据，用于 env 不再自动覆盖后忘记密码的场景；未配置 `ACME_PANEL_PASSWORD` 时忽略并打印警告

### 改进

- 从 v0.1.28 及更早版本升级时，旧 `state` 没有凭据来源标记，启动时按当前 env 推断一次并落盘
- 登录页、账号安全表单、备份说明、README、`.env.example` 全量同步新规则；备份导入提示不再声称「凭据由环境变量管理」

## [0.1.28] - 2026-11-25

### 变更

- 「远程推送」全量改名为「远程同步」；远程同步与本地同步共用同一套同步规则，界面明确说明不再另建第二套规则
- 「远程证书目录」面板不再允许填写自定义目录，直接读取主机配置里的远程目录；文件类型只在被同步规则命中时才标注（由面板拿现有证书匹配规则得出，不再按文件名猜）
- 「远程同步记录」与「本地同步记录」合并为单一「同步记录」列表，每条用「本地同步 / 远程同步」标注范围

### 新增

- 同步记录筛选与分页：关键词（规则 / 来源 / 目标 / 文件名 / 详情）、结果、范围、起止日期、每页 50 条、总数与页码
- 「设置 → 备份恢复」：导出 / 导入单个 JSON 配置备份（DNS 凭证、通知渠道、远程主机、同步规则与记录、去重摘要、系统设置）；导入前预览内容并二次确认，导出与恢复均记入审计
- 备份不含登录账号与密码哈希（凭据独立保存，不随备份覆盖）、`secret.key` 主密钥、审计日志、任务记录与证书文件本身

### 改进

- 删除部署文档中「不管用哪种系统，都需要两个文件」这类无信息量的说明

## [0.1.27] - 2026-11-25

### 变更

- 移除 Web 首次注册页面与 `/api/setup`、`/api/setup/status` 接口；账号密码只由环境变量配置（`ACME_PANEL_USER` 默认 admin、`ACME_PANEL_PASSWORD`）
- 每次启动强制用 env 值覆盖账号密码：Web 上「修改账号 / 修改密码」仅本次运行有效，重启后恢复为 env 配置（用于 env 统一托管凭据）
- 未配置 `ACME_PANEL_PASSWORD` 且库中无密码时，启动自动生成随机密码并打印在日志（仅本次显示），不再开放 Web 注册

### 改进

- 「账号安全」分区新增「修改账号」表单（需验证当前密码）；成功后注销全部会话并要求用新账号重新登录
- 运行信息区分账号来源 / 密码来源，登录页与设置页文案同步说明 env 托管规则

## [0.1.26] - 2026-11-25

### 改进

- 审计日志新增筛选与搜索：支持关键词（用户 / 来源 / 动作 / 详情）、动作、用户、日期范围多条件组合筛选，条件走参数化查询防注入
- 审计日志改为服务端分页（每页 50 条），显示总数与当前页、支持翻页；动作 / 用户下拉自动从已有记录提取，一键重置全部条件
- 不带参数时保持旧行为（返回最近 200 条），兼容原有调用

## [0.1.25] - 2026-11-25

### 改进

- 新增面板版本自动检测：后台按可配置频次（关闭 / 仅启动 / 每 6 小时 / 每天 / 每周，默认每天）自动查询 GitHub 最新 Release，检测失败不影响面板使用
- 检测结果持久化到 SQLite：打开设置页不再每次请求 GitHub，展示最近检测时间与结果；「立即检测」可强制刷新
- 发现新版本时在顶部横幅与设置页显示醒目标记，并通过通知渠道推送一次 `update_available` 事件（同一版本只提醒一次），点击直达 Release 页面；升级仍需手动执行，不自动替换运行中的程序

## [0.1.24] - 2026-11-25

### 修复

- 远程同步不再把整个本地证书目录推给主机：改为与本地同步完全相同的规则匹配，只推送规则命中的文件
- 每条同步规则新增「远程主机」栏，规则未选主机时不做任何远程推送（含本地同步后的自动推送），避免证书被推到不相干的主机

### 改进

- 远程推送分区新增「远程目录」面板：可选择主机、指定目录并列出远程证书文件（名称 / 大小 / 类型 / 修改时间）
- 同步规则列表显示该规则选中的远程主机；规则编辑框可多选目标主机
- 远程同步结果提示会说明未命中规则 / 未选择主机的原因

## [0.1.23] - 2026-11-25

### 改进

- 「远程主机同步」新增「强制同步」勾选，默认普通同步：只推送内容变化过的证书文件，未变化文件按主机分别跳过；勾选后忽略摘要全部重推
- 远程推送结果提示区分成功 / 失败 / 跳过数量；同步记录说明与空状态文案同步更新；存储信息展示远程摘要数

### 修复

- 远程推送摘要按「主机 + 目录 + 文件名」独立记录，避免一台主机的推送状态影响另一台
- 强制同步成功后也会刷新摘要，避免下次普通同步重复推送

## [0.1.22] - 2026-11-25

### 修复

- 证书与私钥同屏视图不再被二次确认弹窗遮住；任务日志用 ✕ / 遮罩 / Esc 关闭时正确断开 SSE，任务结束不再对已移除按钮抛异常
- 修复总览接口两次取任务快照导致的潜在越界 panic；`--remove --purge` 仅在移除任务成功后才删除证书目录
- 失败 / 取消的吊销、移除、部署任务不再误报成功通知；Webhook 拒绝私网 / 环回 / 云元数据地址（SSRF），Gotify 带 query 时 token 拼接正确
- 改密与首次注册统一 12 位复杂度策略并增加失败锁定；同步目录统一转绝对路径；`ca` 前缀不再把 `caddy_*.pem` 误判为证书链；SQLite 时间比较改用纳秒精度
- 修复 SQLite 文件路径在 Windows 上被解析为 `file://C:/...` 导致无法打开的问题；代理取 IP 改为从右侧可信跳取值，避免伪造 XFF 绕过限流

### 改进

- 侧栏按「证书管理 / 系统」分组；证书同步页拆为本地同步 / 远程推送 / 同步记录，设置页拆为账号安全 / 系统运行 / 审计 / 支持，减少长页滚动
- 「签发证书」只在证书页显示；右上角刷新按当前页加载真实数据；切换页面自动回到顶部
- 弹窗支持焦点陷阱与焦点归还，Esc 只关闭最上层；私钥定时清除不再误清新打开的视图
- 统一自动续期、自动推送、密码强度等文案；重写 CSS 为单一设计令牌，消除重复覆盖与移动端限高失效

## [0.1.21] - 2026-11-25

### 修复

- 修复强制远程推送时报 `读取本地文件失败: open /certs/certs/xxx_cert.pem` 的问题：调用方预先拼接绝对路径后，推送层又拼接一次目录，导致路径重复；现在统一在一处解析，相对文件名与绝对路径都不会重复前缀
- 本地证书路径增加越界校验与明确提示：文件不存在时指出应检查容器内 `ACME_PANEL_SYNC_DIR` 挂载路径，避免把宿主机路径当成容器内路径
- 同步记录按 `scope` 严格分流：`/api/sync/rules`、`/api/sync/events`、`/api/sync/run`、`/api/remote/push` 返回的 `remote_events` 只含推送到远程主机的结果；空推送不再产生无意义记录

### 改进

- 远程 / 本地同步记录新增「全部 / 成功 / 失败」筛选；失败原因以独立醒目的错误块展示，路由与来源分行呈现
- 页面视觉重构：统一深色控制台配色与卡片层级、强化选中态与状态色、优化窄屏布局与键盘焦点反馈

## [0.1.20] - 2026-11-25

### 修复

- 恢复弹窗 / 抽屉点击遮罩关闭；普通请求加 30 秒超时，避免「读取中…」卡住无法退出

### 新增

- 设置页显示密码来源（环境变量 / Web 注册）及其隐私说明
- 设置页显示 SQLite 数据库路径、大小与任务 / 审计 / 同步记录数量
- README 补充持久化说明（命名卷 vs 绑定挂载）与主机被入侵时的安全边界

## [0.1.19] - 2026-11-25

### 修复

- 远程推送改用标准 SFTP 子系统，修复 `scp -t` 在部分 SSH 服务上「退出码 1 且无错误信息」的问题；目录自动创建与权限设置也走 SFTP
- 远程目录不存在时自动创建，写入权限分别设置为证书 0644 / 私钥 0600

### 改进

- 远程同步与本地指纹去重彻底分开：新增「强制同步到远程」按钮，默认不自动推送；每台主机可单独开启「本地同步后自动推送」
- 同步记录拆分为「本地同步记录」与「远程同步记录」两个区域，不再混在一起

## [0.1.18] - 2026-11-25

### 新增

- 证书卡片「证书/私钥」合并按钮：二次确认后同屏左右显示证书与私钥，分别复制 / 下载，私钥 60 秒自动清除
- 设置页自动检测 GitHub 新版本：有更新时版本号后显示「可更新 vX」按钮，点击跳转项目主页
- 新增 9 家 DNS 服务商：Hurricane Electric / FreeDNS / Gandi / DigitalOcean / Linode / Vultr / Bunny.net / Porkbun / deSEC

### 修复

- 弹窗与抽屉不再因点击外部区域而关闭，只能通过关闭 / 取消按钮或 Esc 退出
- 设置页「证书目录」改为准确的「acme.sh 目录」并注明容器内路径；凭证页 `state.json` 文案改为 `panel.db`

## [0.1.17] - 2026-11-25

### 修复

- 修复滚动区域只设置 `max-height`、漏写 `overflow-y: auto` 的问题：之前内容会溢出并遮挡下方区块，滚动条也不会出现
- 远程主机页面说明改为支持私钥 / 密码与纯 Go SSH，删除已过时的 `openssh-client` 提示

### 新增

- 远程目录不存在时自动创建（仍要求绝对路径且不含 `..`）

## [0.1.16] - 2026-11-25

### 修复

- 证书卡片的「证书」按钮现在直接显示叶证书（`cert.pem`）并定位到证书链区域，之前错误地显示成「完整链」

## [0.1.15] - 2026-11-25

### 修复

- 远程主机密码认证同时支持 `keyboard-interactive`（群晖 / Windows OpenSSH / 启用 PAM 的 OpenSSH），并给出明确的认证失败提示
- 远程主机与同步规则的「启用」复选项改为紧凑左对齐，修复勾选框与文字分离、文字被挤压换行的问题
- 新增远程主机时未填密码或私钥会直接提示，不再提交空凭证

### 说明

- 滚动区域（0.1.13+）与认证方式选择（0.1.12+）需更新到对应版本后才会显示；若界面仍是旧样式，请重新拉取镜像并强制刷新浏览器

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

[0.1.20]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.20
[0.1.19]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.19
[0.1.18]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.18
[0.1.17]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.17
[0.1.16]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.16
[0.1.15]: https://github.com/ForAllCodeSouls/acmesh-panel/releases/tag/v0.1.15
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
