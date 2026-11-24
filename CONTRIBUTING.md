# 贡献指南

欢迎提交 Issue 和 PR。这个项目刻意保持小：一个 Go 二进制 + 一个内嵌前端 + 一份 Dockerfile。

## 开发环境

```bash
make build       # 本地二进制 bin/acmesh-panel
make run         # 用 tests/fake-acme.sh 在 0.0.0.0:8800 起开发实例
make test        # go vet + Go 单测 + 175+ 项端到端断言 + 首次注册专项
make ui-test     # 前端选择器 / DOM id 一致性检查
```

- 需要 Go 1.26+、Python 3.12+、Node 20+（Node 只用于前端静态检查）
- Go 依赖为 `modernc.org/sqlite` 与 `golang.org/x/crypto`（纯 Go、无 CGO）；改依赖后必须执行 `go mod tidy` 并提交 `go.sum`，否则 CI 会报 `missing go.sum entry`
- 前端不用构建工具，直接改 `web/index.html` / `web/style.css` / `web/app.js`
- 严格 CSP：禁止内联 `<script>`、`onclick=`、`style="..."`；样式写进 `style.css`

## 提交前检查

```bash
gofmt -w *.go
go vet ./...
make test && make ui-test
```

CI 会自动跑上面这些 + Docker 镜像构建/冒烟测试。

## 规则

1. **绝不提交真实凭证**：私钥、证书、API Token、密码、`.env`、`state.json`、`secret.key`
2. 新增 acme.sh 子命令必须走白名单 + argv 调用，不允许 `sh -c`、字符串拼接或任意路径
3. 新增 DNS 服务商要同时给出 `EnvField` 定义；凭证只能按字段白名单传入环境变量
4. 任何能读取私钥的接口都必须：登录 + CSRF + 显式确认 + 审计
5. 用户可见的字符串请用中文；代码注释用中文或英文均可
6. Commit message 用英文祈使句，例如 `fix: validate provider env fields`，`feat: add dns_xxx provider`

## PR 描述建议

- 解决了什么问题
- 怎么验证的（命令 + 结果）
- 是否引入新的攻击面 / 是否需要更新 SECURITY.md 或 README

## 范围之外

不计划做：多用户 RBAC、外部数据库、Web 终端、任意命令执行、自带 ACME 客户端实现、
自动生成 crontab、把面板直接暴露到公网。这些都会破坏当前的轻量与安全模型。
