# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# acmesh-panel — 轻量 acme.sh 证书管理面板（单 Go 二进制 + 内嵌前端）
#   * 多阶段构建，最终镜像仅含 alpine + curl/openssl + acme.sh（SSH 走纯 Go 实现）
#   * 全程非 root（uid 10001），挂载目录权限由宿主机预先修复
# ---------------------------------------------------------------------------

# ---------- 构建阶段 ----------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=0.1.20
WORKDIR /src

# 纯 Go 依赖（modernc.org/sqlite、golang.org/x/crypto），需 go.mod + go.sum
COPY go.mod go.sum ./
COPY *.go ./
COPY web ./web

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.appVersion=${VERSION}" \
      -o /out/acmesh-panel .

# ---------- 运行阶段 ----------
FROM alpine:3.21

ARG ACME_SH_VERSION=3.1.1
ARG VERSION=0.1.20

LABEL org.opencontainers.image.title="acmesh-panel" \
      org.opencontainers.image.description="Lightweight acme.sh web panel with password auth" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

# curl/openssl 是 acme.sh 的 DNS API 实现所必需；bash 兼容个别 dnsapi 脚本写法
RUN set -eux; \
    apk add --no-cache ca-certificates curl openssl bash tzdata; \
    mkdir -p /tmp/acme; \
    url="https://github.com/acmesh-official/acme.sh/archive/refs/tags/v${ACME_SH_VERSION}.tar.gz"; \
    if ! curl -fsSL "$url" -o /tmp/acme.tgz; then \
      echo "==> tag v${ACME_SH_VERSION} 不可用，回退到 master 分支"; \
      curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz -o /tmp/acme.tgz; \
    fi; \
    tar -xzf /tmp/acme.tgz -C /tmp/acme --strip-components=1; \
    ( cd /tmp/acme && ./acme.sh --home /opt/acme-template --install --nocron -m "admin@localhost" ); \
    rm -rf /tmp/acme /tmp/acme.tgz; \
    chmod +x /opt/acme-template/acme.sh; \
    mkdir -p /data /acme.sh; \
    addgroup -g 10001 -S acme; \
    adduser -u 10001 -S -G acme -h /data -s /sbin/nologin acme; \
    chown -R acme:acme /data /acme.sh /opt/acme-template; \
    chmod -R a+rX /opt/acme-template; \
    chmod 700 /data

COPY --from=build /out/acmesh-panel /usr/local/bin/acmesh-panel
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV ACME_HOME=/acme.sh \
    ACME_PANEL_DATA=/data \
    ACME_PANEL_LISTEN=0.0.0.0:8080 \
    ACME_PANEL_USER=admin \
    ACME_PANEL_CA=letsencrypt \
    ACME_PANEL_CRON=1 \
    ACME_PANEL_SYNC_DIR=""

# 证书与面板数据分两个卷：/acme.sh 可被其它容器共享，/data 含密钥与审计
VOLUME ["/acme.sh", "/data"]
EXPOSE 8080

# 非 root uid 10001 运行；挂载目录权限需宿主机预先修复（见启动日志提示 / README）
USER acme
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:8080/api/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
