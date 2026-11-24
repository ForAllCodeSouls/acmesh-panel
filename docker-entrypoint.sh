#!/bin/sh
# 容器入口：以 root 启动，自动修复挂载目录属主，再降权到 acme 运行面板。
# 这样无需在宿主机手动执行 chown -R 10001:10001。
set -eu

: "${ACME_HOME:=/acme.sh}"
: "${ACME_PANEL_DATA:=/data}"

if [ ! -x "$ACME_HOME/acme.sh" ]; then
  echo "[entrypoint] $ACME_HOME 中没有 acme.sh，从镜像内置模板初始化"
  mkdir -p "$ACME_HOME"
  cp -a /opt/acme-template/. "$ACME_HOME"/
  chmod +x "$ACME_HOME/acme.sh" 2>/dev/null || true
fi

mkdir -p "$ACME_PANEL_DATA"
chmod 700 "$ACME_PANEL_DATA" 2>/dev/null || true

# 以 root 启动时，自动把数据目录与证书同步目录的属主改成 acme(10001)，然后降权执行。
if [ "$(id -u)" = "0" ] && command -v su-exec >/dev/null 2>&1; then
  chown -R acme:acme "$ACME_HOME" "$ACME_PANEL_DATA" 2>/dev/null || true
  chmod 700 "$ACME_PANEL_DATA" 2>/dev/null || true

  if [ -n "${ACME_PANEL_SYNC_DIR:-}" ]; then
    printf '%s' "$ACME_PANEL_SYNC_DIR" | tr ',;' '\n\n' | while IFS= read -r d; do
      [ -n "$d" ] || continue
      if [ -d "$d" ]; then
        chown -R acme:acme "$d" 2>/dev/null || \
          echo "[entrypoint] 无法修改 $d 的属主，请检查宿主机挂载权限" >&2
      fi
    done
  fi

  echo "[entrypoint] 挂载目录权限已自动修复，切换到 uid 10001 运行"
  exec su-exec acme:acme /usr/local/bin/acmesh-panel "$@"
fi

# 非 root 启动（用户用 user: 指定了其它 uid）时，跳过 chown 直接运行。
exec /usr/local/bin/acmesh-panel "$@"
