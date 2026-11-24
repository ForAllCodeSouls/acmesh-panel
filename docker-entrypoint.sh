#!/bin/sh
# 容器入口：以 root 启动，自动修复挂载目录属主后降权到 acme(10001) 运行。
# 若无法 chown（缺少 capability），保持 root 运行以保证面板能启动并写入挂载目录。
set -eu

: "${ACME_HOME:=/acme.sh}"
: "${ACME_PANEL_DATA:=/data}"

# 首次启动：从镜像内置模板初始化 acme.sh（模板已设为全局可读）
if [ ! -x "$ACME_HOME/acme.sh" ]; then
  echo "[entrypoint] $ACME_HOME 中没有 acme.sh，从镜像内置模板初始化"
  mkdir -p "$ACME_HOME"
  if [ -d /opt/acme-template ]; then
    cp -R /opt/acme-template/. "$ACME_HOME"/ || {
      echo "[entrypoint] 复制模板失败，请检查 /opt/acme-template 权限" >&2
      exit 1
    }
    chmod +x "$ACME_HOME/acme.sh" 2>/dev/null || true
  else
    echo "[entrypoint] 镜像内缺少 /opt/acme-template，无法初始化 acme.sh" >&2
    exit 1
  fi
fi

mkdir -p "$ACME_PANEL_DATA"

# root 启动：修复挂载目录属主，成功则降权，失败则保持 root（仍能写挂载目录）
if [ "$(id -u)" = "0" ] && command -v su-exec >/dev/null 2>&1; then
  fix_ok=1
  chown -R acme:acme "$ACME_HOME" "$ACME_PANEL_DATA" 2>/dev/null || fix_ok=0

  if [ -n "${ACME_PANEL_SYNC_DIR:-}" ]; then
    old_ifs=$IFS
    IFS=',;'
    for d in $ACME_PANEL_SYNC_DIR; do
      [ -n "$d" ] || continue
      if [ -d "$d" ]; then
        chown -R acme:acme "$d" 2>/dev/null || fix_ok=0
      fi
    done
    IFS=$old_ifs
  fi

  chmod 700 "$ACME_PANEL_DATA" 2>/dev/null || true

  if [ "$fix_ok" = "1" ]; then
    echo "[entrypoint] 挂载目录权限已修复，降权到 uid 10001 运行"
    exec su-exec acme:acme /usr/local/bin/acmesh-panel "$@"
  fi
  echo "[entrypoint] 无法修改目录属主，保持 root 运行以保证写入挂载目录" >&2
fi

# 非 root 启动，或修复失败：直接运行
exec /usr/local/bin/acmesh-panel "$@"
