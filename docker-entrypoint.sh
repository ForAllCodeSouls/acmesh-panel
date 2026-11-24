#!/bin/sh
# 容器入口：保证 acme.sh 存在（支持空目录 bind mount），再启动面板。
# 面板以非 root uid 10001 运行；挂载目录权限由 compose 的自动修复选项处理。
set -eu

: "${ACME_HOME:=/acme.sh}"
: "${ACME_PANEL_DATA:=/data}"

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
chmod 700 "$ACME_PANEL_DATA" 2>/dev/null || true

exec /usr/local/bin/acmesh-panel "$@"
