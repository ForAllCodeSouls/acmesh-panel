#!/bin/sh
# 容器入口：保证 acme.sh 存在（支持空目录 bind mount），再启动面板。
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

exec /usr/local/bin/acmesh-panel "$@"
