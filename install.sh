#!/bin/sh
# 从 GitHub Releases 安装 acmesh-panel 二进制（Linux amd64/arm64）
# 用法：curl -fsSL https://raw.githubusercontent.com/ForAllCodeSouls/acmesh-panel/main/install.sh | sh
#       VERSION=0.1.0 BINDIR=~/.local/bin sh install.sh
set -eu

VERSION="${VERSION:-0.1.0}"
REPO="ForAllCodeSouls/acmesh-panel"
BINDIR="${BINDIR:-/usr/local/bin}"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

URL="https://github.com/${REPO}/releases/download/v${VERSION}/acmesh-panel-linux-${ARCH}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "下载: $URL"
curl -fsSL "$URL" -o "$TMP"
chmod 755 "$TMP"
mkdir -p "$BINDIR"
mv "$TMP" "${BINDIR}/acmesh-panel"

echo "安装完成：${BINDIR}/acmesh-panel（运行前请设置 ACME_PANEL_PASSWORD、ACME_HOME 等环境变量）"
