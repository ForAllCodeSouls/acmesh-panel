#!/bin/sh
# 从 GitHub Releases 安装 acmesh-panel 二进制（Linux amd64/arm64）
# 用法：curl -fsSL https://raw.githubusercontent.com/ForAllCodeSouls/acmesh-panel/main/install.sh | sh
#       VERSION=0.1.72 BINDIR=~/.local/bin sh install.sh
set -eu

VERSION="${VERSION:-0.1.72}"
REPO="ForAllCodeSouls/acmesh-panel"
BINDIR="${BINDIR:-/usr/local/bin}"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

URL="https://github.com/${REPO}/releases/download/v${VERSION}/acmesh-panel-linux-${ARCH}"
TMP="$(mktemp)"
SUMS="$(mktemp)"
trap 'rm -f "$TMP" "$SUMS"' EXIT

echo "下载: $URL"
curl -fsSL "$URL" -o "$TMP"
# 一键安装也必须校验完整性：Release 同时发布 SHA256SUMS，不验真的二进制绝不能装。
curl -fsSL "${URL%/*}/SHA256SUMS" -o "$SUMS"
EXPECTED="$(awk -v f="acmesh-panel-linux-${ARCH}" '$2 == f { print $1; exit }' "$SUMS")"
[ -n "$EXPECTED" ] || { echo "SHA256SUMS 里找不到 acmesh-panel-linux-${ARCH}" >&2; exit 1; }
ACTUAL="$(sha256sum "$TMP" | awk '{ print $1 }')"
[ "$ACTUAL" = "$EXPECTED" ] || { echo "SHA256 校验失败：已弃用下载文件，未安装" >&2; exit 1; }
echo "SHA256 校验通过"
chmod 755 "$TMP"
mkdir -p "$BINDIR"
mv "$TMP" "${BINDIR}/acmesh-panel"

echo "安装完成：${BINDIR}/acmesh-panel（运行前请设置 ACME_PANEL_PASSWORD、ACME_HOME 等环境变量）"
