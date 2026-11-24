#!/bin/sh
# 容器入口：非 root uid 10001 运行。挂载目录权限由宿主机预先修复。
# 任何权限失败都会在日志里打印具体修复命令，便于直接复制执行。
set -eu

: "${ACME_HOME:=/acme.sh}"
: "${ACME_PANEL_DATA:=/data}"

# 权限修复提示（用户可直接复制到宿主机执行）
perm_hint() {
  echo "===================================================================" >&2
  echo "[entrypoint] 目录无权限：$1（容器内路径）" >&2
  echo "[entrypoint] 在宿主机执行下面这条命令即可修复（用容器内路径，不用找宿主机路径）：" >&2
  echo "  docker exec -u root acmesh-panel chown -R 10001:10001 $1" >&2
  echo "===================================================================" >&2
}

# 首次启动：从镜像内置模板初始化 acme.sh（模板已设为全局可读）
if [ ! -x "$ACME_HOME/acme.sh" ]; then
  echo "[entrypoint] $ACME_HOME 中没有 acme.sh，从镜像内置模板初始化"
  mkdir -p "$ACME_HOME" 2>/dev/null || true
  if [ -d /opt/acme-template ]; then
    if ! cp -R /opt/acme-template/. "$ACME_HOME"/ 2>/tmp/cp-error; then
      cat /tmp/cp-error >&2 || true
      perm_hint "$ACME_HOME"
      echo "[entrypoint] 初始化未完成，继续启动面板（acme.sh 可能不可用）" >&2
    else
      chmod +x "$ACME_HOME/acme.sh" 2>/dev/null || true
    fi
  else
    echo "[entrypoint] 镜像内缺少 /opt/acme-template，无法初始化 acme.sh" >&2
  fi
fi

mkdir -p "$ACME_PANEL_DATA" 2>/dev/null || true
chmod 700 "$ACME_PANEL_DATA" 2>/dev/null || true

# 检查证书同步目录的写权限，失败时打印修复命令（不阻断启动）
if [ -n "${ACME_PANEL_SYNC_DIR:-}" ]; then
  old_ifs=$IFS
  IFS=',;'
  for d in $ACME_PANEL_SYNC_DIR; do
    [ -n "$d" ] || continue
    if [ -d "$d" ] && [ ! -w "$d" ]; then
      perm_hint "$d"
    fi
  done
  IFS=$old_ifs
fi

exec /usr/local/bin/acmesh-panel "$@"
