#!/usr/bin/env bash
# 测试用假 acme.sh：模拟签发/续期/部署/删除的最小行为，
# 输出格式与真实 acme.sh 接近，用于端到端验证面板逻辑。
set -uo pipefail

ARGS=("$@")
HOME_DIR="/acme.sh"
i=0
while [ $i -lt ${#ARGS[@]} ]; do
  case "${ARGS[$i]}" in
    --home) HOME_DIR="${ARGS[$((i+1))]}"; i=$((i+2));;
    --log)  i=$((i+2));;
    *) i=$((i+1));;
  esac
done
mkdir -p "$HOME_DIR"

CMD=""
DOMAINS=()
DNS=""
KEYLEN=""
SERVER=""
FORCE=0
KEY_FILE=""; FULLCHAIN_FILE=""; CERT_FILE=""; CA_FILE=""

i=0
while [ $i -lt ${#ARGS[@]} ]; do
  a="${ARGS[$i]}"
  case "$a" in
    --home|--log) i=$((i+2)); continue;;
    --issue|--renew|--renew-all|--cron|--revoke|--remove|--install-cert|--version|--set-default-ca) CMD="$a";;
    -d|--domain) DOMAINS+=("${ARGS[$((i+1))]}"); i=$((i+1));;
    --dns) DNS="${ARGS[$((i+1))]}"; i=$((i+1));;
    --keylength) KEYLEN="${ARGS[$((i+1))]}"; i=$((i+1));;
    --server) SERVER="${ARGS[$((i+1))]}"; i=$((i+1));;
    --key-file) KEY_FILE="${ARGS[$((i+1))]}"; i=$((i+1));;
    --fullchain-file) FULLCHAIN_FILE="${ARGS[$((i+1))]}"; i=$((i+1));;
    --cert-file) CERT_FILE="${ARGS[$((i+1))]}"; i=$((i+1));;
    --ca-file) CA_FILE="${ARGS[$((i+1))]}"; i=$((i+1));;
    --force) FORCE=1;;
    --ecc) ;;
  esac
  i=$((i+1))
done

say() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

case "$CMD" in
  --version)
    echo "v3.1.1-test"; exit 0;;
  --issue)
    d="${DOMAINS[0]:-}"
    [ -z "$d" ] && { echo "缺少域名" >&2; exit 1; }
    [ -z "$DNS" ] && { echo "缺少 --dns" >&2; exit 1; }
    printf '%s\n' "$@" > "$HOME_DIR/last-issue.args"
    case "$d" in
      fail.*) echo "[fake] 模拟 CA 拒绝签发" >&2; exit 1;;
      flaky.*)
        # 首次失败、之后成功：用于验证"失败任务重试"能重新执行并成功。
        flag="$HOME_DIR/.flaky-${d}.done"
        if [ ! -f "$flag" ]; then
          touch "$flag"
          echo "[fake] 模拟首次失败，重试应成功" >&2
          exit 1
        fi
        ;;
    esac
    say "Using CA: ${SERVER:-letsencrypt}"
    say "Single domain='$d'"
    [ ${#DOMAINS[@]} -gt 1 ] && say "Multi domain='${DOMAINS[*]}'"
    say "Getting domain auth token for each domain"
    for x in "${DOMAINS[@]}"; do
      say "Verifying: $x"
      say "Add the following TXT record: _acme-challenge.$x -> dummy-token"
      echo "  (使用 $DNS API 自动添加 TXT 记录)"
      sleep 0.2
      say "Success"
    done
    dir="$HOME_DIR/$d"; [ "$KEYLEN" = "ec-256" ] || [ "$KEYLEN" = "ec-384" ] && dir="$HOME_DIR/${d}_ecc"
    mkdir -p "$dir"
    curve="P-256"; [ "$KEYLEN" = "ec-384" ] && curve="P-384"
    san="DNS:$d"
    for x in "${DOMAINS[@]:1}"; do san="$san,DNS:$x"; done
    if [ "${KEYLEN#ec-}" != "$KEYLEN" ]; then
      openssl req -x509 -newkey ec -pkeyopt "ec_paramgen_curve:$curve" -nodes \
        -keyout "$dir/$d.key" -out "$dir/$d.cer" -days 90 \
        -subj "/CN=$d" -addext "subjectAltName=$san" >/dev/null 2>&1
    else
      openssl req -x509 -newkey "rsa:${KEYLEN:-2048}" -nodes \
        -keyout "$dir/$d.key" -out "$dir/$d.cer" -days 90 \
        -subj "/CN=$d" -addext "subjectAltName=$san" >/dev/null 2>&1
    fi
    cp "$dir/$d.cer" "$dir/fullchain.cer"
    cp "$dir/$d.cer" "$dir/ca.cer"
    chmod 600 "$dir/$d.key"
    {
      echo "Le_Domain='$d'"
      echo "Le_Alt='$(printf '%s\n' "${DOMAINS[@]:1}" | paste -sd, -)'"
      echo "Le_API='${SERVER:-letsencrypt}'"
      echo "Le_Keylength='${KEYLEN:-2048}'"
      echo "Le_Webroot='dns_$DNS'"
    } > "$dir/$d.conf"
    say "Cert success."
    say "Your cert is in: $dir/$d.cer"
    say "Your cert key is in: $dir/$d.key"
    say "The intermediate CA cert is in: $dir/ca.cer"
    exit 0;;
  --renew)
    d="${DOMAINS[0]:-}"
    say "Renew: '$d'"
    [ -f "$HOME_DIR/$d/$d.conf" ] || [ -f "$HOME_DIR/${d}_ecc/$d.conf" ] || { echo "Domain not found" >&2; exit 1; }
    # 模拟 acme.sh "未到续期时间"：域名以 skip. 开头且未加 --force 时返回 2
    case "$d" in
      skip.*)
        if [ "$FORCE" != "1" ]; then
          say "Using CA: Le_API=https://acme.zerossl.com/v2/DV90"
          say "Skipping. Next renewal time is: 2027-02-09T19:04:24Z"
          say "Add '--force' to force renewal."
          exit 2
        fi
        ;;
    esac
    sleep 0.2
    say "Renew success."
    exit 0;;
  --cron|--renew-all)
    say "===Starting cron==="
    for c in "$HOME_DIR"/*; do
      [ -d "$c" ] || continue
      n=$(basename "$c"); n="${n%_ecc}"
      say "Checking $n"
    done
    say "===End cron==="
    exit 0;;
  --revoke)
    say "Revoke: '${DOMAINS[0]}'"
    say "Revoke success."
    exit 0;;
  --remove)
    say "Removed: '${DOMAINS[0]}'"
    exit 0;;
  --install-cert)
    d="${DOMAINS[0]:-}"
    dir="$HOME_DIR/$d"; [ -d "$dir" ] || dir="$HOME_DIR/${d}_ecc"
    say "Installing cert to files"
    [ -n "$KEY_FILE" ] && cp "$dir/$d.key" "$KEY_FILE"
    [ -n "$FULLCHAIN_FILE" ] && cp "$dir/fullchain.cer" "$FULLCHAIN_FILE"
    [ -n "$CERT_FILE" ] && cp "$dir/$d.cer" "$CERT_FILE"
    [ -n "$CA_FILE" ] && cp "$dir/ca.cer" "$CA_FILE"
    say "Run reload cmd: (none)"
    say "Install success."
    exit 0;;
  *)
    echo "fake acme.sh: 未处理的命令 $CMD" >&2; exit 1;;
esac
