<div align="center">
  <img src="assets/logo.png" alt="acmesh-panel" width="120">
</div>

# acmesh-panel (English Guide)

[![CI](https://github.com/ForAllCodeSouls/acmesh-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/ForAllCodeSouls/acmesh-panel/actions/workflows/ci.yml)
[![Docker](https://github.com/ForAllCodeSouls/acmesh-panel/actions/workflows/docker.yml/badge.svg)](https://github.com/ForAllCodeSouls/acmesh-panel/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **简体中文完整文档：[README.md](README.md) · 日本語ガイド：[README.ja.md](README.ja.md)**
> This is a condensed English guide. The Chinese README is the authoritative, full documentation (per-OS steps, full FAQ).

**A lightweight certificate management panel for acme.sh, protected by a single username/password login.** One Go binary with an embedded web UI, shipped as a ~45 MB Alpine image. All state is stored in SQLite (transactional writes). Supports DNS API issuance (including wildcard certificates), per-domain ACME e-mail overrides, webhook notifications, and viewing / copying / downloading certificates and private keys from the web UI.

---

## Why use it

![acmesh-panel workflow](docs/01-overview.svg)

If you have one host and one domain, plain `acme.sh` is enough. This panel earns its place when you have several hosts and domains: issue once, then distribute certificates and keys automatically, see remaining validity at a glance, and never let a certificate expire unnoticed. DNS-01 validation means no public port 80/443 is required.

**How matching works** (all examples use placeholder domains): `example.com` is the registered domain; `www.example.com` is a subdomain. A certificate with `*.example.com` covers one level of subdomains only, so `www.example.com` matches but `deep.api.example.com` does not. Matching compares the CN/SAN **inside the target certificate file** with certificates already issued by the panel — never the filename or hostname. Unmatched third-party certificates are left untouched.

![Domain matching rules](docs/03-domain-matching.svg)

![Remote sync flow](docs/04-remote-sync.svg)

The full Chinese README has the detailed step-by-step explanation: [README.md](README.md).

---

## Features

| Area | Capability |
|---|---|
| **Authentication** | Single account + PBKDF2-HMAC-SHA256 (600k iterations); smart session cookie (plain `HttpOnly` over HTTP, `Secure` + `SameSite=Lax` when HTTPS is confirmed); CSRF token + smart same-origin check (hostname-based, reverse-proxy friendly, zero config); per-IP exponential lockout after 5 failures; optional 90-day "stay logged in"; env vars initialize credentials on first boot only — later changes made in the web UI persist across restarts, no web signup |
| **Certificates** | Scans acme.sh home and parses X.509: SANs, issuer, validity, key type, days remaining, expiry alerts |
| **Issuance** | DNS API validation, wildcard support; 43 built-in DNS providers, each with verified credential fields and a direct official-site link (full list in [README.md §5.2](README.md#52-签发证书)); ECC 256/384 and RSA 2048/4096 |
| **E-mail** | Global default ACME e-mail + per-domain overrides |
| **Notifications** | Gotify / generic webhook / ServerChan³ / DingTalk / Feishu (Lark) / Bark; 11 subscribable events |
| **Private keys** | View + copy + download with double confirmation, audit logging, 60-second auto-clear |
| **Renewal** | Single / forced / all; built-in scheduler runs `acme.sh --cron` every 12 hours, no host cron needed |
| **Deployment** | `--install-cert` output to `/data/output/<cert>/` (fixed path) |
| **Local sync** | After issue/renew, matched certificate & key files are written into mounted sync dirs; 5 match modes (exact domain / subdomain / wildcard / filename / existing cert CN-SAN), atomic replace, content-fingerprint dedup, force overwrite |
| **Remote sync** | Push matched certs to other hosts over SSH/SFTP using the same rules; key or password auth, credentials encrypted at rest, strict host-key checking after first trust; per-host force/auto sync |
| **Sync records** | Local writes and remote syncs merged into one list with keyword / result / scope / date filters and pagination |
| **Backup** | Export / import a single JSON config file (credentials stay encrypted; login credentials are never overwritten by a backup) |
| **Revoke / remove** | `--revoke`, `--remove` (optionally delete the on-disk directory) |
| **Audit log** | Logins, failures, CSRF blocks, issuance, renewal, key views, deployments, deletions, password change, backup export/import — all stored in SQLite and filterable in the web UI |
| **Frontend** | Hand-written HTML/CSS/JS embedded via `go:embed`, strict CSP, no frameworks, no CDN |

---

## Requirements

| Scenario | Requirement |
|---|---|
| Docker | Docker 20.10+ and Docker Compose v2 |
| Binary (Linux) | Any glibc/musl distro (static binary); install `acme.sh` + `curl` + `openssl` yourself |
| Binary (macOS) | macOS 11+, Intel or Apple Silicon; acme.sh installs natively |
| Binary (Windows) | Windows 10/11 x64; acme.sh needs WSL / Git Bash, or just use Docker |
| Port | Host `8800` → container `8080` |
| Network | Outbound access to the CA and DNS provider APIs during issuance |

---

## Quick start (Docker — recommended)

```bash
mkdir acmesh-panel && cd acmesh-panel
curl -fsSLO https://raw.githubusercontent.com/ForAllCodeSouls/acmesh-panel/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/ForAllCodeSouls/acmesh-panel/main/.env.example
mv .env.example .env
```

Edit `.env` — `ACME_PANEL_PASSWORD` is **required** (compose refuses to start without it, 12+ chars):

```bash
openssl rand -base64 24        # generate, paste into ACME_PANEL_PASSWORD=
```

Then start:

```bash
docker compose pull && docker compose up -d
docker compose ps              # wait until healthy
```

Open `http://<host>:8800`, log in, then issue certificates from the **Certificates** tab (pick a DNS provider, paste its API credentials, enter domains, choose key type).

> Windows users: clone or download the repo, open PowerShell in the folder, and run the same commands. For Synology / Dockge / Portainer, copy the compose template from the Chinese README (§3.5).

---

## Quick start (binary)

```bash
# 1. install acme.sh (https://github.com/acmesh-official/acme.sh)
curl https://get.acme.sh | sh

# 2. install the panel binary (Linux amd64/arm64)
curl -fsSL https://raw.githubusercontent.com/ForAllCodeSouls/acmesh-panel/main/install.sh | sh

# 3. run with required env
ACME_PANEL_USER=admin \
ACME_PANEL_PASSWORD='a-long-random-password-12plus' \
ACME_PANEL_LISTEN=0.0.0.0:8800 \
acmesh-panel
```

A systemd unit example and macOS/Windows instructions are in the Chinese README (§4).

---

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `ACME_PANEL_PASSWORD` | random | 12+ chars; used **only on first boot** when the DB has no password; web changes persist and env no longer overwrites on restart. If unset and DB has no password, a random password is generated and printed to the log once |
| `ACME_PANEL_USER` | `admin` | Login name; first boot only |
| `ACME_PANEL_RESET_CREDENTIALS` | `0` | Set `1` together with both vars above to explicitly reset credentials once (forgot-password escape hatch) |
| `ACME_PANEL_LISTEN` | `0.0.0.0:8080` | Listen address **inside the container** |
| `ACME_PANEL_DATA` | `/data` | State, keys, audit, deploy output |
| `ACME_HOME` | `/acme.sh` | acme.sh home |
| `ACME_BIN` | auto | Path to the acme.sh script (binary deployments) |
| `ACME_PANEL_CA` | `letsencrypt` | `letsencrypt` / `zerossl` / `buypass` / `google` / `letsencrypt_test` |
| `ACME_PANEL_EMAIL` | empty | Passed as `--accountemail`; overrides the web-saved default |
| `ACME_PANEL_TRUST_PROXY` | `0` | **Optional**; only chooses the IP used by rate limiting, never affects HTTP/HTTPS login. Trust `X-Forwarded-For` only behind a fully trusted reverse proxy |
| `ACME_PANEL_TRUST_PROXY_HOPS` | `1` | Number of trusted proxy hops (taken right-to-left from XFF) |
| `ACME_PANEL_ALLOW_LOCAL_WEBHOOK` | `0` | Local e2e testing only; allows webhooks to loopback/LAN (never in production) |
| `ACME_PANEL_CRON` | `1` | Daily renewal scheduler on/off |
| `ACME_PANEL_PARALLEL` | `2` | Task concurrency |
| `TZ` | `Asia/Shanghai` | Timezone for notifications and records |
| `ACME_PANEL_SYNC_DIR` | empty | Comma/semicolon-separated sync directories |

---

## Security model (summary)

- Passwords stored as PBKDF2-HMAC-SHA256 (600k iterations, random salt, constant-time compare).
- Sessions: in-memory + smart cookies — plain `HttpOnly` over plain HTTP, with `Secure` + `SameSite=Lax` added automatically when HTTPS is confirmed (`X-Forwarded-Proto: https` from the proxy or direct TLS). Works on both HTTP and HTTPS without switches; session ID rotates on login.
- The panel serves HTTP only. HTTPS is terminated by your nginx/Caddy; HSTS is emitted by the panel only when HTTPS is confirmed, never over plain HTTP (no more self-lockout).
- CSRF: token on every state-changing request; same-origin check compares hostnames (ignores port/scheme, honors `X-Forwarded-Host`), so a reverse proxy rewriting Host never locks you out, while cross-site requests are rejected when the public hostname is known.
- Static assets carry a version query string so upgrades bypass stale proxy caches without manual purging.
- Brute force: exponential per-IP/username lockout + security notifications.
- Credentials (DNS API keys, notify channels, SSH keys/passwords) encrypted with AES-256-GCM; API returns masked values; logs are scrubbed.
- Web UI: strict CSP, no inline scripts/styles, no CDN.
- Container: non-root uid 10001, `read_only` rootfs, `cap_drop ALL` (only `CHOWN` added).

Known boundaries: single account (no RBAC); private keys are viewable by the admin by design; acme.sh writes DNS credentials in plain text to `/acme.sh/account.conf`; the panel never terminates TLS itself. See [SECURITY.md](SECURITY.md).

---

## FAQ (highlights)

- **Forgot the password?** Set `ACME_PANEL_USER` + `ACME_PANEL_PASSWORD` + `ACME_PANEL_RESET_CREDENTIALS=1`, restart once, then remove the reset flag.
- **Login works but issuance fails?** Check DNS provider credentials and that the domain's NS points at the provider zone; the job log shows the acme.sh output verbatim.
- **Port already in use?** Change the left side of `8800:8080` in `docker-compose.yml`.
- **Behind a reverse proxy?** Terminate HTTPS on nginx/Caddy. Forward `X-Forwarded-Proto: https` so the panel adds `Secure`/HSTS; without it, login still works (plain cookie). No panel-side Cookie/HSTS switches; optionally set `ACME_PANEL_TRUST_PROXY=1` only so rate limiting sees the real client IP.

---

## Build from source

Requires Go 1.26+ (pure Go, no CGO; dependencies: `modernc.org/sqlite`, `golang.org/x/crypto`, `github.com/pkg/sftp`).

```bash
go build -o acmesh-panel .
go vet ./... && go test ./...
```

---

## License

MIT — see [LICENSE](LICENSE). If this panel saved you a renewal headache, you can optionally buy the author a coffee (see the Chinese README).
