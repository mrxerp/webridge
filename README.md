# WeBridge

A self-hosted file downloader portal. Paste a link from any supported sharing service and download the file straight through your server — no direct internet access needed for users, no files stored on disk.

## Features

- **Multi-source by design**: providers self-declare which URLs they handle; the rest of the system never cares where the file came from
- **Zero-disk streaming**: bytes flow source CDN → your server → user, nothing touches disk
- **Web UI**: paste URL → click download; per-user Recent list with one-click retry
- **Accounts & RBAC**: local users, LDAP/AD SSO, or org-email (IMAP); groups grant permissions (`download`, `audit`, `users`, `groups`); admin role = full access
- **Admin console**: download stats, live audit log, user/group management, LDAP + IMAP settings editable in the UI (no restart)
- **Resilient**: retries, resume via Range headers
- **Dockerized**: single multi-stage image (~20MB), non-root user
- **Observable**: JSON logging, health checks, in-app audit trail with SQLite persistence
- **Secure**: domain allowlist, SSRF protection, rate limiting, security headers

## Quick Start

### Docker (Recommended)

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/mrxerp/webridge:v0.2.5

# Run with a single volume mount
docker run -d -p 8080:8080 \
  -v ./config:/app/config \
  --name webridge \
  --restart unless-stopped \
  ghcr.io/mrxerp/webridge:v0.2.5
```

**Default login**: `admin` / `admin123` — change it immediately.

### Docker Compose

```bash
mkdir -p config
cp configs/config.yaml.example config/config.yaml
docker compose -f deploy/docker/compose.yaml up -d
```

### Local Development

```bash
go build -o webridge ./cmd/server
./webridge -config configs/config.yaml.example
```

## Docker Image

Available on [GitHub Container Registry](https://github.com/mrxerp/webridge/pkgs/container/webridge):

| Tag | Platforms | Description |
|-----|-----------|-------------|
| `v0.2.5` | `linux/amd64`, `linux/arm64` | Pinned release |
| `latest` | `linux/amd64`, `linux/arm64` | Latest stable |

```bash
docker pull ghcr.io/mrxerp/webridge:v0.2.5
```

## Configuration

### Directory Structure (Docker)

```
/app/
├── webridge                 # binary
└── config/
    ├── config.yaml          # main config (edit this)
    ├── ldap-settings.json   # LDAP settings (managed by UI)
    ├── imap-settings.json   # IMAP settings (managed by UI)
    └── data/
        ├── audit.db         # SQLite audit database
        └── logs/            # daily access logs (JSONL)
```

Mount a single volume: `-v ./config:/app/config`

### Config File (`config/config.yaml`)

Copy `configs/config.yaml.example` to `config/config.yaml` and adjust:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  write_timeout: 0        # 0 = no timeout for streaming

auth:
  session_ttl: 24h
  users:
    - username: "admin"
      password: "admin123"   # CHANGE THIS

wetransfer:
  request_timeout: 30s
  max_redirects: 10

limits:
  max_concurrent_downloads: 50
  max_file_size_gb: 2
  rate_limit_per_minute: 30

logging:
  level: "info"
  format: "json"

ui:
  title: "WeBridge"

audit:
  db_path: "/app/config/data/audit.db"
  retention_days: 90
  access_log_dir: "/app/config/data/logs"
```

### Environment Variables (override config)

All `PROXY_*` vars override the YAML. Common ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_SERVER_PORT` | 8080 | Listen port |
| `PROXY_LOGGING_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PROXY_AUDIT_DB_PATH` | `/app/config/data/audit.db` | SQLite path |
| `PROXY_AUDIT_ACCESS_LOG_DIR` | `/app/config/data/logs` | Access log dir |
| `LDAP_SETTINGS_FILE` | `/app/config/ldap-settings.json` | LDAP settings file |
| `IMAP_SETTINGS_FILE` | `/app/config/imap-settings.json` | IMAP settings file |
| `CONFIG_PATH` | `/app/config/config.yaml` | Main config path |

### LDAP / SSO

Optional — configure in the file (`ldap:` section) or live in the admin UI (Settings → LDAP). Users authenticate against the directory on first login, then are auto-added as local users (source: `ldap`) so you can assign groups/roles.

### IMAP Email Sign-in

Optional — users can log in with their org email address. Credentials verified against the IMAP server; no password stored locally. Configure in Settings → Email Sign-in. Domain allowlist enforced.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI (embedded SPA) |
| `/api/v1/info` | GET | File metadata (`?url=...`) |
| `/api/v1/download` | GET | Streamed download (`?url=...`) |
| `/api/v1/downloads/recent` | GET | Current user's last downloads |
| `/api/v1/admin/*` | GET/POST/PUT/DELETE | Users, groups, audit log, metrics, LDAP, IMAP |
| `/healthz` | GET | Liveness probe |

## Supported Sources

| Service | Hosts | Status |
|---------|-------|--------|
| **WeTransfer** | `wetransfer.com`, `we.tl` | ✅ built in |
| **SendGB** | `sendgb.com`, `www.sendgb.com` | ✅ built in |
| **TransferNow** | `transfernow.net`, `www.transfernow.net` | ✅ built in |
| **Wesendit** | `wesendit.com`, `www.wesendit.com` | ✅ built in |
| **SendSpace** | `sendspace.com`, `www.sendspace.com` | ✅ built in |

Password-protected transfers are supported (the UI asks when needed).

## Production Deployment

Terminate TLS at a reverse proxy (nginx, Traefik, Caddy):

```nginx
server {
    listen 443 ssl http2;
    server_name download.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    proxy_read_timeout 3600s;
    proxy_request_buffering off;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

Kubernetes: run the image as a Deployment with liveness/readiness probes on `/healthz`; mount your `config/` directory.

### Docker Compose (single volume)

```yaml
services:
  webridge:
    image: ghcr.io/mrxerp/webridge:v0.2.5
    #build:                                        # dev: build from source
    #  context: ..
    #  dockerfile: deploy/docker/Dockerfile
    container_name: webridge
    restart: unless-stopped
    ports:
    - "8080:8080"
    environment:
    - CONFIG_PATH=/app/config/config.yaml
    - LDAP_SETTINGS_FILE=/app/config/ldap-settings.json
    - IMAP_SETTINGS_FILE=/app/config/imap-settings.json
    - PROXY_LOGGING_LEVEL=info
    volumes:
    - ./config:/app/config
```

## Architecture

```
User (Browser) → [HTTPS] → Your Server → [HTTPS] → Source API/CDN
                                     ↓
                             Resolve direct URL
                                     ↓
                             Stream → User
```

No files stored on disk — pure streaming with `io.CopyBuffer`.

## Security

- Domain allowlist enforced per request (SSRF guard)
- Private/loopback/link-local IP blocking
- Rate limiting per IP (token bucket) + global concurrency cap
- Security headers (CSP, HSTS, ...)
- Session cookies, SHA-256+salt hashed passwords at runtime, non-root container

## Adding a Source

Any type with three methods is a provider:

```go
func (c *MyClient) Matches(rawURL string) bool                  // "this URL is mine"
func (c *MyClient) Resolve(ctx, url, auth) (*TransferInfo, err) // metadata + direct link
func (c *MyClient) Stream(ctx, info, w) error                   // pipe bytes out
```

See `internal/providers/wetransfer.go` for a complete implementation. Wire it into `cmd/server/main.go` alongside the existing clients.