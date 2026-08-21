# WeBridge

A self-hosted, all-round file downloader portal. Paste a link from any supported sharing service and download the file straight through your own server — no direct internet access needed for users, no files stored on disk.

**Vision:** one downloader for everything. WeTransfer works today; new sources plug in behind a tiny `Matches / Resolve / Stream` interface, so Google Drive, Dropbox, pCloud and friends are a matter of adding one client — the auth, UI, limits and auditing around them stay the same.

## Features

- **Multi-source by design**: providers self-declare which URLs they handle (`Matches`); the rest of the system never cares where the file came from
- **Zero-disk streaming**: bytes flow source CDN → your server → user, nothing touches disk
- **Web UI**: paste URL → click download; per-user Recent list with one-click retry
- **Accounts & RBAC**: local users or LDAP/AD SSO, groups grant permissions (`download`, `dashboard`, `audit`, `users`, `groups`); admin role = full access
- **Admin console**: metrics dashboard, live audit log, user/group management, LDAP settings editable in the UI (no restart)
- **Resilient**: retries, resume via Range headers
- **Dockerized**: single multi-stage image (~20MB), non-root user
- **Observable**: JSON logging, health checks, in-app audit trail
- **Secure**: domain allowlist, SSRF protection, rate limiting, security headers

## Quick Start

### Docker (Recommended)

```bash
docker compose -f deploy/docker/docker-compose.yml up -d

# Or manually
docker build -t webridge -f deploy/docker/Dockerfile .
docker run -p 8080:8080 -v $(pwd)/config.yaml:/app/config.yaml webridge
```

Default login: `admin` / `admin123` — change it immediately.

### Local Development

```bash
make build
./bin/proxy-downloader -config configs/config.yaml.example
```

## Configuration

Copy `configs/config.yaml.example` to `config.yaml` and adjust:

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
```

LDAP/AD login is optional — configure it in the file (`ldap:` section) or live in the admin UI. Environment variables override config (prefix `PROXY_`, e.g. `PROXY_SERVER_PORT=8080`). `LDAP_SETTINGS_FILE` sets where UI-edited LDAP settings persist.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI (embedded SPA) |
| `/api/v1/info` | GET | File metadata (`?url=...`) |
| `/api/v1/download` | GET | Streamed download (`?url=...`) |
| `/api/v1/downloads/recent` | GET | Current user's last downloads |
| `/api/v1/admin/*` | GET/POST/PUT/DELETE | Users, groups, audit log, metrics, LDAP |
| `/healthz`, `/readyz` | GET | Probes |

## Supported Sources

| Service | Status |
|---------|--------|
| WeTransfer (`wetransfer.com`, `we.tl`) | ✅ built in |
| More services | 🧩 add one — see below |

Password-protected WeTransfer transfers are supported (the UI asks when needed).

## Production Deployment

Terminate TLS at a reverse proxy:

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

Kubernetes: run the image as a Deployment with liveness/readiness probes on `/healthz` and `/readyz`; mount your `config.yaml`.

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
- Session cookies, bcrypt-hashed passwords, non-root container

## Adding a Source

Any type with three methods is a provider:

```go
func (c *MyClient) Matches(rawURL string) bool                  // "this URL is mine"
func (c *MyClient) Resolve(ctx, url, auth) (*TransferInfo, err) // metadata + direct link
func (c *MyClient) Stream(ctx, info, w) error                   // pipe bytes out
```

See `internal/wetransfer/wetransfer.go` for a complete implementation. Wire it into `cmd/server/main.go` alongside the existing client and extend the domain allowlist in `internal/middleware/security.go`.

## License

MIT
