# GL.iNet Client Block Web UI

A clean, user-friendly web interface for managing client blocking/unblocking on GL.iNet routers.

## Quick Start

1. **Set up env and config**:
   ```bash
   cp ../.env.example .env
   cp config/config.example.yaml config/config.yaml
   ```

2. **Edit `.env`** with your password and router credentials (see `.env.example`).

3. **Edit `config/config.yaml`** with your routers, device categories, and MAC addresses.

4. **Run**:
   ```bash
   docker compose up -d
   ```

5. Open **http://localhost:5000** and log in.

---

## Router Configuration

Routers can be configured three ways (in order of preference):

### Method 1: config.yaml (recommended)

Define routers in `config/config.yaml` alongside devices and services. See `config/README.md`.

### Method 2: Numbered env variables

```env
ROUTER_HOST_1=192.168.1.1
ROUTER_PASS_1=password1
ROUTER_NAME_1=Home Router
ROUTER_HOST_2=192.168.1.2
ROUTER_PASS_2=password2
ROUTER_NAME_2=Office Router
```

### Method 3: Comma-separated lists

```env
ROUTER_HOSTS=192.168.1.1,192.168.1.2
ROUTER_PASSES=password1,password2
```

### Method 4: routers.csv (legacy fallback)

If no env vars and no `config.yaml`, the app looks for `config/routers.csv`:
```
HOST,PASS
192.168.1.1,password1
192.168.1.2,password2
```

---

## Directory Structure

```
glinet-client-block/
├── webapp/               # Application code
│   ├── app.py           # Flask application (APP_VERSION defined here)
│   ├── glinet_block.py  # Blocking logic
│   ├── templates/       # HTML templates (login, dashboard)
│   └── static/          # Static assets
├── config/              # Configuration (mounted as volume at /config/)
│   ├── config.yaml      # Your config: routers, devices, services (git-ignored)
│   ├── config.example.yaml
│   └── README.md
├── Dockerfile
├── compose.yml
└── README.md
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(insecure default)* | Flask session secret — set a long random string in production |
| `WEBUI_PASSWORD` | `admin` | Login password |
| `WEBUI_PASSWORD_HASH` | — | Pre-hashed password (overrides `WEBUI_PASSWORD`) |
| `ROUTER_HOST_N` | — | Router IP/hostname (N = 1, 2, 3…) |
| `ROUTER_PASS_N` | — | Router password |
| `ROUTER_NAME_N` | — | Router display name (optional) |
| `ROUTER_HOSTS` | — | Comma-separated router IPs (alternative to numbered vars) |
| `ROUTER_PASSES` | — | Comma-separated router passwords |
| `ADGUARD_PASSWORD` | — | AdGuard admin password (only for direct host:3000 API) |
| `ADGUARD_USERNAME` | — | AdGuard username (optional; tries admin then root) |
| `OIDC_ENABLED` | `false` | Set `true` to enable Authentik SSO |
| `OIDC_CLIENT_ID` | — | Authentik OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | — | Authentik OAuth2 client secret |
| `OIDC_DISCOVERY_URL` | — | Authentik OpenID configuration URL |

---

## Logging

```bash
docker compose logs -f glinet-webui
```

---

## Troubleshooting

**"No routers configured"** — Add routers to `config/config.yaml` or set `ROUTER_HOST_1` / `ROUTER_PASS_1` in `.env`.

**"No clients found"** — Add a `devices:` section to `config/config.yaml`. See `config/config.example.yaml`.

**YouTube / Roblox block fails** — By default the app uses the router proxy (root + router password); no AdGuard credentials needed. Check logs for details.

**Login fails** — Ensure `SECRET_KEY` is set and `WEBUI_PASSWORD` matches what you're entering. For OIDC, verify the redirect URI in Authentik matches `https://<your-domain>/oidc/callback`.
