# GL.iNet Client Block

A web interface for managing client blocking/unblocking and service blocking (YouTube, Roblox) on GL.iNet routers via AdGuard Home.

## Project Structure

```
glinet-client-block/
├── glinet-client-block/       # Web UI (Docker)
│   ├── config/                # Configuration (mounted as volume)
│   │   ├── config.example.yaml   # Template; copy to config.yaml
│   │   └── README.md
│   ├── webapp/                # Flask app and blocking logic
│   ├── compose.yml
│   ├── Dockerfile
│   └── README.md
├── .env.example               # Example env for Web UI
└── README.md
```

---

## Deploying with Docker

### 1. Create a directory and add a compose file

Create a directory anywhere on your host, e.g. `~/glinet-block/`, then create a `compose.yml`:

```yaml
services:
  glinet-webui:
    image: harbor.karubits.com/public/glinet-client-block:latest
    container_name: glinet-client-block-webui
    ports:
      - "5000:5000"
    volumes:
      - ./config:/config:ro
    env_file:
      - .env
    restart: unless-stopped
```

> For Traefik users, add the appropriate labels and networks — see the example in `glinet-client-block/compose.yml`.

### 2. Create the config directory and config file

The app reads `/config/config.yaml` inside the container, which maps to `./config/config.yaml` next to your compose file.

```
~/glinet-block/
├── compose.yml
├── .env
└── config/
    └── config.yaml      ← you must create this
```

Create `config/config.yaml` with your devices and (optionally) routers:

```yaml
# Devices: category -> device name -> mac
# These appear as groups in the web UI for blocking/unblocking.
devices:
  Kids Devices:
    ipad-kid:
      mac: "AA:BB:CC:DD:EE:01"
    nintendo-switch:
      mac: "AA:BB:CC:DD:EE:02"
  TV Devices:
    smart-tv:
      mac: "AA:BB:CC:DD:EE:10"

# Optional: AdGuard Home service IDs for network-wide blocking
services:
  - youtube
  - roblox
```

> **Client list is empty?** This almost always means `config/config.yaml` is missing or has no `devices` section. The file must exist at `./config/config.yaml` relative to your `compose.yml`.

Routers are configured via env vars in `.env` (preferred) or in `config.yaml` under a `routers:` key.

### 3. Create the .env file

```env
WEBUI_PASSWORD=your-secure-password
SECRET_KEY=change-this-to-a-long-random-string

# Router credentials (up to 3; add more numbered vars as needed)
ROUTER_HOST_1=192.168.1.1
ROUTER_PASS_1=your-router-password
ROUTER_NAME_1=Home Router
```

For OIDC/Authentik, see the [Authentication](#authentication) section below.

### 4. Start

```bash
docker compose up -d
```

Open **http://localhost:5000** and log in with the password set in `WEBUI_PASSWORD`.

---

## Authentication

Two mutually exclusive modes, controlled by `OIDC_ENABLED`.

### Password mode (default)

```env
WEBUI_PASSWORD=your-secure-password
```

### OIDC mode (Authentik / OpenID Connect)

When `OIDC_ENABLED=true`, the login page shows a **"Login with Authentik"** button instead of the password form. Set `OIDC_ENABLED=false` and restart to revert.

#### Authentik setup

1. In **Authentik Admin → Applications**, create a new **OAuth2/OpenID Provider**:
   - **Client type**: `Confidential`
   - **Redirect URI**: `https://<your-app-domain>/oidc/callback`
   - **Scopes**: `openid`, `email`, `profile`
   - Note the generated **Client ID** and **Client Secret**

2. Create an **Application** that uses this provider.

3. Copy the **OpenID Configuration URL** from the provider detail page:
   ```
   https://<authentik-domain>/application/o/<app-slug>/.well-known/openid-configuration
   ```

#### Required env vars

```env
OIDC_ENABLED=true
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_DISCOVERY_URL=https://auth.example.com/application/o/glinet-block/.well-known/openid-configuration
SECRET_KEY=change-this-to-a-long-random-string
```

#### Restricting access

Manage access on the Authentik side via **Application → Policy / Group Bindings**. Users outside bound groups are denied before the callback reaches the app.

---

## Publishing to Harbor

The image is published to `harbor.karubits.com/public/glinet-client-block`.

Build and push with both a version tag and `latest`:

```bash
cd glinet-client-block

docker build \
  -t harbor.karubits.com/public/glinet-client-block:1.11 \
  -t harbor.karubits.com/public/glinet-client-block:latest \
  .

docker push harbor.karubits.com/public/glinet-client-block:1.11
docker push harbor.karubits.com/public/glinet-client-block:latest
```

The version is defined in `webapp/app.py` (`APP_VERSION` / `APP_VERSION_DATE`) and rendered automatically in the footer of both pages. To bump the version, update those two constants and rebuild.

> Log in first if needed: `docker login harbor.karubits.com`

To pull the image on another host:

```bash
docker pull harbor.karubits.com/public/glinet-client-block:latest
```

---

## License

This project is provided as-is for personal use.
