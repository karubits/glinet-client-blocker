# GL.iNet Client Block

A web interface for managing client blocking/unblocking and service blocking (YouTube, Roblox) on GL.iNet routers via AdGuard Home.

## Project Structure

```
glinet-client-block/
├── glinet-client-block-ui/    # Web UI (Docker)
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

## Setup

1. **Copy config and env**:
   ```bash
   cd glinet-client-block-ui
   cp ../.env.example .env
   cp config/config.example.yaml config/config.yaml
   ```

2. **Edit configuration**:
   - **`.env`** – Web UI password; optional router hosts/passwords (see `.env.example` and `glinet-client-block-ui/README.md`).
   - **`config/config.yaml`** – Single file for routers, client categories (mapping), and optional AdGuard services. See `config/config.example.yaml` and `config/README.md`.

**Security:** `config/config.yaml` and `.env` are in `.gitignore` and are not committed.

## Quick Start

```bash
cd glinet-client-block-ui
docker compose up -d
```

Then open **http://localhost:5000** and log in with the password set in `WEBUI_PASSWORD` (or `.env`).

---

## Authentication

The app supports two mutually exclusive authentication modes, controlled by the `OIDC_ENABLED` environment variable.

### Password mode (default)

The login page shows a password form. Set `WEBUI_PASSWORD` in `.env`:

```env
WEBUI_PASSWORD=your-secure-password
```

### OIDC mode (Authentik / OpenID Connect)

When `OIDC_ENABLED=true`, the login page shows a **"Login with Authentik"** button instead of the password form. Authentication is fully delegated to your Authentik instance.

To switch back to password auth at any time, set `OIDC_ENABLED=false` and restart the container — no other changes needed.

#### Setting up the Authentik application

1. In **Authentik Admin → Applications**, create a new **OAuth2/OpenID Provider**:
   - **Authorization flow**: choose your preferred flow (e.g. `default-provider-authorization-implicit-consent`)
   - **Client type**: `Confidential`
   - **Redirect URI**: `https://<your-app-domain>/oidc/callback`
   - **Scopes**: `openid`, `email`, `profile`
   - Note the generated **Client ID** and **Client Secret**

2. Create an **Application** that uses this provider.

3. Copy the **OpenID Configuration URL** from the provider's detail page — it looks like:
   ```
   https://<authentik-domain>/application/o/<app-slug>/.well-known/openid-configuration
   ```

#### Environment variables

Add these to your `.env` file:

```env
# Enable OIDC (set to false to revert to password auth)
OIDC_ENABLED=true

# From the Authentik OAuth2 provider
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret

# OpenID Connect discovery URL
OIDC_DISCOVERY_URL=https://auth.example.com/application/o/glinet-block/.well-known/openid-configuration

# Flask session key — must be a long random string when exposed to the internet
SECRET_KEY=change-this-to-a-random-secret
```

Then restart the container:
```bash
docker compose up -d
```

#### Restricting access to specific groups

Access control is managed entirely on the Authentik side — no changes to this app are needed. In Authentik, open your **Application → Policy / Group Bindings** and bind it to the groups that should have access. Users outside those groups will be denied by Authentik before the callback ever reaches the app.

---

## License

This project is provided as-is for personal use.
