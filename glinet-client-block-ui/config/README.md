# Configuration Directory

This directory contains configuration for the GL.iNet Client Block Web UI.

## Single-file configuration (recommended)

Use **`config.yaml`** for all settings: routers, devices (by category), and optional AdGuard services. All devices live in this single YAML file; no CSV files.

1. Copy the example and edit:
   ```bash
   cp config.example.yaml config.yaml
   ```
2. Edit `config.yaml` with your routers, categories, and devices.

### config.yaml structure

```yaml
# Routers: add as many as you need (or use Docker Compose env vars)
routers:
  - host: 192.168.1.1
    password: YourRouterPassword1
    name: Living Room
  - host: 192.168.1.2
    password: YourRouterPassword2
    name: Office

# Devices: category -> device name -> mac (sub-category is the map, then the device)
devices:
  Gaming Devices:
    nintendo-switch:
      mac: "AA:BB:CC:DD:EE:01"
    playstation-5:
      mac: "AA:BB:CC:DD:EE:02"
  TV Devices:
    smart-tv:
      mac: "AA:BB:CC:DD:EE:10"
    apple-tv:
      mac: "AA:BB:CC:DD:EE:11"
  # Add more categories and devices as needed

# Optional: AdGuard Home service IDs (YouTube, Roblox, etc.)
services:
  - youtube
  - roblox
```

- **routers**: List of `host`, `password`, and optional `name`. Prefer defining routers in Docker Compose env vars.
- **devices**: Category names as keys; each value is a dict of device name → `mac` (and optional `name` for display). Add more categories and devices as needed.
- **services**: Optional list of AdGuard service IDs for network-wide blocking in the Web UI.

The file is designed to be expanded: add more routers, categories, or devices without changing the format.

## Legacy configuration (optional)

If `config.yaml` is not present, the app falls back to:

- **routers.csv** – Router list (HOST,PASS). Only used when env vars and config.yaml are not set.
- **mapping.csv** – Category name and client list filename per line.
- **clients/** – Directory of client list CSV files (MAC_ADDRESS,CLIENT_NAME).
- **services.yml** – Optional `services:` list for AdGuard.

Prefer `config.yaml` to avoid maintaining multiple files.

## Setup

1. Copy and edit:
   ```bash
   cp config.example.yaml config.yaml
   ```
2. Fill in your routers, client categories, and MAC addresses.
3. Mount this directory into the container at `/config/` (e.g. in `compose.yml`: `./config:/config:ro`).

## YouTube / Roblox block (AdGuard Home)

The Web UI controls AdGuard Home on each router.

**On GL.iNet (root + router password only):** The app uses the router proxy. It logs in to the router (root + router password), then calls **http://router/control/...** (nginx proxies to AdGuard on port 3000). No separate AdGuard password is needed.

- **Default:** Router proxy (root + router password). No extra env vars.
- **Optional:** To use the direct AdGuard API (host:3000), set an admin user/password in AdGuard and set `ADGUARD_PASSWORD` (and optionally `ADGUARD_USERNAME`) in the app.

## Notes

- `config.yaml` contains credentials and is ignored by git.
- `config.example.yaml` is a template and is tracked in git.
- The config directory is typically mounted read-only in the container.
