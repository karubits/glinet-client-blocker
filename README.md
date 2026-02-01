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

## License

This project is provided as-is for personal use.
