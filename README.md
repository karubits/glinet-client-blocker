# GL.iNet Client Block

A web interface for managing client blocking/unblocking and service blocking (YouTube, Roblox) on GL.iNet routers via AdGuard Home.

## Project Structure

```
glinet-client-block/
├── glinet-client-block-ui/    # Web UI (Docker)
│   ├── config/                # Configuration (mounted as volume)
│   ├── webapp/                # Flask app and blocking logic
│   ├── compose.yml
│   ├── Dockerfile
│   └── README.md
├── .env.example               # Example env for Web UI
└── README.md
```

## Setup

1. **Copy example files**:
   ```bash
   cd glinet-client-block-ui
   cp ../.env.example .env
   cp config/mapping.example.csv config/mapping.csv
   cp config/routers.example.csv config/routers.csv   # Optional if using env vars
   cp config/clients/*.example.csv config/clients/
   ```

2. **Edit configuration**:
   - **`.env`** – Web UI password, router hosts/passwords (and optional AdGuard credentials). See `.env.example` and `glinet-client-block-ui/README.md`.
   - **`config/mapping.csv`** – Category name → client list filename.
   - **`config/routers.csv`** – Router IP and password (only if not using router env vars in `.env`).
   - **`config/clients/*.csv`** – MAC address and device name per line.

**Security:** Config files and `.env` are in `.gitignore` and are not committed.

## Quick Start

```bash
cd glinet-client-block-ui
docker compose up -d
```

Then open **http://localhost:5000** and log in with the password set in `WEBUI_PASSWORD` (or `.env`).

## License

This project is provided as-is for personal use.
