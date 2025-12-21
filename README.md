# GL.iNet Client Blocking Tool

A Python script and web interface for managing client blocking/unblocking on GL.iNet routers.

## Project Structure

This repository contains two separate components:

### 📜 Script (`glinet-client-block-script/`)
Command-line tool for blocking/unblocking clients. See [`glinet-client-block-script/README.md`](glinet-client-block-script/README.md) for details.

### 🌐 Web UI (`glinet-client-block-ui/`)
Web interface for managing client blocking/unblocking. See [`glinet-client-block-ui/README.md`](glinet-client-block-ui/README.md) for details.

## Shared Resources

- **`clients/`** - Client list CSV files used by both the script and web UI
  - See `clients/*.example.csv` for example formats
  - **Important:** Your actual client lists are in `.gitignore` to protect privacy

## Setup

### First Time Setup

1. **Copy example files:**
   ```bash
   # For script usage
   cd glinet-client-block-script
   cp routers.example.csv routers.csv
   
   # For web UI usage
   cd glinet-client-block-ui
   cp .env.example .env
   cp data/mapping.example.csv data/mapping.csv
   cp data/routers.example.csv data/routers.csv  # Optional if using env vars
   cp data/clients/*.example.csv data/clients/
   ```

2. **Edit the files with your actual data:**
   - Update `routers.csv` with your router IPs and passwords
   - Update `.env` with your web UI password and router configuration
   - Update `mapping.csv` with your categories
   - Update client list CSV files with your device MAC addresses

**Security Note:** All personal data files (client lists, routers.csv, .env) are in `.gitignore` and will not be committed to git.

## Quick Start

### Using the Script
```bash
cd glinet-client-block-script
./setup.sh
./glinet-block --list ../clients/client-list-games.csv --block
```

### Using the Web UI
```bash
cd glinet-client-block-ui
docker-compose up -d
```

Then access `http://localhost:5000`

## License

This project is provided as-is for personal use.
