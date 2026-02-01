# GL.iNet Client Block Web UI

A clean, user-friendly web interface for managing client blocking/unblocking on GL.iNet routers.

## Quick Start

### Using Docker Compose

1. **Set environment variables** (create a `.env` file in this directory or export them):
   ```bash
   # Option A: copy from repo root and edit
   cp ../.env.example .env

   # Option B: export before running
   export SECRET_KEY="your-secret-key-here"
   export WEBUI_PASSWORD="your-secure-password"
   
   # Router configuration - choose one method:
   
   # Method 1: Comma-separated lists
   export ROUTER_HOSTS="100.65.142.110,100.122.185.100"
   export ROUTER_PASSES="password1,password2"
   
   # Method 2: Numbered variables (for multiple routers)
   export ROUTER_HOST_1="100.65.142.110"
   export ROUTER_PASS_1="password1"
   export ROUTER_HOST_2="100.122.185.100"
   export ROUTER_PASS_2="password2"
   ```

2. **Prepare configuration files**:
   ```bash
   # Copy example files and customize them
   cp config/mapping.example.csv config/mapping.csv
   cp config/routers.example.csv config/routers.csv  # Optional if using env vars
   cp config/clients/*.example.csv config/clients/
   
   # Edit the files with your actual data:
   # - Update mapping.csv with your categories
   # - Update routers.csv with your router IPs/passwords (or use env vars)
   # - Update client list CSV files with your device MAC addresses
   # - Update services.yml with your service blocking preferences
   ```

3. **Build and run**:
   ```bash
   docker compose up -d
   ```
   (Or `docker-compose up -d` with older Docker Compose.)

4. **Access the web UI**:
   - Open your browser to `http://localhost:5000`
   - Or if using Traefik, access via your configured domain

## Router Configuration

The web UI supports multiple methods for configuring routers:

### Method 1: Comma-Separated Lists
```bash
ROUTER_HOSTS="100.65.142.110,100.122.185.100"
ROUTER_PASSES="password1,password2"
```

### Method 2: Numbered Environment Variables
```bash
ROUTER_HOST_1="100.65.142.110"
ROUTER_PASS_1="password1"
ROUTER_NAME_1="Sekine House"
ROUTER_HOST_2="100.122.185.100"
ROUTER_PASS_2="password2"
ROUTER_NAME_2="Minamicho House"
# Add ROUTER_HOST_3, ROUTER_PASS_3, ROUTER_NAME_3 as needed
```

### Method 3: routers.csv File (Fallback)
If no environment variables are set, the web UI will look for `config/routers.csv`:
```
HOST,PASS
100.65.142.110,password1
100.122.185.100,password2
```

## Directory Structure

```
glinet-client-block-ui/
├── webapp/               # Application code
│   ├── app.py           # Flask application
│   ├── glinet_block.py  # Shared blocking logic
│   ├── templates/       # HTML templates
│   │   ├── login.html
│   │   └── dashboard.html
│   └── static/          # Static assets
├── config/              # User configuration files (mounted as volume)
│   ├── mapping.csv      # Category to file mapping
│   ├── services.yml     # Service blocking configuration
│   ├── routers.csv      # Router configuration (optional)
│   └── clients/         # Client list CSV files
├── Dockerfile
├── compose.yml
└── README.md
```

**Note:** 
- Configuration files in `config/` are mounted into the container at `/config/`
- Client list files should be placed in `config/clients/`
- Example files (`.example.csv`, `.example.yml`) are provided as templates

## Environment Variables

- `SECRET_KEY`: Flask secret key for session management (required for production)
- `WEBUI_PASSWORD`: Login password (default: `admin`)
- `WEBUI_PASSWORD_HASH`: Pre-hashed password (optional, overrides `WEBUI_PASSWORD`)
- `CONFIG_DIR`: Config directory inside container (default: `/config`; set by volume mount)
- **Routers** (use one method):
  - `ROUTER_HOSTS`: Comma-separated list of router IPs
  - `ROUTER_PASSES`: Comma-separated list of router passwords
  - Or `ROUTER_HOST_1`, `ROUTER_PASS_1`, `ROUTER_NAME_1`, then `ROUTER_HOST_2`, `ROUTER_PASS_2`, `ROUTER_NAME_2`, etc.
- **AdGuard (YouTube / Roblox block)** – optional; default uses router proxy (root + router password):
  - `ADGUARD_PASSWORD`: AdGuard admin password (only if using direct API to host:3000)
  - `ADGUARD_USERNAME`: AdGuard username (optional; default tries admin then root)

## Logging

The web UI provides detailed logging for all operations:
- Router connection attempts
- Authentication status
- Block/unblock operations per client
- Success/failure counts per router
- Overall operation summaries

View logs with:
```bash
docker compose logs -f glinet-webui
```
(The service name in `compose.yml` is `glinet-webui`; the container name is `glinet-client-block-webui`.)

## Features

- 🔐 **Password-only authentication** with 4-hour session cookies
- 🎨 **Clean, modern UI** with theme and language (EN/JA) support
- 🐳 **Docker ready** – run with `docker compose up -d` from this directory
- 📋 **Client Block Control** – router selector, All Clients, and category blocks (e.g. Gaming Devices, TV Devices)
- ⚡ **Quick actions** – block/unblock all clients or by category
- 📺 **YouTube Block** – per-router Block/Enable via AdGuard Home (uses router proxy by default)
- 🎮 **Roblox Block** – per-router Block/Enable via AdGuard Home
- 📊 **Detailed logging** – all operations logged; use `docker compose logs -f glinet-webui` to follow

## Troubleshooting

### "No routers configured"
- Set router env vars in `.env` (e.g. `ROUTER_HOST_1`, `ROUTER_PASS_1`, `ROUTER_NAME_1`) or use `config/routers.csv`
- Run from `glinet-client-block-ui` so `.env` and `config/` are available: `docker compose up -d`
- Check logs: `docker compose logs glinet-webui`

### "No clients found"
- Ensure `config/mapping.csv` exists and maps category names to filenames under `config/clients/`
- Put client list CSVs in `config/clients/` (e.g. `client-list-games.csv`) with format `MAC_ADDRESS,CLIENT_NAME`
- Confirm the `config` directory is mounted (compose mounts `./config:/config:ro`)

### YouTube / Roblox block fails
- By default the app uses the router proxy (root + router password); no AdGuard password needed
- If you set `ADGUARD_PASSWORD`, ensure an admin user exists in AdGuard on the router
- See `config/README.md` for AdGuard and router proxy details
- Check logs: `docker compose logs glinet-webui`

### Authentication fails (Web UI login)
- Ensure `SECRET_KEY` is set in `.env`
- Use the password set in `WEBUI_PASSWORD` (or `WEBUI_PASSWORD_HASH`)

