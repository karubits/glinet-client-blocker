# Configuration Directory

This directory contains all user-configurable files for the GL.iNet Client Block Web UI.

## Files

### `mapping.csv`
Maps categories to client list files. Format:
```
Category Name,client-list-filename.csv
```

Example:
```
Gaming Devices,client-list-games.csv
TV Devices,client-list-media.csv
```

### `services.yml`
Configuration for network-wide service blocking via AdGuard Home. Lists all available services that can be blocked.

### `routers.csv` (Optional)
Router configuration file. Only needed if not using environment variables.
Format:
```
HOST,PASS
100.65.142.110,password1
100.122.185.100,password2
```

### `clients/` directory
Contains client list CSV files. Each file should have the format:
```
MAC_ADDRESS,CLIENT_NAME
AA:BB:CC:DD:EE:FF,Device Name
```

## Setup

1. Copy example files:
   ```bash
   cp mapping.example.csv mapping.csv
   cp routers.example.csv routers.csv  # Optional
   cp clients/*.example.csv clients/
   ```

2. Edit the files with your actual data

3. The files will be automatically mounted into the Docker container at `/config/`

## YouTube block (AdGuard Home)

The YouTube block feature controls AdGuard Home on each router.

**On GL.iNet (root + router password only):** The app uses **HTTP only**. It first logs in to the router (RPC challenge + login with root + router password), then calls **http://router/control/...** (the router’s nginx proxies `location /control/` to AdGuard on port 3000). No separate AdGuard password; the router session authenticates the request.

- **Default:** Router proxy (root + router password). No extra env vars needed.
- **Optional:** To use direct AdGuard API (host:3000) instead, set an admin user/password in AdGuard on the router and set `ADGUARD_PASSWORD` (and optionally `ADGUARD_USERNAME`) in the app. On stock GL.iNet, AdGuard often has `users: []`, so direct API can hit rate limits (429) after failed logins.

## Notes

- Files with `.example` suffix are templates and are tracked in git
- Actual configuration files (without `.example`) are ignored by git for security
- All files in this directory are mounted read-only in the Docker container