# GL.iNet Client Block Web UI

A clean, user-friendly web interface for managing client blocking/unblocking on GL.iNet routers.

## Quick Start

### Using Docker Compose

1. **Set environment variables** (create a `.env` file or export them):
   ```bash
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
   docker-compose up -d
   ```

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
ROUTER_HOST_2="100.122.185.100"
ROUTER_PASS_2="password2"
ROUTER_HOST_3="192.168.1.1"
ROUTER_PASS_3="password3"
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
- `ROUTER_HOSTS`: Comma-separated list of router IPs
- `ROUTER_PASSES`: Comma-separated list of router passwords
- `ROUTER_HOST_1`, `ROUTER_PASS_1`, etc.: Numbered router configuration

## Logging

The web UI provides detailed logging for all operations:
- Router connection attempts
- Authentication status
- Block/unblock operations per client
- Success/failure counts per router
- Overall operation summaries

View logs with:
```bash
docker-compose logs -f glinet-webui
```

## Features

- 🔐 **Password-only authentication** with 4-hour session cookies
- 🎨 **Clean, modern UI** with bright pink accent color
- 📱 **User-friendly** interface designed for non-technical users
- 🐳 **Docker ready** with Docker Compose support
- 📋 **Category management** - organize clients by categories
- ⚡ **Quick actions** - block/unblock all clients or by category
- 📊 **Detailed logging** - see exactly what's happening in docker logs

## Troubleshooting

### "No routers configured"
- Check that router environment variables are set correctly
- Verify `config/routers.csv` exists if using file-based config
- Check docker logs: `docker-compose logs glinet-webui`

### "No clients found"
- Verify `config/mapping.csv` exists and is correctly formatted
- Check that client list files are in `config/clients/`
- Ensure client list files have the correct CSV format

### "No services found"
- Verify `config/services.yml` exists and is correctly formatted
- Check docker logs for YAML parsing errors
- Ensure the file is properly mounted in docker-compose

### Authentication fails
- Verify `SECRET_KEY` is set
- Check password is correct

