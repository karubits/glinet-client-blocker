# Web UI Data Directory

This directory contains configuration and client list files for the web UI.

## Files

### `mapping.csv`
Maps category names to client list files. See `mapping.example.csv` for format.

### `routers.csv` (Optional)
Router configuration file. Only used if environment variables are not set.
See `routers.example.csv` for format.

### `clients/`
Directory containing client list CSV files. See `clients/*.example.csv` for examples.

## Setup

1. **Copy example files:**
   ```bash
   cp mapping.example.csv mapping.csv
   cp routers.example.csv routers.csv  # Optional if using env vars
   cp clients/*.example.csv clients/
   ```

2. **Edit the files with your actual data:**
   - Update `mapping.csv` with your categories and client list filenames
   - Update `routers.csv` with your router IPs and passwords (or use environment variables)
   - Update client list CSV files with your device MAC addresses and names

## Security Note

**DO NOT commit your actual data files to git!** They contain personal information.
Only commit example files (`.example.csv`).

