# GL.iNet Client Blocking Script

A Python command-line script to manage client blocking/unblocking on GL.iNet routers.

## Features

- ✅ Connect to multiple GL.iNet routers
- ✅ Block/unblock clients by MAC address
- ✅ Batch operations from a client list file
- ✅ Check if clients exist on the router
- ✅ Color-coded terminal output
- ✅ Verbose debugging mode
- ✅ SSL certificate handling (accepts self-signed certificates)
- ✅ Error handling and connection retry logic

## Prerequisites

- Python 3.6 or higher
- Access to GL.iNet router(s)
- Router username and password

## Installation

### Quick Setup

Run the setup script to create a Python virtual environment and install dependencies:

```bash
chmod +x setup.sh
./setup.sh
```

This will:
1. Check if Python 3 is installed
2. Create a virtual environment in `venv/`
3. Install required dependencies

**Note for Fish Shell Users:** The standard `activate` script is for bash/zsh. Use one of these options:
- Use the wrapper script: `./glinet-block --help` (recommended)
- Use venv Python directly: `venv/bin/python3 glinet_block.py --help`
- Use fish activate script: `source venv/bin/activate.fish`

### Manual Setup

If you prefer to set up manually:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration

### Router Configuration

**Option 1: Single router via `--router` argument:**
```bash
./glinet-block --router 100.122.185.100 --list ../clients/client-list-games.csv --block
```

**Option 2: Multiple routers via `--routers` file:**
Create a `routers.csv` file with router IPs and passwords (see `routers.example.csv` for format):

```
HOST,PASS
192.168.1.1,password1
192.168.1.2,password2
```

**Note:** `routers.csv` is in `.gitignore` to protect your credentials. Copy `routers.example.csv` to `routers.csv` and fill in your actual router information.

Then use:
```bash
./glinet-block --routers routers.csv --list ../clients/client-list-games.csv --block
```

**Option 3: Legacy `router-list.txt` (single router, no password):**
Create or edit `router-list.txt` with your router IP address (one per line):
```
100.122.185.100
```

### Client List Format

The client list file(s) should contain MAC addresses and client names in CSV format. Client lists are located in the root `../clients/` directory:

```
MAC_ADDRESS,CLIENT_NAME
FE:49:6A:67:07:EF,iphone-rieko
38:CA:DA:60:7E:06,iphone-jun
38:53:9C:AF:41:EB,iphone-kaito
```

**MAC Address Format Flexibility:**
The script accepts MAC addresses in **any case and format**:
- With colons: `AA:BB:CC:DD:EE:FF` or `aa:bb:cc:dd:ee:ff` or `Aa:Bb:Cc:Dd:Ee:Ff`
- With dashes: `AA-BB-CC-DD-EE-FF`
- With spaces: `AA BB CC DD EE FF`
- No separators: `AABBCCDDEEFF`
- Mixed case: `dc:68:eb:60:3f:ec` (will be normalized to `DC:68:EB:60:3F:EC`)

All formats are automatically normalized to uppercase with colons internally.

**Multiple Client List Files:**
You can specify multiple client list files separated by commas:
```bash
./glinet-block --list ../clients/client-list-games.csv,../clients/client-list-media.csv --block
```

## Usage

### Basic Usage

**Option 1: Use the wrapper script (works with any shell, recommended):**

```bash
./glinet-block --list ../clients/client-list-games.csv --block
./glinet-block --list ../clients/client-list-games.csv --unblock
```

**Option 2: Use venv Python directly (works with any shell):**

```bash
venv/bin/python3 glinet_block.py --list ../clients/client-list-games.csv --block
venv/bin/python3 glinet_block.py --list ../clients/client-list-games.csv --unblock
```

**Option 3: Activate virtual environment (bash/zsh only):**

```bash
source venv/bin/activate  # bash/zsh
# or for fish shell:
source venv/bin/activate.fish  # fish shell

python3 glinet_block.py --list ../clients/client-list-games.csv --block
python3 glinet_block.py --list ../clients/client-list-games.csv --unblock
```

### Advanced Usage

**Specify a single router:**
```bash
python3 glinet_block.py --router 100.122.185.100 --list ../clients/client-list-games.csv --block
```

**Process multiple routers from file:**
```bash
python3 glinet_block.py --routers routers.csv --list ../clients/client-list-games.csv --block
```

**Process multiple client list files:**
```bash
python3 glinet_block.py --list ../clients/client-list-games.csv,../clients/client-list-media.csv --block
```

**Use custom credentials (single router):**
```bash
python3 glinet_block.py --router 100.122.185.100 --username root --password yourpassword --list ../clients/client-list-games.csv --block
```

**Enable verbose output:**
```bash
python3 glinet_block.py --list ../clients/client-list-games.csv --block --verbose
```

## Command Line Options

```
--router ROUTER      Router IP address or hostname (single router mode)
--routers FILE       Path to routers file with HOST,PASS format (multi-router mode)
--list FILES         Path to client list file(s) (required). Multiple files can be comma-separated: file1.csv,file2.csv
--block              Block clients from the list
--unblock            Unblock clients from the list
--username USER      Router username (default: root, applies to all routers)
--password PASS      Router password (single router mode only, or use GLINET_PASSWORD env var)
--verify-ssl         Verify SSL certificates (default: False)
--verbose            Enable verbose output
```

## Examples

### Block all children's devices during homework time

```bash
# Create a homework-block.txt with children's device MACs
python3 glinet_block.py --list ../clients/client-list-games.csv --block
```

### Unblock devices after homework

```bash
python3 glinet_block.py --list ../clients/client-list-games.csv --unblock
```

## Troubleshooting

### "Failed to connect to router"
- Verify the router IP address is correct
- Check network connectivity: `ping ROUTER_IP`
- Ensure the router web interface is accessible
- Try using `--verbose` for more details

### "Authentication failed"
- Verify username and password
- Check if the router requires a different username
- Some routers may have API access disabled
- Try accessing the router web interface first

### "Client not found on router"
- This is a warning, not an error
- The script will still attempt to block/unblock the MAC address
- The device may be offline or not currently connected
- MAC addresses are case-insensitive and normalized automatically

## License

This project is provided as-is for personal use.

