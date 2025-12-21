# Client Lists

This directory contains CSV files with MAC addresses and client names for blocking/unblocking.

## Format

Each CSV file should follow this format:

```csv
MAC_ADDRESS,CLIENT_NAME
AA:BB:CC:DD:EE:FF,device-name-1
11:22:33:44:55:66,device-name-2
```

## MAC Address Format

MAC addresses can be in any format:
- With colons: `AA:BB:CC:DD:EE:FF`
- With dashes: `AA-BB-CC-DD-EE-FF`
- With spaces: `AA BB CC DD EE FF`
- No separators: `AABBCCDDEEFF`

The script will automatically normalize them.

## Example Files

See `*.example.csv` files for examples of how to structure your client lists.

## Security Note

**DO NOT commit your actual client list files to git!** They contain personal device information. Only commit example files.

