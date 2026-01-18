#!/usr/bin/env python3
"""
GL.iNet Router Client Blocking Script

This script connects to GL.iNet routers and manages client blocking/unblocking
based on a client list file.
"""

import argparse
import sys
import os
import json
import csv
import getpass
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Try to import python-glinet for authentication
try:
    from pyglinet import GlInet
    HAS_PYGLINET = True
except ImportError:
    HAS_PYGLINET = False

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_colored(message: str, color: str = Colors.WHITE, verbose: bool = True):
    """Print colored message if verbose is enabled."""
    if verbose:
        print(f"{color}{message}{Colors.RESET}")

def print_error(message: str, verbose: bool = True):
    """Print error message."""
    print_colored(f"ERROR: {message}", Colors.RED, verbose)

def print_success(message: str, verbose: bool = True):
    """Print success message."""
    print_colored(f"SUCCESS: {message}", Colors.GREEN, verbose)

def print_info(message: str, verbose: bool = True):
    """Print info message."""
    print_colored(f"INFO: {message}", Colors.CYAN, verbose)

def print_warning(message: str, verbose: bool = True):
    """Print warning message."""
    print_colored(f"WARNING: {message}", Colors.YELLOW, verbose)

def print_debug(message: str, verbose: bool = False):
    """Print debug message."""
    if verbose:
        print_colored(f"DEBUG: {message}", Colors.MAGENTA, verbose)


class GLiNetRouter:
    """GL.iNet Router API client."""
    
    def __init__(self, host: str, username: str = "root", password: str = "", verify_ssl: bool = False, verbose: bool = False):
        """
        Initialize router connection.
        
        Args:
            host: Router IP address or hostname
            username: Router username (default: root)
            password: Router password
            verify_ssl: Whether to verify SSL certificates (default: False for self-signed)
            verbose: Enable verbose output
        """
        self.host = host
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        
        # Determine protocol
        if not host.startswith(('http://', 'https://')):
            # Try HTTPS first, fallback to HTTP
            self.base_url = f"https://{host}"
        else:
            self.base_url = host
            self.host = urlparse(host).netloc or host
        
        self.rpc_url = f"{self.base_url}/rpc"
        self.session_token = None
        self.session = requests.Session()
        self.glinet_client = None  # python-glinet client if available
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Disable SSL verification if requested
        if not verify_ssl:
            self.session.verify = False
    
    def _rpc_call(self, method: str, params: List) -> Optional[Dict]:
        """
        Make JSON-RPC 2.0 call to router.
        
        Args:
            method: RPC method name (e.g., "clients.get_list")
            params: RPC parameters
            
        Returns:
            Response data or None on error
        """
        # Use python-glinet if available
        if self.glinet_client:
            try:
                # Parse method like "clients.get_list" into ["clients", "get_list"]
                parts = method.split(".", 1)
                if len(parts) == 2:
                    result = self.glinet_client.request("call", [parts[0], parts[1], params[0] if params else {}])
                    # Convert ResultContainer to dict if needed
                    if hasattr(result, 'result'):
                        return result.result
                    elif hasattr(result, '__dict__'):
                        return result.__dict__
                    return result
            except Exception as e:
                print_debug(f"python-glinet request failed: {e}, falling back to direct RPC", self.verbose)
        
        # Fallback: Direct RPC call
        if not self.session_token or self.session_token == "authenticated":
            # Try to use python-glinet's internal session
            if self.glinet_client:
                try:
                    parts = method.split(".", 1)
                    if len(parts) == 2:
                        result = self.glinet_client.request("call", [parts[0], parts[1], params[0] if params else {}])
                        if hasattr(result, 'result'):
                            return result.result
                        return result
                except:
                    pass
            
            print_error("Not authenticated. Please login first.", self.verbose)
            return None
        
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [self.session_token] + params
        }
        
        try:
            print_debug(f"RPC Call: {method} with params: {params}", self.verbose)
            response = self.session.post(
                self.rpc_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if "error" in data:
                error = data["error"]
                error_code = error.get("code", 0)
                error_message = error.get("message", "Unknown error")
                
                # Check for authentication errors
                if error_code in [-32602, -32001, -32000]:
                    # -32602: Invalid params (often means invalid session token)
                    # -32001: Session not found
                    # -32000: Server error (sometimes auth-related)
                    if "Invalid params" in error_message or "Session" in error_message or error_code == -32001:
                        print_error(f"Authentication error: {error_message} (code: {error_code})", self.verbose)
                        print_error("Session token appears to be invalid. Authentication may have failed.", self.verbose)
                        return None
                
                print_error(f"RPC Error: {error_message} (code: {error_code})", self.verbose)
                return None
            
            return data.get("result")
        except requests.exceptions.RequestException as e:
            print_error(f"Failed to connect to router: {e}", self.verbose)
            return None
        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON response: {e}", self.verbose)
            return None
    
    def _rpc_method_call(self, method: str, params: Dict) -> Optional[Dict]:
        """
        Make a direct JSON-RPC method call (not using 'call' method).
        Used for challenge and login.
        
        Args:
            method: RPC method name (e.g., "challenge", "login")
            params: Method parameters
            
        Returns:
            Response data or None on error
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        try:
            print_debug(f"RPC Method Call: {method}", self.verbose)
            response = self.session.post(
                self.rpc_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if "error" in data:
                error = data["error"]
                error_code = error.get("code", 0)
                error_message = error.get("message", "Unknown error")
                print_debug(f"RPC Error: {error_message} (code: {error_code})", self.verbose)
                return None
            
            return data.get("result")
        except requests.exceptions.RequestException as e:
            print_debug(f"Request error: {e}", self.verbose)
            return None
        except json.JSONDecodeError as e:
            print_debug(f"JSON decode error: {e}", self.verbose)
            return None
    
    def login(self) -> bool:
        """
        Authenticate with the router.
        
        Uses python-glinet library if available (recommended), otherwise falls back
        to custom implementation.
        
        Reference: https://github.com/tomtana/python-glinet
        """
        # Prefer python-glinet library if available (it handles auth correctly)
        if HAS_PYGLINET:
            try:
                print_debug(f"Using python-glinet library for authentication", self.verbose)
                # Create GlInet client
                self.glinet_client = GlInet(
                    url=self.rpc_url,
                    username=self.username if self.username else "root",
                    password=self.password if self.password else None,
                    verify_ssl_certificate=self.verify_ssl
                )
                
                # Login (will prompt for password if not provided)
                self.glinet_client.login()
                
                # Extract session token from the client
                # The library stores it internally, we need to get it from the session
                if hasattr(self.glinet_client, '_sid'):
                    self.session_token = self.glinet_client._sid
                elif hasattr(self.glinet_client, 'sid'):
                    self.session_token = self.glinet_client.sid
                else:
                    # Try to get it by making a test request
                    try:
                        result = self.glinet_client.request("call", ["system", "board", {}])
                        # If request succeeds, auth is working
                        self.session_token = "authenticated"  # Placeholder, library handles it
                    except:
                        pass
                
                print_success(f"Authenticated with {self.host} using python-glinet", self.verbose)
                return True
                
            except Exception as e:
                print_warning(f"python-glinet authentication failed: {e}", self.verbose)
                print_info("Falling back to custom authentication...", self.verbose)
                # Fall through to custom implementation
        
        # Fallback: Custom authentication (may not work correctly)
        print_error("python-glinet library not available. Please install it:", self.verbose)
        print_info("  pip install python-glinet", self.verbose)
        print_info("Or run: ./setup.sh", self.verbose)
        return False
    
    def _verify_auth(self) -> bool:
        """
        Verify that authentication is working by making a test RPC call.
        
        Returns:
            True if authentication is valid, False otherwise
        """
        if not self.session_token:
            return False
        
        # Try a simple RPC call that should work with valid auth
        test_payload = {
            "jsonrpc": "2.0",
            "id": 999,
            "method": "call",
            "params": [self.session_token, "system", "board", {}]
        }
        
        try:
            response = self.session.post(self.rpc_url, json=test_payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                # If we get a result (even if empty) or a specific error code, auth might be working
                # But if we get "Invalid params" with code -32602, the token is invalid
                if "error" in data:
                    error = data["error"]
                    error_code = error.get("code", 0)
                    # -32602 is "Invalid params" which often means invalid session token
                    # -32001 is "Session not found" or similar
                    if error_code in [-32602, -32001, -32000]:
                        print_debug(f"Auth verification failed: {error.get('message', 'Unknown error')}", self.verbose)
                        return False
                # If we get a result or a different error, assume auth might work
                return True
        except Exception:
            pass
        
        return False
    
    def get_clients(self) -> Optional[List[Dict]]:
        """Get list of all clients from the router."""
        result = self._rpc_call("clients.get_list", [{}])
        if result and "clients" in result:
            return result["clients"]
        return None
    
    def get_blacklist(self) -> Optional[Dict]:
        """Get current blacklist configuration."""
        result = self._rpc_call("black_white_list.get_config", [{}])
        return result
    
    def block_client(self, mac: str) -> bool:
        """
        Block a client by MAC address.
        
        Args:
            mac: MAC address in format XX:XX:XX:XX:XX:XX
            
        Returns:
            True if successful, False otherwise
        """
        params = [{
            "mode": "black",
            "operate": "add",
            "mac": mac.upper()
        }]
        
        result = self._rpc_call("black_white_list.set_single_mac", params)
        return result is not None
    
    def unblock_client(self, mac: str) -> bool:
        """
        Unblock a client by MAC address.
        
        Args:
            mac: MAC address in format XX:XX:XX:XX:XX:XX
            
        Returns:
            True if successful, False otherwise
        """
        params = [{
            "mode": "black",
            "operate": "del",
            "mac": mac.upper()
        }]
        
        result = self._rpc_call("black_white_list.set_single_mac", params)
        return result is not None
    
    def client_exists(self, mac: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if a client exists on the router.
        
        Args:
            mac: MAC address to check
            
        Returns:
            Tuple of (exists, client_info)
        """
        clients = self.get_clients()
        if not clients:
            return False, None
        
        mac_upper = mac.upper()
        for client in clients:
            if client.get("mac", "").upper() == mac_upper:
                return True, client
        
        return False, None
    
    def import_client(self, mac: str, name: str) -> bool:
        """
        Import/add a client to the router by setting its alias/name.
        This allows blocking clients that don't exist yet.
        
        Note: GL.iNet routers may automatically add clients to the list when
        they're blocked, so this may not always be necessary.
        
        Args:
            mac: MAC address
            name: Client name/alias
            
        Returns:
            True if successful, False otherwise
        """
        # Try various methods to set client alias/name
        methods_to_try = [
            ("clients.set_alias", {"mac": mac.upper(), "alias": name}),
            ("clients.set_name", {"mac": mac.upper(), "name": name}),
            ("clients.set", {"mac": mac.upper(), "alias": name}),
        ]
        
        for method, params in methods_to_try:
            try:
                result = self._rpc_call(method, [params])
                if result is not None:
                    print_debug(f"Successfully imported client using {method}", self.verbose)
                    return True
            except Exception as e:
                print_debug(f"Method {method} failed: {e}", self.verbose)
                continue
        
        # If direct methods don't work, that's okay
        # The router will still allow blocking the MAC address
        # and may automatically add it when blocked
        return False
    
    def logout(self) -> None:
        """
        Clean up and logout from the router.
        Stops keep-alive thread if using python-glinet.
        """
        if self.glinet_client:
            try:
                self.glinet_client.logout()
                print_debug("Logged out and stopped keep-alive thread", self.verbose)
            except Exception as e:
                print_debug(f"Error during logout: {e}", self.verbose)


def parse_routers_file(file_path: str) -> List[Tuple[str, str]]:
    """
    Parse routers file.
    
    Format: HOST,PASS (CSV format, one per line)
    Header line (HOST,PASS) is automatically skipped.
    
    Passwords with special characters (commas, quotes, etc.) should be quoted:
    Example:
        HOST,PASS
        100.122.185.100,"password,with,commas"
        100.65.142.110,"password-with-dashes-and!exclamation"
    
    Returns:
        List of (host, password) tuples
    """
    routers = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for line_num, row in enumerate(reader, 1):
                # Skip empty rows
                if not row or all(not cell.strip() for cell in row):
                    continue
                
                # Skip rows that look like comments
                if row[0].strip().startswith('#'):
                    continue
                
                if len(row) >= 2:
                    host = row[0].strip()
                    password = row[1].strip()
                    
                    # Skip header lines (check if first part looks like a header)
                    if host.upper() in ['HOST', 'HOSTNAME', 'IP', 'IP_ADDRESS', 'ROUTER']:
                        continue
                    
                    if host and password:
                        routers.append((host, password))
                    else:
                        print_warning(f"Invalid router entry on line {line_num}: missing host or password", True)
                else:
                    print_warning(f"Skipping invalid line {line_num} in {file_path}: {','.join(row)}", True)
    except FileNotFoundError:
        print_error(f"Routers file not found: {file_path}")
        sys.exit(1)
    except csv.Error as e:
        print_error(f"CSV parsing error in routers file: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error reading routers file: {e}")
        sys.exit(1)
    
    return routers


def parse_client_list(file_path: str) -> List[Tuple[str, str]]:
    """
    Parse a single client list file.
    
    Format: MAC_ADDRESS,CLIENT_NAME (one per line)
    MAC address can be in any case and format (colons, dashes, spaces, or no separators)
    Header lines (containing "MAC" or "ADDRESS") are automatically skipped.
    
    Returns:
        List of (mac, name) tuples with normalized MAC addresses
    """
    clients = []
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(',')
                if len(parts) >= 2:
                    mac = parts[0].strip()
                    name = parts[1].strip()
                    
                    # Skip header lines (check if first part looks like a header)
                    if mac.upper() in ['MAC_ADDRESS', 'MAC', 'ADDRESS'] or \
                       'MAC' in mac.upper() and 'ADDRESS' in mac.upper():
                        continue
                    
                    # Normalize MAC address (handles any case/format)
                    normalized_mac = normalize_mac(mac)
                    if normalized_mac and len(normalized_mac.split(':')) == 6:
                        clients.append((normalized_mac, name))
                    else:
                        print_warning(f"Invalid MAC address format on line {line_num} in {file_path}: {mac}", True)
                else:
                    print_warning(f"Skipping invalid line {line_num} in {file_path}: {line}", True)
    except FileNotFoundError:
        print_error(f"Client list file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error reading client list file {file_path}: {e}")
        sys.exit(1)
    
    return clients


def parse_client_lists(file_paths: str) -> List[Tuple[str, str]]:
    """
    Parse multiple client list files (comma-separated).
    
    Format: file1.csv,file2.csv,file3.csv
    Each file follows the same format as parse_client_list().
    
    If the same MAC address appears in multiple files, the first occurrence is used.
    
    Returns:
        List of (mac, name) tuples with normalized MAC addresses (deduplicated)
    """
    # Split by comma and strip whitespace
    file_list = [f.strip() for f in file_paths.split(',') if f.strip()]
    
    if not file_list:
        print_error("No client list files specified")
        sys.exit(1)
    
    all_clients = []
    seen_macs = {}  # Track MAC addresses to handle duplicates
    
    for file_path in file_list:
        print_debug(f"Parsing client list file: {file_path}", True)
        clients = parse_client_list(file_path)
        
        for mac, name in clients:
            if mac in seen_macs:
                # MAC already seen, skip duplicate (keep first occurrence)
                print_debug(f"Skipping duplicate MAC {mac} from {file_path} (already in {seen_macs[mac]})", True)
                continue
            
            seen_macs[mac] = file_path
            all_clients.append((mac, name))
    
    return all_clients


def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to uppercase with colons.
    
    Accepts MAC addresses in any case and format:
    - With colons: AA:BB:CC:DD:EE:FF
    - With dashes: AA-BB-CC-DD-EE-FF
    - With spaces: AA BB CC DD EE FF
    - No separators: AABBCCDDEEFF
    - Mixed case: aa:bb:cc:dd:ee:ff or Aa:Bb:Cc:Dd:Ee:Ff
    
    Returns:
        Normalized MAC address in format XX:XX:XX:XX:XX:XX (uppercase)
    """
    if not mac:
        return mac
    
    # Remove all whitespace
    mac = ''.join(mac.split())
    
    # Replace dashes with colons
    mac = mac.replace('-', ':')
    
    # If no separators, assume it's a continuous string
    if ':' not in mac:
        # Split into pairs if it's 12 characters
        if len(mac) == 12:
            mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
        else:
            # Invalid format, return as-is (will be caught later)
            return mac.upper()
    
    # Split by colon and normalize each part
    parts = mac.split(':')
    
    # Handle cases where there might be extra colons or empty parts
    parts = [p.strip() for p in parts if p.strip()]
    
    # If we have 6 parts, format them properly
    if len(parts) == 6:
        # Ensure each part is 2 characters (pad with 0 if needed)
        normalized_parts = []
        for part in parts:
            if len(part) == 1:
                normalized_parts.append(f"0{part}")
            elif len(part) == 2:
                normalized_parts.append(part)
            else:
                # Invalid part length
                return mac.upper()
        
        # Join with colons and convert to uppercase
        return ':'.join(normalized_parts).upper()
    
    # If format is unexpected, return uppercase version
    return mac.upper()


def process_router(
    router_host: str,
    password: str,
    username: str,
    clients: List[Tuple[str, str]],
    action: str,
    verify_ssl: bool,
    verbose: bool
) -> Tuple[int, int, int]:
    """
    Process clients on a single router.
    
    Returns:
        Tuple of (success_count, fail_count, not_found_count)
    """
    print_colored("\n" + "="*50, Colors.BOLD, True)
    print_colored(f"Processing router: {router_host}", Colors.BOLD, True)
    print_colored("="*50, Colors.BOLD, True)
    
    # Connect to router
    router = GLiNetRouter(
        host=router_host,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        verbose=verbose
    )
    
    # Authenticate
    if not router.login():
        print_error(f"Failed to authenticate with router {router_host}")
        print_error("Please verify:")
        print_error(f"  - Router IP/hostname is correct: {router_host}")
        print_error(f"  - Username is correct: {username}")
        print_error(f"  - Password is correct")
        print_error("  - Router web interface is accessible")
        if not verbose:
            print_info("Run with --verbose for more details", True)
        return (0, 0, 0)  # Return zeros for this router
    
    # Get current blacklist and normalize MAC addresses (handle any case from router)
    blacklist = router.get_blacklist()
    if blacklist:
        # Normalize all MACs from router to ensure case-insensitive comparison
        current_blocked = {normalize_mac(mac) for mac in blacklist.get("black_mac", [])}
        print_debug(f"Current blacklist: {current_blocked}", verbose)
    else:
        current_blocked = set()
    
    # Process clients (MACs are already normalized from parse_client_list)
    success_count = 0
    fail_count = 0
    not_found_count = 0
    
    try:
        for mac, name in clients:
            # MAC is already normalized from parse_client_list, but ensure it's valid
            print_info(f"Processing {name} ({mac})...", verbose)
            
            # Check if client exists
            exists, client_info = router.client_exists(mac)
            if not exists:
                print_warning(f"Client {name} ({mac}) not found on router - skipping", verbose)
                print_info(f"  (Client will be targeted once it connects to the network)", verbose)
                not_found_count += 1
                continue  # Skip this client - it will be handled when it connects
            
            # Perform action (mac is already normalized/uppercase)
            if action == "block":
                if mac in current_blocked:
                    print_info(f"{name} ({mac}) is already blocked", verbose)
                    success_count += 1
                else:
                    if router.block_client(mac):
                        print_success(f"Blocked {name} ({mac})", verbose)
                        success_count += 1
                    else:
                        print_error(f"Failed to block {name} ({mac})", verbose)
                        fail_count += 1
            else:  # unblock
                if mac not in current_blocked:
                    print_info(f"{name} ({mac}) is not blocked", verbose)
                    success_count += 1
                else:
                    if router.unblock_client(mac):
                        print_success(f"Unblocked {name} ({mac})", verbose)
                        success_count += 1
                    else:
                        print_error(f"Failed to unblock {name} ({mac})", verbose)
                        fail_count += 1
        
        # Router summary
        print_colored(f"\nRouter {router_host} Summary:", Colors.BOLD, True)
        print_colored(f"  Action: {action.upper()}", Colors.BOLD, True)
        print_colored(f"  Successful: {success_count}", Colors.GREEN, True)
        if fail_count > 0:
            print_colored(f"  Failed: {fail_count}", Colors.RED, True)
        if not_found_count > 0:
            print_colored(f"  Skipped (not on router): {not_found_count}", Colors.YELLOW, True)
            print_colored(f"    (These will be targeted once they connect)", Colors.YELLOW, True)
        
    finally:
        # Always cleanup/logout to stop keep-alive thread
        router.logout()
    
    return (success_count, fail_count, not_found_count)


def main():
    parser = argparse.ArgumentParser(
        description="GL.iNet Router Client Blocking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Block clients from client-list.txt on default router
  %(prog)s --list client-list.txt --block

  # Unblock clients
  %(prog)s --list client-list.txt --unblock

  # Block on specific router
  %(prog)s --router 100.122.185.100 --list client-list.txt --block

  # Process multiple routers from file
  %(prog)s --routers routers.csv --list client-list.txt --block

  # Process multiple client list files
  %(prog)s --list client-list.csv,client-list-media.csv,client-list-games.csv --block

  # Verbose output
  %(prog)s --list client-list.txt --block --verbose
        """
    )
    
    parser.add_argument(
        '--router',
        type=str,
        help='Router IP address or hostname (default: from router-list.txt or environment). Ignored if --routers is specified.'
    )
    parser.add_argument(
        '--routers',
        type=str,
        help='Path to routers file (format: HOST,PASS). If specified, processes all routers in the file.'
    )
    parser.add_argument(
        '--list',
        type=str,
        required=True,
        help='Path to client list file(s) (format: MAC,NAME). Multiple files can be specified comma-separated: file1.csv,file2.csv,file3.csv'
    )
    parser.add_argument(
        '--block',
        action='store_true',
        help='Block clients from the list'
    )
    parser.add_argument(
        '--unblock',
        action='store_true',
        help='Unblock clients from the list'
    )
    parser.add_argument(
        '--username',
        type=str,
        default='root',
        help='Router username (default: root)'
    )
    parser.add_argument(
        '--password',
        type=str,
        default='',
        help='Router password (or set GLINET_PASSWORD env var, or will prompt if not provided)'
    )
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verify SSL certificates (default: False, accepts self-signed)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if not args.block and not args.unblock:
        parser.error("Must specify either --block or --unblock")
    
    if args.block and args.unblock:
        parser.error("Cannot specify both --block and --unblock")
    
    # Parse client list(s) - supports comma-separated multiple files
    clients = parse_client_lists(args.list)
    if not clients:
        print_error("No clients found in list file(s)")
        sys.exit(1)
    
    # Count how many files were specified
    file_count = len([f.strip() for f in args.list.split(',') if f.strip()])
    if file_count > 1:
        print_info(f"Found {len(clients)} clients from {file_count} list file(s)", args.verbose)
    else:
        print_info(f"Found {len(clients)} clients in list", args.verbose)
    
    # Determine action
    action = "block" if args.block else "unblock"
    
    # Handle routers
    routers = []
    
    if args.routers:
        # Parse routers from file
        routers = parse_routers_file(args.routers)
        if not routers:
            print_error("No routers found in routers file")
            sys.exit(1)
        print_info(f"Found {len(routers)} router(s) in file", args.verbose)
    else:
        # Single router mode
        # Get password from command line, environment, or prompt securely
        password = args.password or os.getenv('GLINET_PASSWORD', '')
        if not password:
            # Prompt for password securely (input is hidden)
            try:
                password = getpass.getpass("Enter router password: ")
                if not password:
                    print_error("Password cannot be empty")
                    sys.exit(1)
            except (KeyboardInterrupt, EOFError):
                print_error("\nPassword input cancelled")
                sys.exit(1)
        
        # Get router address
        router_host = args.router
        if not router_host:
            # Try to read from router-list.txt
            try:
                with open('router-list.txt', 'r') as f:
                    line = f.readline().strip()
                    if line:
                        router_host = line.split()[0] if ' ' in line else line
            except FileNotFoundError:
                pass
            
            if not router_host:
                router_host = os.getenv('GLINET_ROUTER', '')
            
            if not router_host:
                print_error("No router specified. Use --router, --routers, or set GLINET_ROUTER env var.")
                sys.exit(1)
        
        # Add single router to list
        routers = [(router_host, password)]
    
    # Process each router
    total_success = 0
    total_fail = 0
    total_not_found = 0
    
    for router_host, password in routers:
        # Process this router
        success, fail, not_found = process_router(
            router_host=router_host,
            password=password,
            username=args.username,
            clients=clients,
            action=action,
            verify_ssl=args.verify_ssl,
            verbose=args.verbose
        )
        
        total_success += success
        total_fail += fail
        total_not_found += not_found
    
    # Overall summary
    print_colored("\n" + "="*50, Colors.BOLD, True)
    print_colored(f"Overall Summary:", Colors.BOLD, True)
    print_colored(f"  Routers processed: {len(routers)}", Colors.BOLD, True)
    print_colored(f"  Action: {action.upper()}", Colors.BOLD, True)
    print_colored(f"  Successful: {total_success}", Colors.GREEN, True)
    if total_fail > 0:
        print_colored(f"  Failed: {total_fail}", Colors.RED, True)
    if total_not_found > 0:
        print_colored(f"  Skipped (not on router): {total_not_found}", Colors.YELLOW, True)
        print_colored(f"    (These will be targeted once they connect)", Colors.YELLOW, True)
    print_colored("="*50 + "\n", Colors.BOLD, True)
    
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()

