#!/usr/bin/env python3
"""
GL.iNet Client Blocking Web UI

A web interface for managing client blocking/unblocking on GL.iNet routers.
"""

import os
import sys
import csv
import logging
import time
import threading
import yaml
from datetime import timedelta
from functools import wraps
from typing import List, Dict, Tuple, Optional

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import requests
from authlib.integrations.flask_client import OAuth

# Import glinet_block from same directory
from glinet_block import (
    GLiNetRouter,
    AdGuardHomeClient,
    AdGuardViaRouter,
    parse_routers_file,
    parse_client_list,
    normalize_mac
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Trust X-Forwarded-Proto / X-Forwarded-Host headers set by Traefik (or any reverse proxy).
# Required so url_for() generates https:// URLs (needed for OIDC redirect URI) and so
# SESSION_COOKIE_SECURE is respected correctly.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

_secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key-in-production')
if _secret_key == 'change-this-secret-key-in-production':
    logging.getLogger(__name__).critical(
        "SECRET_KEY is set to the default placeholder — session cookies can be forged. "
        "Set a random SECRET_KEY in your .env file: "
        "python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key

# Session configuration
app.permanent_session_lifetime = timedelta(hours=4)
app.config['SESSION_COOKIE_SECURE'] = True   # only send cookie over HTTPS (Traefik handles TLS)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # already Flask default; explicit for clarity
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Active timed YouTube enables: {router_host: {'timer': threading.Timer, 'expires_at': float}}
youtube_timers: Dict[str, Dict] = {}


def _reblock_youtube_on_router(router_host: str, password: str, router_name: str) -> None:
    """Timer callback: re-block YouTube on a router after a temporary enable."""
    youtube_timers.pop(router_host, None)
    logger.info(f"YouTube timer expired: re-blocking on {router_name} ({router_host})")
    try:
        adguard, err = get_adguard_client(router_host, password, router_name)
        if err or not adguard:
            logger.error(f"YouTube timer: AdGuard connect failed on {router_name}: {err}")
            return
        try:
            current = adguard.get_blocked_services()
            if current is None:
                logger.error(f"YouTube timer: failed to get blocked services on {router_name}")
                return
            new_ids = list(set(current.get('ids', [])) | {'youtube'})
            adguard.update_blocked_services(new_ids, current.get('schedule'))
            logger.info(f"YouTube timer: re-blocked on {router_name}")
        finally:
            adguard.logout()
    except Exception as e:
        logger.error(f"YouTube timer: error on {router_name}: {e}", exc_info=True)

# Configuration - use config directory for mounted volumes
# Default to /config (when mounted) or fallback to local data directory for development
CONFIG_DIR = os.environ.get('CONFIG_DIR', '/config')
if not os.path.exists(CONFIG_DIR):
    # Fallback to local data directory for development
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG_DIR = os.path.join(BASE_DIR, 'data')

CONFIG_YAML = os.path.join(CONFIG_DIR, 'config.yaml')
MAPPING_FILE = os.path.join(CONFIG_DIR, 'mapping.csv')
ROUTERS_FILE = os.path.join(CONFIG_DIR, 'routers.csv')
CLIENTS_DIR = os.path.join(CONFIG_DIR, 'clients')
SERVICES_FILE = os.path.join(CONFIG_DIR, 'services.yml')

# Optional AdGuard Home credentials for YouTube block. On GL.iNet, AdGuard is proxied at
# http://router/control/; use router session (root + router password) via AdGuardViaRouter.
# Set ADGUARD_PASSWORD (and optionally ADGUARD_USERNAME) only if using direct host:3000 API.
ADGUARD_USERNAME = os.environ.get('ADGUARD_USERNAME', '').strip() or None
ADGUARD_PASSWORD = os.environ.get('ADGUARD_PASSWORD', '').strip() or None

# Default password (should be changed via environment variables)
DEFAULT_PASSWORD = os.environ.get('WEBUI_PASSWORD', 'admin')

# Store password hash (in production, use environment variable)
PASSWORD_HASH = os.environ.get('WEBUI_PASSWORD_HASH')
if not PASSWORD_HASH:
    # Generate hash from plain password if hash not provided
    PASSWORD_HASH = generate_password_hash(DEFAULT_PASSWORD)

# OIDC configuration (works with Authentik and any OpenID Connect provider)
OIDC_ENABLED = os.environ.get('OIDC_ENABLED', 'false').lower() in ('true', '1', 'yes')
OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID', '')
OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET', '')
# Full discovery URL, e.g. https://auth.example.com/application/o/<slug>/.well-known/openid-configuration
OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL', '')

oauth = None
if OIDC_ENABLED:
    if not all([OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_DISCOVERY_URL]):
        logger.warning("OIDC_ENABLED=true but OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, or OIDC_DISCOVERY_URL is missing — OIDC disabled")
        OIDC_ENABLED = False
    else:
        oauth = OAuth(app)
        oauth.register(
            name='authentik',
            client_id=OIDC_CLIENT_ID,
            client_secret=OIDC_CLIENT_SECRET,
            server_metadata_url=OIDC_DISCOVERY_URL,
            client_kwargs={'scope': 'openid email profile'},
        )
        logger.info("OIDC enabled (Authentik / OpenID Connect)")


def _load_config_yaml() -> Optional[Dict]:
    """Load config.yaml if present. Returns dict with routers, devices, services or None."""
    if not os.path.exists(CONFIG_YAML):
        return None
    try:
        with open(CONFIG_YAML, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else None
    except yaml.YAMLError as e:
        logger.error(f"YAML error in {CONFIG_YAML}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error reading {CONFIG_YAML}: {e}")
        return None


def get_routers_from_env() -> List[Tuple[str, str, str]]:
    """
    Get routers from (in order): env vars, config.yaml, routers.csv.
    Returns list of (host, password, name) tuples.
    """
    routers = []

    # 1) Try comma-separated env lists
    router_hosts = os.environ.get('ROUTER_HOSTS', '').strip()
    router_passes = os.environ.get('ROUTER_PASSES', '').strip()

    if router_hosts and router_passes:
        hosts = [h.strip() for h in router_hosts.split(',') if h.strip()]
        passes = [p.strip() for p in router_passes.split(',') if p.strip()]

        if len(hosts) == len(passes):
            for i, (host, password) in enumerate(zip(hosts, passes), 1):
                name = os.environ.get(f'ROUTER_NAME_{i}', '').strip() or host
                routers.append((host, password, name))
            logger.info(f"Loaded {len(routers)} router(s) from ROUTER_HOSTS/ROUTER_PASSES env vars")
            return routers
        logger.warning("ROUTER_HOSTS and ROUTER_PASSES have different lengths, ignoring")

    # 2) Try numbered env vars
    i = 1
    while True:
        host = os.environ.get(f'ROUTER_HOST_{i}', '').strip()
        password = os.environ.get(f'ROUTER_PASS_{i}', '').strip()

        if not host:
            break

        if password:
            name = os.environ.get(f'ROUTER_NAME_{i}', '').strip() or host
            routers.append((host, password, name))
            logger.info(f"Loaded router {i}: {name} ({host})")
        else:
            logger.warning(f"ROUTER_HOST_{i} set but ROUTER_PASS_{i} missing, skipping")

        i += 1

    if routers:
        logger.info(f"Loaded {len(routers)} router(s) from environment variables")
        return routers

    # 3) config.yaml
    cfg = _load_config_yaml()
    if cfg and isinstance(cfg.get('routers'), list):
        for r in cfg['routers']:
            if isinstance(r, dict) and r.get('host') and r.get('password'):
                host = str(r['host']).strip()
                password = str(r['password']).strip()
                name = (r.get('name') or host).strip() if r.get('name') else host
                routers.append((host, password, name))
        if routers:
            logger.info(f"Loaded {len(routers)} router(s) from {CONFIG_YAML}")
            return routers

    # 4) Fall back to routers.csv
    if os.path.exists(ROUTERS_FILE):
        try:
            router_list = parse_routers_file(ROUTERS_FILE)
            routers = [(host, password, host) for host, password in router_list]
            logger.info(f"Loaded {len(routers)} router(s) from {ROUTERS_FILE}")
            return routers
        except Exception as e:
            logger.error(f"Error reading routers.csv: {e}")

    logger.warning("No routers configured (no env vars, config.yaml, or routers.csv)")
    return []


def get_adguard_client(router_host: str, password: str, router_name: str):
    """
    Return an AdGuard client (HTTP only): try via router proxy first (root + router password),
    then direct AdGuard API if ADGUARD_PASSWORD is set.
    Returns (client, None) on success, (None, error_message) on failure.
    """
    # 1) Prefer router proxy: login to GL.iNet, then hit http://router/control/ (nginx proxies to AdGuard).
    try:
        router = GLiNetRouter(
            host=router_host,
            username="root",
            password=password,
            verify_ssl=False,
            verbose=False,
        )
        if router.login():
            via_router = AdGuardViaRouter(router, verbose=False)
            if via_router.login():
                return via_router, None
        logger.info("AdGuard via router proxy failed for %s, trying direct AdGuard API", router_name)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        pass
    except Exception as e:
        logger.info("AdGuard via router failed for %s: %s", router_name, e)
    # 2) Direct AdGuard HTTP API (host:3000) if credentials set
    adguard_password = ADGUARD_PASSWORD if ADGUARD_PASSWORD else None
    if adguard_password or ADGUARD_USERNAME:
        adguard = AdGuardHomeClient(
            host=router_host,
            password=adguard_password or password,
            verify_ssl=False,
            verbose=False,
            username=ADGUARD_USERNAME,
        )
        try:
            if adguard.login():
                return adguard, None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            pass
    return None, "Authentication failed (try router proxy with root + router password, or set ADGUARD_PASSWORD)"


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # Check if this is an API request
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            else:
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Main page - redirect to login if not authenticated."""
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        if check_password_hash(PASSWORD_HASH, password):
            session.permanent = True
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password', 'error')

    return render_template('login.html', oidc_enabled=OIDC_ENABLED)


@app.route('/oidc/login')
def oidc_login():
    """Redirect to the OIDC provider (Authentik)."""
    if not OIDC_ENABLED or oauth is None:
        return redirect(url_for('login'))
    redirect_uri = url_for('oidc_callback', _external=True)
    return oauth.authentik.authorize_redirect(redirect_uri)


@app.route('/oidc/callback')
def oidc_callback():
    """Handle the OIDC authorization callback."""
    if not OIDC_ENABLED or oauth is None:
        return redirect(url_for('login'))
    try:
        token = oauth.authentik.authorize_access_token()
        userinfo = token.get('userinfo') or oauth.authentik.userinfo()
        session.permanent = True
        session['logged_in'] = True
        session['oidc_user'] = {
            'sub': userinfo.get('sub', ''),
            'email': userinfo.get('email', ''),
            'name': userinfo.get('name') or userinfo.get('preferred_username', ''),
        }
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"OIDC callback error: {e}", exc_info=True)
        flash('OIDC login failed. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard."""
    return render_template('dashboard.html')


@app.route('/api/mapping')
@login_required
def get_mapping():
    """Get categories from config.yaml devices or legacy mapping.csv."""
    try:
        mapping = []
        cfg = _load_config_yaml()
        if cfg and isinstance(cfg.get('devices'), dict):
            for category, devices_dict in cfg['devices'].items():
                if category and isinstance(devices_dict, dict) and len(devices_dict) > 0:
                    mapping.append({
                        'category': category,
                        'filename': '',
                        'path': ''
                    })
            if mapping:
                return jsonify({'mapping': mapping})
        if os.path.exists(MAPPING_FILE):
            with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2 and row[0].strip() and row[1].strip():
                        category = row[0].strip()
                        filename = row[1].strip()
                        file_path = os.path.join(CLIENTS_DIR, filename)
                        if os.path.exists(file_path):
                            mapping.append({
                                'category': category,
                                'filename': filename,
                                'path': file_path
                            })
        return jsonify({'mapping': mapping})
    except Exception as e:
        logger.error(f"Error getting mapping: {e}")
        return jsonify({'error': str(e)}), 500


def _get_clients_list(category: str = 'all') -> List[Dict]:
    """Helper: get clients from a category or all. Uses config.yaml devices first, else legacy CSV."""
    clients = []
    cfg = _load_config_yaml()
    if cfg and isinstance(cfg.get('devices'), dict):
        for cat_name, devices_dict in cfg['devices'].items():
            if not cat_name or not isinstance(devices_dict, dict):
                continue
            if category != 'all' and cat_name != category:
                continue
            for device_name, device_data in devices_dict.items():
                if not isinstance(device_data, dict):
                    continue
                mac_raw = device_data.get('mac') or device_data.get('MAC_ADDRESS')
                if not mac_raw:
                    continue
                mac = normalize_mac(str(mac_raw).strip())
                if mac and len(mac.split(':')) == 6:
                    name = (device_data.get('name') or device_name or 'Unknown').strip()
                    clients.append({'mac': mac, 'name': name, 'category': cat_name})
        if clients:
            return clients
    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2 or not row[1].strip():
                    continue
                category_name = row[0].strip()
                if category != 'all' and category_name != category:
                    continue
                filename = row[1].strip()
                file_path = os.path.join(CLIENTS_DIR, filename)
                if not os.path.exists(file_path):
                    continue
                try:
                    client_list = parse_client_list(file_path)
                    for mac, name in client_list:
                        clients.append({'mac': mac, 'name': name, 'category': category_name})
                except Exception as e:
                    logger.error(f"Error parsing {file_path}: {e}")
    return clients


@app.route('/api/clients')
@login_required
def get_clients():
    """Get all clients from a specific category or all categories."""
    category = request.args.get('category', 'all')
    
    try:
        clients = _get_clients_list(category)
        return jsonify({'clients': clients})
    except Exception as e:
        logger.error(f"Error getting clients: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/routers')
@login_required
def get_routers():
    """Get list of routers."""
    try:
        routers = []
        router_list = get_routers_from_env()
        for host, password, name in router_list:
            routers.append({
                'host': host,
                'name': name,
                'password': '***'  # Don't expose password
            })
        return jsonify({'routers': routers})
    except Exception as e:
        logger.error(f"Error getting routers: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/block', methods=['POST'])
@login_required
def block_clients():
    """Block clients."""
    data = request.get_json()
    category = data.get('category', 'all')
    mac_addresses = data.get('macs', [])  # Optional: specific MACs
    router_selection = data.get('router', 'all')  # 'all' or router host/name
    
    try:
        # Get clients to block
        if mac_addresses:
            clients = [{'mac': mac, 'name': 'Unknown'} for mac in mac_addresses]
        else:
            # Get all clients from category
            clients = _get_clients_list(category)
        
        if not clients:
            logger.warning(f"No clients found for category: {category}")
            return jsonify({'error': 'No clients found'}), 400
        
        # Get routers
        all_routers = get_routers_from_env()
        if not all_routers:
            logger.error("No routers configured")
            return jsonify({'error': 'No routers configured'}), 400
        
        # Filter routers based on selection
        if router_selection == 'all':
            routers = all_routers
        else:
            # Find router by host or name
            routers = [r for r in all_routers if r[0] == router_selection or r[2] == router_selection]
            if not routers:
                return jsonify({'error': f'Router "{router_selection}" not found'}), 400
        
            logger.info(f"Blocking {len(clients)} client(s) in category '{category}' on {len(routers)} router(s)")
        
        results = []
        for router_host, password, router_name in routers:
            logger.info(f"Connecting to router: {router_host}")
            try:
                router = GLiNetRouter(
                    host=router_host,
                    username='root',
                    password=password,
                    verify_ssl=False,
                    verbose=False
                )
            except Exception as e:
                logger.error(f"Failed to initialize router connection to {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': f'Failed to connect: {str(e)}'
                })
                continue
            
            try:
                logger.info(f"Attempting login to router {router_name} ({router_host})...")
                login_result = router.login()
                if not login_result:
                    logger.error(f"Failed to authenticate with router {router_name} ({router_host}) - login() returned False")
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Authentication failed'
                    })
                    continue
                logger.info(f"Successfully logged in to router {router_name} ({router_host})")
            except requests.exceptions.Timeout as e:
                logger.error(f"Connection timeout to router {router_name} ({router_host}) after 15 seconds: {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out. Router may be unreachable or slow to respond.'
                })
                continue
            except TimeoutError as e:
                logger.error(f"Operation timeout to router {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out. Router may be unreachable or slow to respond.'
                })
                continue
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error to router {router_name} ({router_host}): {e}", exc_info=True)
                error_msg = str(e).lower()
                if 'timeout' in error_msg or 'timed out' in error_msg:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Request timed out. Router may be unreachable or slow to respond.'
                    })
                else:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Router unreachable. Please check if the router is online and accessible.'
                    })
                continue
            except Exception as e:
                error_str = str(e).lower()
                if 'timeout' in error_str or 'timed out' in error_str:
                    logger.error(f"Timeout error connecting to router {router_name} ({router_host}): {e}", exc_info=True)
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Request timed out. Router may be unreachable or slow to respond.'
                    })
                elif 'connection' in error_str or 'unreachable' in error_str:
                    logger.error(f"Connection error to router {router_name} ({router_host}): {e}", exc_info=True)
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Router unreachable. Please check if the router is online and accessible.'
                    })
                else:
                    logger.error(f"Unexpected error connecting to router {router_name} ({router_host}): {e}", exc_info=True)
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': f'Connection failed: {str(e)}'
                    })
                continue
            
            logger.info(f"Successfully authenticated with router {router_name} ({router_host})")
            router_results = []
            success_count = 0
            fail_count = 0
            
            try:
                for client in clients:
                    mac = client['mac']
                    name = client.get('name', 'Unknown')
                    
                    logger.info(f"Blocking {name} ({mac}) on {router_name}")
                    if router.block_client(mac):
                        logger.info(f"✓ Successfully blocked {name} ({mac}) on {router_name}")
                        router_results.append({
                            'mac': mac,
                            'name': name,
                            'success': True
                        })
                        success_count += 1
                    else:
                        logger.error(f"✗ Failed to block {name} ({mac}) on {router_name}")
                        router_results.append({
                            'mac': mac,
                            'name': name,
                            'success': False,
                            'error': 'Block failed'
                        })
                        fail_count += 1
            finally:
                try:
                    router.logout()
                except:
                    pass
            
            logger.info(f"Router {router_name}: {success_count} successful, {fail_count} failed")
            
            results.append({
                'router': router_host,
                'router_name': router_name,
                'success': True,
                'clients': router_results,
                'summary': {
                    'total': len(clients),
                    'success': success_count,
                    'failed': fail_count
                }
            })
        
        total_success = sum(r.get('summary', {}).get('success', 0) for r in results)
        total_failed = sum(r.get('summary', {}).get('failed', 0) for r in results)
        router_names = [r.get('router_name', r.get('router', 'Unknown')) for r in results if r.get('success')]
        logger.info(f"Block operation complete on {', '.join(router_names)}: {total_success} successful, {total_failed} failed")
        
        return jsonify({
            'results': results,
            'router_names': router_names
        })
    except Exception as e:
        logger.error(f"Error blocking clients: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/unblock', methods=['POST'])
@login_required
def unblock_clients():
    """Unblock clients."""
    data = request.get_json()
    category = data.get('category', 'all')
    mac_addresses = data.get('macs', [])  # Optional: specific MACs
    router_selection = data.get('router', 'all')  # 'all' or router host/name
    
    try:
        # Get clients to unblock
        if mac_addresses:
            clients = [{'mac': mac, 'name': 'Unknown'} for mac in mac_addresses]
        else:
            # Get all clients from category
            clients = _get_clients_list(category)
        
        if not clients:
            logger.warning(f"No clients found for category: {category}")
            return jsonify({'error': 'No clients found'}), 400
        
        # Get routers
        all_routers = get_routers_from_env()
        if not all_routers:
            logger.error("No routers configured")
            return jsonify({'error': 'No routers configured'}), 400
        
        # Filter routers based on selection
        if router_selection == 'all':
            routers = all_routers
        else:
            # Find router by host or name
            routers = [r for r in all_routers if r[0] == router_selection or r[2] == router_selection]
            if not routers:
                return jsonify({'error': f'Router "{router_selection}" not found'}), 400
        
        logger.info(f"Unblocking {len(clients)} client(s) in category '{category}' on {len(routers)} router(s)")
        
        results = []
        for router_host, password, router_name in routers:
            logger.info(f"Connecting to router: {router_host}")
            try:
                router = GLiNetRouter(
                    host=router_host,
                    username='root',
                    password=password,
                    verify_ssl=False,
                    verbose=False
                )
            except Exception as e:
                logger.error(f"Failed to initialize router connection to {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': f'Failed to connect: {str(e)}'
                })
                continue
            
            try:
                logger.info(f"Attempting login to router {router_name} ({router_host})...")
                login_result = router.login()
                if not login_result:
                    logger.error(f"Failed to authenticate with router {router_name} ({router_host}) - login() returned False")
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Authentication failed'
                    })
                    continue
                logger.info(f"Successfully logged in to router {router_name} ({router_host})")
            except requests.exceptions.Timeout as e:
                logger.error(f"Connection timeout to router {router_name} ({router_host}) after 15 seconds: {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out. Router may be unreachable or slow to respond.'
                })
                continue
            except TimeoutError as e:
                logger.error(f"Operation timeout to router {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out. Router may be unreachable or slow to respond.'
                })
                continue
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error to router {router_name} ({router_host}): {e}", exc_info=True)
                error_msg = str(e).lower()
                if 'timeout' in error_msg or 'timed out' in error_msg:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Request timed out. Router may be unreachable or slow to respond.'
                    })
                else:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Router unreachable. Please check if the router is online and accessible.'
                    })
                continue
            except Exception as e:
                error_str = str(e).lower()
                if 'timeout' in error_str or 'timed out' in error_str:
                    logger.error(f"Timeout error connecting to router {router_name} ({router_host}): {e}", exc_info=True)
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Request timed out. Router may be unreachable or slow to respond.'
                    })
                elif 'connection' in error_str or 'unreachable' in error_str:
                    logger.error(f"Connection error to router {router_name} ({router_host}): {e}", exc_info=True)
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Router unreachable. Please check if the router is online and accessible.'
                    })
                else:
                    logger.error(f"Unexpected error connecting to router {router_name} ({router_host}): {e}", exc_info=True)
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': f'Connection failed: {str(e)}'
                    })
                continue
            
            logger.info(f"Successfully authenticated with router {router_name} ({router_host})")
            router_results = []
            success_count = 0
            fail_count = 0
            
            try:
                for client in clients:
                    mac = client['mac']
                    name = client.get('name', 'Unknown')
                    
                    logger.info(f"Unblocking {name} ({mac}) on {router_name}")
                    if router.unblock_client(mac):
                        logger.info(f"✓ Successfully unblocked {name} ({mac}) on {router_name}")
                        router_results.append({
                            'mac': mac,
                            'name': name,
                            'success': True
                        })
                        success_count += 1
                    else:
                        logger.error(f"✗ Failed to unblock {name} ({mac}) on {router_name}")
                        router_results.append({
                            'mac': mac,
                            'name': name,
                            'success': False,
                            'error': 'Unblock failed'
                        })
                        fail_count += 1
            finally:
                try:
                    router.logout()
                except:
                    pass
            
            logger.info(f"Router {router_name}: {success_count} successful, {fail_count} failed")
            
            results.append({
                'router': router_host,
                'router_name': router_name,
                'success': True,
                'clients': router_results,
                'summary': {
                    'total': len(clients),
                    'success': success_count,
                    'failed': fail_count
                }
            })
        
        total_success = sum(r.get('summary', {}).get('success', 0) for r in results)
        total_failed = sum(r.get('summary', {}).get('failed', 0) for r in results)
        router_names = [r.get('router_name', r.get('router', 'Unknown')) for r in results if r.get('success')]
        logger.info(f"Unblock operation complete on {', '.join(router_names)}: {total_success} successful, {total_failed} failed")
        
        return jsonify({
            'results': results,
            'router_names': router_names
        })
    except Exception as e:
        logger.error(f"Error unblocking clients: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def _load_services() -> List[str]:
    """Load available services from config.yaml or services.yml."""
    services = []
    cfg = _load_config_yaml()
    if cfg and isinstance(cfg.get('services'), list):
        services = [str(s).strip() for s in cfg['services'] if s]
        if services:
            logger.info(f"Loaded {len(services)} services from {CONFIG_YAML}")
            return services
    if os.path.exists(SERVICES_FILE):
        try:
            with open(SERVICES_FILE, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and 'services' in data:
                    svc = data['services']
                    if isinstance(svc, list):
                        services = [str(s).strip() for s in svc if s]
                        logger.info(f"Loaded {len(services)} services from {SERVICES_FILE}")
                        return services
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {SERVICES_FILE}: {e}")
        except Exception as e:
            logger.error(f"Error loading services.yml: {e}", exc_info=True)
    return services


def _get_service_display_name(service_id: str) -> str:
    """Convert service ID to human-readable name."""
    # Convert snake_case to Title Case
    return service_id.replace('_', ' ').title()


@app.route('/api/services')
@login_required
def get_services():
    """Get list of available services."""
    try:
        services = _load_services()
        if not services:
            logger.warning(f"No services loaded. File exists: {os.path.exists(SERVICES_FILE)}, Path: {SERVICES_FILE}")
        services_list = [{'id': svc, 'name': _get_service_display_name(svc)} for svc in services]
        return jsonify({'services': services_list})
    except Exception as e:
        logger.error(f"Error getting services: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/status')
@login_required
def get_services_status():
    """Get current blocked services status for selected router(s)."""
    router_selection = request.args.get('router', 'all')
    
    try:
        all_routers = get_routers_from_env()
        if not all_routers:
            logger.error("No routers configured")
            return jsonify({'error': 'No routers configured'}), 400
        
        # Filter routers based on selection
        if router_selection == 'all':
            routers = all_routers
        else:
            routers = [r for r in all_routers if r[0] == router_selection or r[2] == router_selection]
            if not routers:
                return jsonify({'error': f'Router "{router_selection}" not found'}), 400
        
        results = []
        for router_host, password, router_name in routers:
            logger.info(f"Getting service status from AdGuard Home on {router_name} ({router_host})")
            try:
                adguard, err = get_adguard_client(router_host, password, router_name)
                if err or not adguard:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': err or 'Authentication failed'
                    })
                    continue
                try:
                    blocked_services = adguard.get_blocked_services()
                    if blocked_services is None:
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': False,
                            'error': 'Failed to get blocked services'
                        })
                    else:
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': True,
                            'blocked_services': blocked_services.get('ids', []),
                            'schedule': blocked_services.get('schedule', {})
                        })
                finally:
                    adguard.logout()
                    
            except requests.exceptions.Timeout:
                logger.error(f"Timeout connecting to AdGuard Home on {router_name} ({router_host})")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out'
                })
            except requests.exceptions.ConnectionError:
                logger.error(f"Connection error to AdGuard Home on {router_name} ({router_host})")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Router unreachable'
                })
            except Exception as e:
                logger.error(f"Error getting service status from {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': str(e)
                })
        
        # If single router, return simplified response
        if len(routers) == 1:
            router_result = results[0] if results else None
            if router_result and router_result.get('success'):
                return jsonify({
                    'blocked_services': router_result.get('blocked_services', []),
                    'schedule': router_result.get('schedule', {}),
                    'router': router_result.get('router'),
                    'router_name': router_result.get('router_name')
                })
            else:
                # Single router but failed
                return jsonify({
                    'error': router_result.get('error', 'Failed to get service status') if router_result else 'No router result',
                    'blocked_services': [],
                    'schedule': {}
                }), 400
        
        # Multiple routers - return results array
        return jsonify({'results': results})
        
    except Exception as e:
        logger.error(f"Error getting services status: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/block', methods=['POST'])
@login_required
def block_service():
    """Block a service (or multiple services)."""
    data = request.get_json()
    service_ids = data.get('services', [])
    if not service_ids:
        # Support single service for backward compatibility
        service_id = data.get('service')
        if service_id:
            service_ids = [service_id]
    
    if not service_ids:
        return jsonify({'error': 'No services specified'}), 400
    
    router_selection = data.get('router', 'all')
    
    try:
        all_routers = get_routers_from_env()
        if not all_routers:
            logger.error("No routers configured")
            return jsonify({'error': 'No routers configured'}), 400
        
        # Filter routers based on selection
        if router_selection == 'all':
            routers = all_routers
        else:
            routers = [r for r in all_routers if r[0] == router_selection or r[2] == router_selection]
            if not routers:
                return jsonify({'error': f'Router "{router_selection}" not found'}), 400
        
        logger.info(f"Blocking {len(service_ids)} service(s) on {len(routers)} router(s)")
        
        results = []
        for router_host, password, router_name in routers:
            logger.info(f"Connecting to AdGuard Home on {router_name} ({router_host})")
            try:
                adguard, err = get_adguard_client(router_host, password, router_name)
                if err or not adguard:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': err or 'Authentication failed'
                    })
                    continue
                try:
                    # Get current blocked services
                    current = adguard.get_blocked_services()
                    if current is None:
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': False,
                            'error': 'Failed to get current blocked services'
                        })
                        continue
                    
                    # Add new services to existing list
                    current_ids = set(current.get('ids', []))
                    new_ids = list(current_ids | set(service_ids))
                    schedule = current.get('schedule')
                    
                    if adguard.update_blocked_services(new_ids, schedule):
                        # Cancel any timed YouTube enable when manually blocking
                        if 'youtube' in service_ids and router_host in youtube_timers:
                            youtube_timers[router_host]['timer'].cancel()
                            youtube_timers.pop(router_host, None)
                            logger.info(f"Cancelled YouTube timer for {router_name} (manual block)")
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': True,
                            'blocked_services': new_ids
                        })
                        logger.info(f"Successfully blocked services on {router_name}")
                    else:
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': False,
                            'error': 'Failed to update blocked services'
                        })
                finally:
                    adguard.logout()

            except requests.exceptions.Timeout:
                logger.error(f"Timeout connecting to AdGuard Home on {router_name} ({router_host})")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out'
                })
            except requests.exceptions.ConnectionError:
                logger.error(f"Connection error to AdGuard Home on {router_name} ({router_host})")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Router unreachable'
                })
            except Exception as e:
                logger.error(f"Error blocking services on {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': str(e)
                })

        router_names = [r.get('router_name', r.get('router', 'Unknown')) for r in results if r.get('success')]
        logger.info(f"Block service operation complete on {', '.join(router_names) if router_names else 'no routers'}")
        
        return jsonify({
            'results': results,
            'router_names': router_names
        })
        
    except Exception as e:
        logger.error(f"Error blocking services: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/unblock', methods=['POST'])
@login_required
def unblock_service():
    """Unblock a service (or multiple services)."""
    data = request.get_json()
    service_ids = data.get('services', [])
    if not service_ids:
        # Support single service for backward compatibility
        service_id = data.get('service')
        if service_id:
            service_ids = [service_id]
    
    if not service_ids:
        return jsonify({'error': 'No services specified'}), 400
    
    router_selection = data.get('router', 'all')
    
    try:
        all_routers = get_routers_from_env()
        if not all_routers:
            logger.error("No routers configured")
            return jsonify({'error': 'No routers configured'}), 400
        
        # Filter routers based on selection
        if router_selection == 'all':
            routers = all_routers
        else:
            routers = [r for r in all_routers if r[0] == router_selection or r[2] == router_selection]
            if not routers:
                return jsonify({'error': f'Router "{router_selection}" not found'}), 400
        
        logger.info(f"Unblocking {len(service_ids)} service(s) on {len(routers)} router(s)")
        
        results = []
        for router_host, password, router_name in routers:
            logger.info(f"Connecting to AdGuard Home on {router_name} ({router_host})")
            try:
                adguard, err = get_adguard_client(router_host, password, router_name)
                if err or not adguard:
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': err or 'Authentication failed'
                    })
                    continue
                try:
                    # Get current blocked services
                    current = adguard.get_blocked_services()
                    if current is None:
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': False,
                            'error': 'Failed to get current blocked services'
                        })
                        continue
                    
                    # Remove services from existing list
                    current_ids = set(current.get('ids', []))
                    new_ids = [sid for sid in current_ids if sid not in service_ids]
                    schedule = current.get('schedule')
                    
                    if adguard.update_blocked_services(new_ids, schedule):
                        # Cancel any timed YouTube enable when manually enabling permanently
                        if 'youtube' in service_ids and router_host in youtube_timers:
                            youtube_timers[router_host]['timer'].cancel()
                            youtube_timers.pop(router_host, None)
                            logger.info(f"Cancelled YouTube timer for {router_name} (manual permanent enable)")
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': True,
                            'blocked_services': new_ids
                        })
                        logger.info(f"Successfully unblocked services on {router_name}")
                    else:
                        results.append({
                            'router': router_host,
                            'router_name': router_name,
                            'success': False,
                            'error': 'Failed to update blocked services'
                        })
                finally:
                    adguard.logout()
                    
            except requests.exceptions.Timeout:
                logger.error(f"Timeout connecting to AdGuard Home on {router_name} ({router_host})")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out'
                })
            except requests.exceptions.ConnectionError:
                logger.error(f"Connection error to AdGuard Home on {router_name} ({router_host})")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Router unreachable'
                })
            except Exception as e:
                logger.error(f"Error unblocking services on {router_name} ({router_host}): {e}", exc_info=True)
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': str(e)
                })
        
        router_names = [r.get('router_name', r.get('router', 'Unknown')) for r in results if r.get('success')]
        logger.info(f"Unblock service operation complete on {', '.join(router_names) if router_names else 'no routers'}")
        
        return jsonify({
            'results': results,
            'router_names': router_names
        })
        
    except Exception as e:
        logger.error(f"Error unblocking services: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/youtube-timer', methods=['POST'])
@login_required
def youtube_timer_enable():
    """Temporarily enable YouTube for the given number of minutes, then re-block."""
    data = request.get_json()
    minutes = data.get('minutes')
    if minutes not in (30, 60):
        return jsonify({'error': 'minutes must be 30 or 60'}), 400

    router_selection = data.get('router', 'all')

    try:
        all_routers = get_routers_from_env()
        if not all_routers:
            return jsonify({'error': 'No routers configured'}), 400

        if router_selection == 'all':
            routers = all_routers
        else:
            routers = [r for r in all_routers if r[0] == router_selection or r[2] == router_selection]
            if not routers:
                return jsonify({'error': f'Router "{router_selection}" not found'}), 400

        delay = minutes * 60
        expires_at = time.time() + delay
        results = []

        for router_host, password, router_name in routers:
            try:
                adguard, err = get_adguard_client(router_host, password, router_name)
                if err or not adguard:
                    results.append({'router': router_host, 'router_name': router_name, 'success': False, 'error': err or 'Authentication failed'})
                    continue
                try:
                    current = adguard.get_blocked_services()
                    if current is None:
                        results.append({'router': router_host, 'router_name': router_name, 'success': False, 'error': 'Failed to get current blocked services'})
                        continue
                    new_ids = [sid for sid in current.get('ids', []) if sid != 'youtube']
                    if adguard.update_blocked_services(new_ids, current.get('schedule')):
                        # Cancel any existing timer before starting a new one
                        if router_host in youtube_timers:
                            youtube_timers[router_host]['timer'].cancel()
                        timer = threading.Timer(delay, _reblock_youtube_on_router, args=[router_host, password, router_name])
                        timer.daemon = True
                        timer.start()
                        youtube_timers[router_host] = {'timer': timer, 'expires_at': expires_at}
                        results.append({'router': router_host, 'router_name': router_name, 'success': True, 'expires_at': expires_at})
                        logger.info(f"YouTube enabled for {minutes}m on {router_name}, timer set")
                    else:
                        results.append({'router': router_host, 'router_name': router_name, 'success': False, 'error': 'Failed to update blocked services'})
                finally:
                    adguard.logout()
            except requests.exceptions.Timeout:
                results.append({'router': router_host, 'router_name': router_name, 'success': False, 'error': 'Request timed out'})
            except requests.exceptions.ConnectionError:
                results.append({'router': router_host, 'router_name': router_name, 'success': False, 'error': 'Router unreachable'})
            except Exception as e:
                logger.error(f"Error in youtube_timer_enable on {router_name}: {e}", exc_info=True)
                results.append({'router': router_host, 'router_name': router_name, 'success': False, 'error': str(e)})

        return jsonify({'results': results})

    except Exception as e:
        logger.error(f"Error in youtube_timer_enable: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/youtube-timer/status', methods=['GET'])
@login_required
def youtube_timer_status():
    """Return active YouTube timers with seconds remaining."""
    now = time.time()
    timers = {}
    for router_host, info in list(youtube_timers.items()):
        remaining = max(0, info['expires_at'] - now)
        timers[router_host] = {
            'expires_at': info['expires_at'],
            'remaining_seconds': int(remaining)
        }
    return jsonify({'timers': timers})


if __name__ == '__main__':
    # Create config directories if they don't exist (for development). Skip when config is read-only (e.g. Docker :ro).
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.makedirs(CLIENTS_DIR, exist_ok=True)
    except OSError as e:
        if e.errno != 30:  # 30 = read-only file system
            raise
        logger.info("Config directory is read-only; using config.yaml only (clients in config, not clients/)")

    # Log startup info
    routers = get_routers_from_env()
    logger.info(f"Starting GL.iNet Client Block Web UI")
    logger.info(f"Configured routers: {len(routers)}")
    for i, (host, _, name) in enumerate(routers, 1):
        logger.info(f"  Router {i}: {name} ({host})")
    
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=False)

