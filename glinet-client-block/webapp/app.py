#!/usr/bin/env python3
"""
GL.iNet Client Blocking Web UI

A web interface for managing client blocking/unblocking on GL.iNet routers.
"""

import os
import sys
import csv
import json
import fcntl
import logging
import time
import threading
import yaml
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
from typing import List, Dict, Tuple, Optional

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import requests
from authlib.integrations.flask_client import OAuth
# authlib 1.3+ uses joserfc; RSA algorithms (RS256) must be explicitly imported
# to register them in joserfc's JWS registry before any JWT verification occurs
try:
    import joserfc.rfc7518  # noqa: F401
except ImportError:
    pass

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

APP_VERSION = "1.12"
APP_VERSION_DATE = "2026-07-18"

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

@app.context_processor
def inject_version():
    return {"app_version": APP_VERSION, "app_version_date": APP_VERSION_DATE}

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

# Writable data directory for schedule config + runtime state. The /config mount is read-only,
# so recurring schedules (which are edited from the UI) live here instead.
# Default to /data (mount a writable volume there) or fall back to webapp/data for local dev.
DATA_DIR = os.environ.get('DATA_DIR', '/data')
if not os.path.isdir(DATA_DIR):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError:
        # e.g. /data not mounted and not creatable -> fall back to a local dev directory
        DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except OSError:
            pass

SCHEDULES_FILE = os.path.join(DATA_DIR, 'schedules.json')
SCHEDULE_STATE_FILE = os.path.join(DATA_DIR, 'schedule_state.json')
SCHEDULER_LOCK_FILE = os.path.join(DATA_DIR, 'scheduler.lock')
# How often the reconcile loop wakes up (seconds); schedule boundaries are enforced within one tick.
RECONCILE_INTERVAL = int(os.environ.get('SCHEDULE_INTERVAL', '30'))
# Day tokens indexed to match datetime.weekday() (Monday == 0).
DAY_TOKENS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

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


# ---------------------------------------------------------------------------
# Scheduled service blocking
# ---------------------------------------------------------------------------
# Schedules are stored per router -> per service as a list of weekly windows. A window
# blocks the service on the given weekdays between `start` and `end` (HH:MM, service-local
# time). A window whose `end` is <= `start` wraps past midnight and is treated as belonging
# to its start day (e.g. Fri 14:00->04:00 blocks Fri afternoon through Sat 04:00).
#
# A background reconcile loop (single worker, guarded by an flock) applies changes only at
# window boundaries, so a manual block/unblock between boundaries sticks until the next
# scheduled transition.


def _load_json(path: str, default):
    """Load JSON from path, returning `default` on any error/absence."""
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error reading {path}: {e}")
    return default


def _save_json(path: str, data) -> None:
    """Atomically write JSON to path (temp file + os.replace)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _load_schedules() -> Dict:
    """Load the schedules document, normalising to {'version', 'routers': {...}}."""
    data = _load_json(SCHEDULES_FILE, None)
    if not isinstance(data, dict):
        data = {}
    if not isinstance(data.get('routers'), dict):
        data['routers'] = {}
    data.setdefault('version', 1)
    return data


def _parse_hhmm(value) -> Optional[int]:
    """Parse 'HH:MM' into minutes-of-day (0..1439), or None if invalid."""
    if not isinstance(value, str):
        return None
    try:
        hh, mm = value.split(':')
        h, m = int(hh), int(mm)
    except (ValueError, AttributeError):
        return None
    if 0 <= h <= 23 and 0 <= m <= 59:
        return h * 60 + m
    return None


def _service_now(sched: Dict) -> datetime:
    """Current time in the schedule's timezone (defaults to Asia/Tokyo)."""
    tz = (sched or {}).get('timezone') or 'Asia/Tokyo'
    try:
        return datetime.now(ZoneInfo(tz))
    except Exception:
        return datetime.now(ZoneInfo('Asia/Tokyo'))


def _window_active(window: Dict, now: datetime) -> bool:
    """True if `now` falls inside this weekly window (handles wrap past midnight)."""
    if not isinstance(window, dict):
        return False
    days = window.get('days') or []
    start = _parse_hhmm(window.get('start'))
    end = _parse_hhmm(window.get('end'))
    if start is None or end is None or not days:
        return False
    today = DAY_TOKENS[now.weekday()]
    prev = DAY_TOKENS[(now.weekday() - 1) % 7]
    mod = now.hour * 60 + now.minute
    if end > start:
        return today in days and start <= mod < end
    if end < start:
        # Wraps past midnight; the window belongs to its start day.
        return (today in days and mod >= start) or (prev in days and mod < end)
    # start == end: zero-length window, treated as inactive (use 00:00-23:59 for all day).
    return False


def _service_should_block(sched: Dict, now: datetime) -> bool:
    """True if any enabled window of this schedule is active at `now`."""
    if not sched or not sched.get('enabled'):
        return False
    for window in sched.get('windows') or []:
        if _window_active(window, now):
            return True
    return False


def _next_transition(sched: Dict, now: datetime) -> Optional[str]:
    """ISO timestamp of the next time the block state flips within a week, or None."""
    if not sched or not sched.get('enabled'):
        return None
    current = _service_should_block(sched, now)
    probe = now.replace(second=0, microsecond=0)
    for _ in range(7 * 24 * 60):
        probe = probe + timedelta(minutes=1)
        if _service_should_block(sched, probe) != current:
            return probe.isoformat()
    return None


def _reconcile_schedules() -> None:
    """Apply scheduled block/unblock transitions across all routers.

    Only acts when a service's desired state differs from the last state the scheduler
    recorded, so manual overrides between boundaries are left untouched. Never contacts a
    router unless at least one of its services is transitioning.
    """
    schedules = _load_schedules()
    routers_cfg = schedules.get('routers') or {}
    if not routers_cfg:
        return

    state = _load_json(SCHEDULE_STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    router_creds = {host: (pw, name) for host, pw, name in get_routers_from_env()}
    state_changed = False

    for host, svc_map in routers_cfg.items():
        if not isinstance(svc_map, dict):
            continue

        to_block, to_unblock, pending = set(), set(), {}
        for service, sched in svc_map.items():
            if not isinstance(sched, dict) or not sched.get('enabled'):
                continue
            desired = _service_should_block(sched, _service_now(sched))
            last = state.get(f"{host}|{service}")
            last_bool = {'blocked': True, 'unblocked': False}.get(last)
            if last_bool is None or desired != last_bool:
                pending[service] = desired
                (to_block if desired else to_unblock).add(service)

        if not pending:
            continue

        creds = router_creds.get(host)
        if not creds:
            logger.warning(f"Scheduler: router {host} has schedules but is not configured; skipping")
            continue
        password, name = creds

        try:
            adguard, err = get_adguard_client(host, password, name)
            if err or not adguard:
                logger.error(f"Scheduler: AdGuard connect failed on {name} ({host}): {err}")
                continue
            try:
                current = adguard.get_blocked_services()
                if current is None:
                    logger.error(f"Scheduler: failed to get blocked services on {name}")
                    continue
                ids = set(current.get('ids', []))
                new_ids = (ids | to_block) - to_unblock
                if new_ids != ids:
                    if not adguard.update_blocked_services(list(new_ids), current.get('schedule')):
                        logger.error(f"Scheduler: update failed on {name}")
                        continue
                    logger.info(
                        f"Scheduler: {name} block+={sorted(to_block)} unblock-={sorted(to_unblock)}"
                    )
                # Record applied state (even when ids already matched the desired state).
                for service, desired in pending.items():
                    state[f"{host}|{service}"] = 'blocked' if desired else 'unblocked'
                    state_changed = True
            finally:
                adguard.logout()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            logger.error(f"Scheduler: {name} ({host}) unreachable: {e}")
        except Exception as e:
            logger.error(f"Scheduler: error on {name} ({host}): {e}", exc_info=True)

    if state_changed:
        try:
            _save_json(SCHEDULE_STATE_FILE, state)
        except Exception as e:
            logger.error(f"Scheduler: failed to persist state: {e}", exc_info=True)


# Held open for the process lifetime so the flock stays acquired by the winning worker.
_scheduler_lock_fh = None


def _scheduler_loop() -> None:
    logger.info("Schedule reconcile loop started (interval=%ss)", RECONCILE_INTERVAL)
    while True:
        try:
            _reconcile_schedules()
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}", exc_info=True)
        time.sleep(RECONCILE_INTERVAL)


def _start_scheduler_thread() -> None:
    """Start the reconcile loop in exactly one worker, using an flock for mutual exclusion.

    gunicorn runs multiple workers; each imports this module and calls here, but only the
    worker that wins the exclusive lock actually runs the loop. (Requires no --preload so
    each worker opens its own file descriptor.)
    """
    global _scheduler_lock_fh
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        fh = open(SCHEDULER_LOCK_FILE, 'w')
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logger.info("Scheduler: another worker holds the lock; reconcile loop not started here")
        return
    _scheduler_lock_fh = fh  # keep reference alive so the lock is retained
    threading.Thread(target=_scheduler_loop, name='schedule-reconcile', daemon=True).start()
    logger.info("Scheduler: acquired lock, reconcile loop running in this worker")


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


@app.route('/api/schedules', methods=['GET'])
@login_required
def get_schedules():
    """Return the saved schedules plus available services and routers for the editor."""
    try:
        schedules = _load_schedules()
        services = [{'id': s, 'name': _get_service_display_name(s)} for s in _load_services()]
        routers = [{'host': h, 'name': n} for h, _, n in get_routers_from_env()]
        return jsonify({'schedules': schedules, 'services': services, 'routers': routers})
    except Exception as e:
        logger.error(f"Error getting schedules: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/schedules', methods=['PUT'])
@login_required
def save_schedules():
    """Validate and replace-all save the schedules document, then reconcile immediately."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid payload'}), 400
    routers_in = data.get('routers')
    if not isinstance(routers_in, dict):
        return jsonify({'error': 'Missing "routers" object'}), 400

    valid_hosts = {h for h, _, _ in get_routers_from_env()}
    valid_services = set(_load_services())
    cleaned = {}

    for host, svc_map in routers_in.items():
        if host not in valid_hosts:
            return jsonify({'error': f'Unknown router: {host}'}), 400
        if not isinstance(svc_map, dict):
            return jsonify({'error': f'Invalid schedules for router {host}'}), 400
        cleaned_services = {}
        for service, sched in svc_map.items():
            if service not in valid_services:
                return jsonify({'error': f'Unknown service: {service}'}), 400
            if not isinstance(sched, dict):
                return jsonify({'error': f'Invalid schedule for {service}'}), 400
            tz = sched.get('timezone') or 'Asia/Tokyo'
            try:
                ZoneInfo(tz)
            except Exception:
                return jsonify({'error': f'Invalid timezone: {tz}'}), 400
            windows_in = sched.get('windows') or []
            if not isinstance(windows_in, list):
                return jsonify({'error': f'Invalid windows for {service}'}), 400
            cleaned_windows = []
            for w in windows_in:
                if not isinstance(w, dict):
                    return jsonify({'error': 'Invalid window'}), 400
                days = w.get('days') or []
                if not isinstance(days, list) or not days or any(d not in DAY_TOKENS for d in days):
                    return jsonify({'error': f'Invalid days: {days}'}), 400
                if _parse_hhmm(w.get('start')) is None or _parse_hhmm(w.get('end')) is None:
                    return jsonify({'error': 'Invalid start/end time (use HH:MM)'}), 400
                cleaned_windows.append({
                    'days': [d for d in DAY_TOKENS if d in days],  # normalise order, dedupe
                    'start': w['start'],
                    'end': w['end'],
                })
            cleaned_services[service] = {
                'enabled': bool(sched.get('enabled', True)),
                'timezone': tz,
                'windows': cleaned_windows,
            }
        if cleaned_services:
            cleaned[host] = cleaned_services

    doc = {'version': 1, 'routers': cleaned}
    try:
        _save_json(SCHEDULES_FILE, doc)
    except Exception as e:
        logger.error(f"Error saving schedules: {e}", exc_info=True)
        return jsonify({'error': 'Failed to save schedules'}), 500

    # Apply changes right away rather than waiting for the next reconcile tick.
    try:
        _reconcile_schedules()
    except Exception as e:
        logger.error(f"Reconcile after save failed: {e}", exc_info=True)

    return jsonify({'success': True, 'schedules': doc})


@app.route('/api/schedules/status', methods=['GET'])
@login_required
def schedules_status():
    """Per router+service: whether it's in a blocked window now and when it next changes."""
    try:
        schedules = _load_schedules()
        routers_cfg = schedules.get('routers') or {}
        out = {}
        for host, svc_map in routers_cfg.items():
            if not isinstance(svc_map, dict):
                continue
            svc_out = {}
            for service, sched in svc_map.items():
                if not isinstance(sched, dict):
                    continue
                now = _service_now(sched)
                svc_out[service] = {
                    'enabled': bool(sched.get('enabled')),
                    'blocked_now': _service_should_block(sched, now),
                    'next_change': _next_transition(sched, now),
                    'timezone': sched.get('timezone') or 'Asia/Tokyo',
                }
            out[host] = svc_out
        return jsonify({'status': out})
    except Exception as e:
        logger.error(f"Error getting schedules status: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# Start the reconcile loop at import time so it runs under gunicorn (single worker via flock)
# as well as the local dev server below.
_start_scheduler_thread()


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

