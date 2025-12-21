#!/usr/bin/env python3
"""
GL.iNet Client Blocking Web UI

A web interface for managing client blocking/unblocking on GL.iNet routers.
"""

import os
import sys
import csv
import logging
from datetime import timedelta
from functools import wraps
from typing import List, Dict, Tuple, Optional

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
import requests

# Import glinet_block from same directory
from glinet_block import (
    GLiNetRouter,
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
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key-in-production')

# Session configuration - 4 hours
app.permanent_session_lifetime = timedelta(hours=4)

# Configuration - use data directory for mounted volumes
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MAPPING_FILE = os.path.join(DATA_DIR, 'mapping.csv')
ROUTERS_FILE = os.path.join(DATA_DIR, 'routers.csv')
CLIENTS_DIR = os.path.join(DATA_DIR, 'clients')

# Default password (should be changed via environment variables)
DEFAULT_PASSWORD = os.environ.get('WEBUI_PASSWORD', 'admin')

# Store password hash (in production, use environment variable)
PASSWORD_HASH = os.environ.get('WEBUI_PASSWORD_HASH')
if not PASSWORD_HASH:
    # Generate hash from plain password if hash not provided
    PASSWORD_HASH = generate_password_hash(DEFAULT_PASSWORD)


def get_routers_from_env() -> List[Tuple[str, str, str]]:
    """
    Get routers from environment variables.
    Supports ROUTER_HOST_1, ROUTER_PASS_1, ROUTER_NAME_1, etc.
    Also supports comma-separated ROUTER_HOSTS and ROUTER_PASSES.
    Falls back to routers.csv file if env vars not set.
    Returns list of (host, password, name) tuples.
    """
    routers = []
    
    # Try comma-separated lists first
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
        else:
            logger.warning("ROUTER_HOSTS and ROUTER_PASSES have different lengths, ignoring")
    
    # Try numbered environment variables (ROUTER_HOST_1, ROUTER_PASS_1, ROUTER_NAME_1, etc.)
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
    
    # Fall back to routers.csv file
    if os.path.exists(ROUTERS_FILE):
        try:
            router_list = parse_routers_file(ROUTERS_FILE)
            # Convert to (host, password, name) format, using host as name
            routers = [(host, password, host) for host, password in router_list]
            logger.info(f"Loaded {len(routers)} router(s) from {ROUTERS_FILE}")
            return routers
        except Exception as e:
            logger.error(f"Error reading routers.csv: {e}")
    
    logger.warning("No routers configured (no env vars or routers.csv found)")
    return []


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
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        # Check password
        if check_password_hash(PASSWORD_HASH, password):
            session.permanent = True
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password', 'error')
    
    # If already logged in, redirect to dashboard
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')


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
    """Get mapping of categories to client list files."""
    try:
        mapping = []
        if os.path.exists(MAPPING_FILE):
            with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2 and row[0].strip() and row[1].strip():
                        category = row[0].strip()
                        filename = row[1].strip()
                        # Check if file exists in clients directory
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
    """Helper function to get clients from a specific category or all categories."""
    clients = []
    
    if category == 'all':
        # Read all client lists from mapping
        if os.path.exists(MAPPING_FILE):
            with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2 and row[1].strip():
                        filename = row[1].strip()
                        file_path = os.path.join(CLIENTS_DIR, filename)
                        
                        if os.path.exists(file_path):
                            category_name = row[0].strip()
                            try:
                                client_list = parse_client_list(file_path)
                                for mac, name in client_list:
                                    clients.append({
                                        'mac': mac,
                                        'name': name,
                                        'category': category_name
                                    })
                            except Exception as e:
                                logger.error(f"Error parsing {file_path}: {e}")
    else:
        # Read specific category
        if os.path.exists(MAPPING_FILE):
            with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2 and row[0].strip() == category:
                        filename = row[1].strip()
                        file_path = os.path.join(CLIENTS_DIR, filename)
                        
                        if os.path.exists(file_path):
                            try:
                                client_list = parse_client_list(file_path)
                                for mac, name in client_list:
                                    clients.append({
                                        'mac': mac,
                                        'name': name,
                                        'category': category
                                    })
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
                logger.error(f"Failed to initialize router connection to {router_name} ({router_host}): {e}")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': f'Failed to connect: {str(e)}'
                })
                continue
            
            try:
                if not router.login():
                    logger.error(f"Failed to authenticate with router {router_name} ({router_host})")
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Authentication failed'
                    })
                    continue
            except requests.exceptions.Timeout as e:
                logger.error(f"Connection timeout to router {router_name} ({router_host}): {e}")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out. Router may be unreachable or slow to respond.'
                })
                continue
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error to router {router_name} ({router_host}): {e}")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Router unreachable. Please check if the router is online and accessible.'
                })
                continue
            except Exception as e:
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
                logger.error(f"Failed to initialize router connection to {router_name} ({router_host}): {e}")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': f'Failed to connect: {str(e)}'
                })
                continue
            
            try:
                if not router.login():
                    logger.error(f"Failed to authenticate with router {router_name} ({router_host})")
                    results.append({
                        'router': router_host,
                        'router_name': router_name,
                        'success': False,
                        'error': 'Authentication failed'
                    })
                    continue
            except requests.exceptions.Timeout as e:
                logger.error(f"Connection timeout to router {router_name} ({router_host}): {e}")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Request timed out. Router may be unreachable or slow to respond.'
                })
                continue
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error to router {router_name} ({router_host}): {e}")
                results.append({
                    'router': router_host,
                    'router_name': router_name,
                    'success': False,
                    'error': 'Router unreachable. Please check if the router is online and accessible.'
                })
                continue
            except Exception as e:
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


if __name__ == '__main__':
    # Create data directories if they don't exist
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    
    # Log startup info
    routers = get_routers_from_env()
    logger.info(f"Starting GL.iNet Client Block Web UI")
    logger.info(f"Configured routers: {len(routers)}")
    for i, (host, _, name) in enumerate(routers, 1):
        logger.info(f"  Router {i}: {name} ({host})")
    
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=False)

