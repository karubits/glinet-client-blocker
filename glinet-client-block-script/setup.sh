#!/bin/bash
# Setup script for GL.iNet Client Blocking Tool
# This script sets up a Python virtual environment and installs dependencies

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON_CMD="python3"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed."
    print_info "Please install Python 3.6 or higher:"
    echo "  - Ubuntu/Debian: sudo apt-get install python3 python3-pip python3-venv"
    echo "  - Fedora/RHEL: sudo dnf install python3 python3-pip"
    echo "  - Arch Linux: sudo pacman -S python python-pip"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 6 ]); then
    print_error "Python 3.6 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

print_success "Found Python $PYTHON_VERSION"

# Check if venv module is available
if ! python3 -m venv --help &> /dev/null; then
    print_error "Python venv module is not available."
    print_info "Please install python3-venv:"
    echo "  - Ubuntu/Debian: sudo apt-get install python3-venv"
    echo "  - Fedora/RHEL: sudo dnf install python3-venv"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    print_success "Virtual environment created at $VENV_DIR"
else
    print_info "Virtual environment already exists at $VENV_DIR"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    print_info "Installing dependencies from requirements.txt..."
    pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
    print_success "Dependencies installed"
else
    print_warning "requirements.txt not found. Installing basic dependencies..."
    pip install requests urllib3 --quiet
    print_success "Basic dependencies installed"
fi

print_success "Setup complete!"
echo ""
print_info "To use the script, you have several options:"
echo ""
echo "Option 1: Use the wrapper script (works with any shell):"
echo "  ./glinet-block --help"
echo ""
echo "Option 2: Use venv Python directly (works with any shell):"
echo "  $VENV_DIR/bin/python3 glinet_block.py --help"
echo ""
echo "Option 3: Activate venv (bash/zsh only):"
echo "  source $VENV_DIR/bin/activate"
echo "  python3 glinet_block.py --help"
echo ""
echo "Note: For fish shell, use Option 1 or 2 (the wrapper script or direct venv python)"

