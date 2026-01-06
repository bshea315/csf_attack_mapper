#!/bin/bash
#
# CSF×ATT&CK Mapper - One-Click Setup Script
#
# This script sets up the entire application with sample data:
# 1. Creates Python virtual environment
# 2. Installs backend dependencies
# 3. Initializes database with reference data (MITRE, CSF, crosswalk)
# 4. Loads sample detections with automatic MITRE mapping
# 5. Creates sample SOAR playbooks with execution metrics
# 6. Installs frontend dependencies
#
# After running this script, you'll have a fully working demo with:
# - 20 sample SPL detections mapped to MITRE ATT&CK
# - CSF 2.0 posture coverage calculated
# - 8 SOAR playbooks with 200 execution runs
# - Detection-playbook links for automation tracking
#

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_step "Python 3 found: $PYTHON_VERSION"
    else
        print_error "Python 3 is required but not found. Please install Python 3.10+"
        exit 1
    fi

    # Check Node.js
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_step "Node.js found: $NODE_VERSION"
    else
        print_error "Node.js is required but not found. Please install Node.js 18+"
        exit 1
    fi

    # Check npm
    if command -v npm &> /dev/null; then
        NPM_VERSION=$(npm --version)
        print_step "npm found: $NPM_VERSION"
    else
        print_error "npm is required but not found."
        exit 1
    fi
}

# Setup backend
setup_backend() {
    print_header "Setting Up Backend"

    cd "$SCRIPT_DIR/backend"

    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv venv
        print_step "Virtual environment created"
    else
        print_warning "Virtual environment already exists, skipping creation"
    fi

    # Activate virtual environment
    source venv/bin/activate
    print_step "Virtual environment activated"

    # Install dependencies
    echo "Installing Python dependencies..."
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    print_step "Python dependencies installed"

    cd "$SCRIPT_DIR"
}

# Initialize database
init_database() {
    print_header "Initializing Database"

    cd "$SCRIPT_DIR/backend"
    source venv/bin/activate

    # Remove existing database for clean start
    if [ -f "../data/csf_attack_mapper.db" ]; then
        print_warning "Removing existing database for fresh setup..."
        rm ../data/csf_attack_mapper.db
    fi

    # Create data directory if it doesn't exist
    mkdir -p ../data

    # Run init script
    echo "Creating database tables and loading reference data..."
    python ../scripts/init_db.py

    print_step "Database initialized with MITRE ATT&CK techniques"
    print_step "CSF 2.0 categories loaded"
    print_step "MITRE to CSF crosswalk mappings loaded"
    print_step "Default admin user created"

    cd "$SCRIPT_DIR"
}

# Load sample detections
load_sample_detections() {
    print_header "Loading Sample Detections"

    cd "$SCRIPT_DIR/backend"
    source venv/bin/activate

    echo "Ingesting sample detections and computing MITRE mappings..."
    python ../scripts/load_sample_data.py

    print_step "20 sample SPL detections loaded"
    print_step "Automatic MITRE ATT&CK mapping completed"
    print_step "CSF impact scores calculated"

    cd "$SCRIPT_DIR"
}

# Load SOAR playbook data
load_soar_data() {
    print_header "Loading SOAR Playbook Data"

    cd "$SCRIPT_DIR/backend"
    source venv/bin/activate

    echo "Creating sample playbooks and execution metrics..."
    python ../scripts/seed_soar_fixtures.py

    print_step "8 SOAR playbooks created"
    print_step "200 playbook execution runs generated"
    print_step "Action run metrics populated"
    print_step "Detection-playbook links established"

    cd "$SCRIPT_DIR"
}

# Setup frontend
setup_frontend() {
    print_header "Setting Up Frontend"

    cd "$SCRIPT_DIR/frontend"

    # Install dependencies
    echo "Installing Node.js dependencies..."
    npm install --silent
    print_step "Frontend dependencies installed"

    cd "$SCRIPT_DIR"
}

# Print completion message
print_completion() {
    print_header "Setup Complete!"

    echo -e "${GREEN}The CSF×ATT&CK Mapper is ready to use!${NC}"
    echo ""
    echo "Sample data loaded:"
    echo "  - 20 SPL detections with MITRE ATT&CK mappings"
    echo "  - CSF 2.0 coverage scores calculated"
    echo "  - 8 SOAR playbooks with time savings metrics"
    echo "  - 200 playbook execution runs over 30 days"
    echo "  - Detection-to-playbook automation links"
    echo ""
    echo -e "${YELLOW}To start the application:${NC}"
    echo ""
    echo "  Terminal 1 (Backend):"
    echo "    cd backend"
    echo "    source venv/bin/activate"
    echo "    uvicorn app.main:app --reload --port 8000"
    echo ""
    echo "  Terminal 2 (Frontend):"
    echo "    cd frontend"
    echo "    npm run dev"
    echo ""
    echo "  Then open: http://localhost:5173"
    echo ""
    echo -e "${YELLOW}Default credentials:${NC}"
    echo "  Username: admin"
    echo "  Password: changeme123"
    echo ""
}

# Main execution
main() {
    print_header "CSF×ATT&CK Mapper Setup"
    echo "This script will set up the complete application with sample data."
    echo "Estimated time: 2-3 minutes"
    echo ""

    check_prerequisites
    setup_backend
    init_database
    load_sample_detections
    load_soar_data
    setup_frontend
    print_completion
}

# Run main function
main
