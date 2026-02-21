#!/bin/bash
#
# SOC Firewall Docker Entrypoint Script
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting SOC Firewall container...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Warning: Not running as root. Some features may not work.${NC}"
fi

# Create necessary directories
mkdir -p /var/log/soc-firewall
mkdir -p /var/lib/soc-firewall
mkdir -p /var/run/soc-firewall

# Set permissions
chown -R socfw:socfw /var/log/soc-firewall /var/lib/soc-firewall /var/run/soc-firewall 2>/dev/null || true

# Check configuration
if [ ! -f "$SOC_FW_CONFIG" ]; then
    echo -e "${RED}Configuration file not found: $SOC_FW_CONFIG${NC}"
    echo "Using default configuration..."
    export SOC_FW_CONFIG="/etc/soc-firewall/production.yaml"
fi

# Validate configuration
python -c "from src.config.validators import validate_config; import yaml; validate_config(yaml.safe_load(open('$SOC_FW_CONFIG')))" || {
    echo -e "${RED}Configuration validation failed${NC}"
    exit 1
}

# Check capabilities
if [ -f /proc/self/status ]; then
    if ! grep -q "CapBnd:.*00000000.*" /proc/self/status; then
        echo -e "${YELLOW}Warning: Required capabilities may be missing${NC}"
    fi
fi

# Check network interfaces
INTERFACE=$(python -c "import yaml; print(yaml.safe_load(open('$SOC_FW_CONFIG'))['firewall']['interface'])")
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Network interface $INTERFACE not found${NC}"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
fi

# Initialize database if needed
if [ ! -f /var/lib/soc-firewall/threat_intel.db ]; then
    echo "Initializing threat intelligence database..."
    python -m src.detection.threat_intel --init-db
fi

# Start the application
echo -e "${GREEN}Starting SOC Firewall...${NC}"
exec python main.py --config "$SOC_FW_CONFIG"

# Health check endpoint
if [ "$1" = "healthcheck" ]; then
    curl -f http://localhost:5000/api/v1/status || exit 1
    exit 0
fi
