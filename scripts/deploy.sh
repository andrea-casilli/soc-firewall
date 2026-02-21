#!/bin/bash
#
# SOC Firewall Deployment Script
# Automated deployment for production environments
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="soc-firewall"
APP_USER="socfw"
APP_GROUP="socfw"
APP_HOME="/opt/$APP_NAME"
CONFIG_DIR="/etc/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
DATA_DIR="/var/lib/$APP_NAME"
VENV_DIR="$APP_HOME/venv"
SERVICE_NAME="$APP_NAME.service"

# Print banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         SOC Firewall Deployment Script                     ║"
echo "║         Version 1.0.0                                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        error "Cannot determine OS"
        exit 1
    fi
    
    log "Detected OS: $OS $VER"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed"
        exit 1
    fi
    
    PY_VERSION=$(python3 --version)
    log "Python: $PY_VERSION"
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        error "pip3 is not installed"
        exit 1
    fi
    
    # Check required system packages
    local REQUIRED_PKGS=(
        "python3-dev"
        "python3-venv"
        "libpcap-dev"
        "build-essential"
        "iptables"
        "curl"
        "wget"
    )
    
    case $OS in
        ubuntu|debian)
            for pkg in "${REQUIRED_PKGS[@]}"; do
                if ! dpkg -l | grep -q "^ii  $pkg "; then
                    warn "Package $pkg is not installed"
                    apt-get install -y $pkg
                fi
            done
            ;;
        centos|rhel|fedora)
            for pkg in "${REQUIRED_PKGS[@]}"; do
                if ! rpm -q $pkg &> /dev/null; then
                    warn "Package $pkg is not installed"
                    yum install -y $pkg
                fi
            done
            ;;
        *)
            error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    log "Prerequisites check completed"
}

# Create system user
create_user() {
    log "Creating system user and group..."
    
    if ! getent group $APP_GROUP > /dev/null; then
        groupadd --system $APP_GROUP
        log "Group $APP_GROUP created"
    fi
    
    if ! getent passwd $APP_USER > /dev/null; then
        useradd --system \
                --gid $APP_GROUP \
                --home-dir $APP_HOME \
                --shell /bin/bash \
                --comment "SOC Firewall Service" \
                $APP_USER
        log "User $APP_USER created"
    fi
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    # Application directories
    mkdir -p $APP_HOME
    mkdir -p $CONFIG_DIR
    mkdir -p $LOG_DIR
    mkdir -p $DATA_DIR
    mkdir -p $DATA_DIR/quarantine
    mkdir -p $DATA_DIR/threat_intel
    
    # Create config subdirectories
    mkdir -p $CONFIG_DIR/rules
    mkdir -p $CONFIG_DIR/playbooks
    mkdir -p $CONFIG_DIR/signatures
    
    # Set permissions
    chown -R $APP_USER:$APP_GROUP $APP_HOME
    chown -R $APP_USER:$APP_GROUP $CONFIG_DIR
    chown -R $APP_USER:$APP_GROUP $LOG_DIR
    chown -R $APP_USER:$APP_GROUP $DATA_DIR
    
    # Set restrictive permissions on config
    chmod 750 $CONFIG_DIR
    chmod 640 $CONFIG_DIR/*.yaml 2>/dev/null || true
    
    log "Directory structure created"
}

# Copy application files
copy_files() {
    log "Copying application files..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    # Copy source code
    cp -r $PROJECT_DIR/src $APP_HOME/
    cp $PROJECT_DIR/main.py $APP_HOME/
    cp $PROJECT_DIR/requirements.txt $APP_HOME/
    cp $PROJECT_DIR/setup.py $APP_HOME/
    
    # Copy default configuration
    if [ ! -f $CONFIG_DIR/production.yaml ]; then
        cp $PROJECT_DIR/config/production.yaml $CONFIG_DIR/ 2>/dev/null || \
        cat > $CONFIG_DIR/production.yaml <<EOF
# SOC Firewall Production Configuration
firewall:
  interface: "eth0"
  num_workers: 4
  max_connections: 100000
  block_external_ping: true
  internal_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"

detection:
  enable_ids: true
  enable_anomaly: true
  enable_threat_intel: true
  port_scan_threshold: 50
  syn_flood_threshold: 100
  dos_threshold: 1000

response:
  enable_auto_response: true
  enable_quarantine: true
  quarantine_default_duration: 3600
  alert_channels: ["log", "email"]

api:
  enable_rest_api: true
  rest_host: "127.0.0.1"
  rest_port: 5000
  enable_websocket: true
  websocket_port: 8765
  enable_auth: true

logging:
  log_dir: "/var/log/soc-firewall"
  log_level: "info"
  log_format: "json"
  console_output: false
EOF
    fi
    
    # Copy default rules
    if [ ! -f $CONFIG_DIR/rules/base_rules.yaml ]; then
        cat > $CONFIG_DIR/rules/base_rules.yaml <<EOF
rules:
  - name: "block_external_ping"
    action: "DROP"
    priority: 10
    conditions:
      - field: "protocol"
        operator: "eq"
        value: "ICMP"
      - field: "flags"
        operator: "contains"
        value: "type=8"
      - field: "src_ip"
        operator: "cidr"
        value: "0.0.0.0/0"

  - name: "allow_internal_ping"
    action: "ALLOW"
    priority: 20
    conditions:
      - field: "protocol"
        operator: "eq"
        value: "ICMP"
      - field: "flags"
        operator: "contains"
        value: "type=8"
      - field: "src_ip"
        operator: "cidr"
        value: "192.168.0.0/16"

  - name: "block_ssh_external"
    action: "DROP"
    priority: 30
    conditions:
      - field: "protocol"
        operator: "eq"
        value: "TCP"
      - field: "dst_port"
        operator: "eq"
        value: 22
EOF
    fi
    
    # Set ownership
    chown -R $APP_USER:$APP_GROUP $APP_HOME
    
    log "Application files copied"
}

# Setup Python virtual environment
setup_venv() {
    log "Setting up Python virtual environment..."
    
    # Create virtual environment
    python3 -m venv $VENV_DIR
    
    # Activate and install requirements
    source $VENV_DIR/bin/activate
    pip install --upgrade pip
    pip install -r $APP_HOME/requirements.txt
    pip install gunicorn  # For production API server
    deactivate
    
    # Set ownership
    chown -R $APP_USER:$APP_GROUP $VENV_DIR
    
    log "Virtual environment created"
}

# Create systemd service
create_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=SOC Firewall Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_HOME
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=$APP_HOME"
Environment="SOC_FW_CONFIG=$CONFIG_DIR/production.yaml"
ExecStart=$VENV_DIR/bin/python $APP_HOME/main.py --config $CONFIG_DIR/production.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$APP_NAME
LimitNOFILE=65536
LimitNPROC=65536
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    log "Systemd service created: $SERVICE_NAME"
}

# Configure firewall rules
configure_firewall() {
    log "Configuring system firewall..."
    
    # Save existing rules
    iptables-save > /tmp/iptables.backup
    
    # Add SOC Firewall specific rules
    iptables -N SOC_FIREWALL 2>/dev/null || iptables -F SOC_FIREWALL
    
    # Redirect traffic to SOC Firewall (if using NFQUEUE)
    iptables -I INPUT -j SOC_FIREWALL 2>/dev/null || true
    
    # Save rules
    if command -v iptables-save > /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi
    
    log "Firewall configured"
}

# Setup log rotation
setup_logrotate() {
    log "Setting up log rotation..."
    
    cat > /etc/logrotate.d/$APP_NAME <<EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $APP_USER $APP_GROUP
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log "Log rotation configured"
}

# Create API tokens
create_api_tokens() {
    log "Creating API tokens..."
    
    # Generate random tokens
    ADMIN_TOKEN=$(openssl rand -hex 24)
    READONLY_TOKEN=$(openssl rand -hex 24)
    
    # Save tokens to file
    cat > $CONFIG_DIR/api_tokens.txt <<EOF
# SOC Firewall API Tokens
# Generated on $(date)

Admin Token: $ADMIN_TOKEN
Read-Only Token: $READONLY_TOKEN

# Add to configuration:
api:
  api_tokens:
    "$ADMIN_TOKEN":
      permissions: ["admin", "read", "write", "configure"]
      expiry: $(($(date +%s) + 31536000))
      user: "admin"
    "$READONLY_TOKEN":
      permissions: ["read"]
      expiry: $(($(date +%s) + 31536000))
      user: "readonly"
EOF
    
    chmod 600 $CONFIG_DIR/api_tokens.txt
    chown $APP_USER:$APP_GROUP $CONFIG_DIR/api_tokens.txt
    
    log "API tokens created and saved to $CONFIG_DIR/api_tokens.txt"
}

# Start service
start_service() {
    log "Starting SOC Firewall service..."
    
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME
    
    # Wait for service to start
    sleep 5
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        log "Service started successfully"
    else
        error "Service failed to start"
        systemctl status $SERVICE_NAME
        exit 1
    fi
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Check service status
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        error "Service is not running"
        return 1
    fi
    
    # Check API endpoint
    if command -v curl &> /dev/null; then
        sleep 2
        curl -s http://localhost:5000/api/v1/status > /dev/null
        if [ $? -eq 0 ]; then
            log "API is responding"
        else
            warn "API is not responding"
        fi
    fi
    
    # Check logs
    if [ -f $LOG_DIR/soc_firewall.log ]; then
        log "Log file exists"
        tail -n 5 $LOG_DIR/soc_firewall.log
    fi
    
    log "Deployment verification completed"
}

# Main deployment function
main() {
    log "Starting SOC Firewall deployment..."
    
    check_prerequisites
    create_user
    create_directories
    copy_files
    setup_venv
    create_service
    configure_firewall
    setup_logrotate
    create_api_tokens
    start_service
    verify_deployment
    
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║         SOC Firewall Deployment Complete!                  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "Installation Path: $APP_HOME"
    echo "Configuration: $CONFIG_DIR"
    echo "Logs: $LOG_DIR"
    echo "Data: $DATA_DIR"
    echo ""
    echo "Service Management:"
    echo "  Start:   systemctl start $SERVICE_NAME"
    echo "  Stop:    systemctl stop $SERVICE_NAME"
    echo "  Restart: systemctl restart $SERVICE_NAME"
    echo "  Status:  systemctl status $SERVICE_NAME"
    echo ""
    echo "API Tokens: $CONFIG_DIR/api_tokens.txt"
    echo ""
    echo -e "${YELLOW}Please review the configuration in $CONFIG_DIR/production.yaml${NC}"
}

# Run main function
main
