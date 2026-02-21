# SOC Firewall Deployment Guide

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Options](#installation-options)
3. [Production Deployment](#production-deployment)
4. [Configuration](#configuration)
5. [Security Hardening](#security-hardening)
6. [Monitoring](#monitoring)
7. [Backup and Recovery](#backup-and-recovery)
8. [Upgrading](#upgrading)
9. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **RAM**: 2 GB
- **Disk**: 20 GB SSD
- **Network**: 1 Gbps NIC
- **OS**: Ubuntu 20.04+, Debian 11+, RHEL 8+

### Recommended for Production
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Disk**: 100+ GB SSD
- **Network**: 10 Gbps NIC
- **OS**: Ubuntu 22.04 LTS

### Network Requirements
- Promiscuous mode capable NIC
- At least one monitoring interface
- Management interface (separate recommended)

## Installation Options

### Option 1: Debian/Ubuntu Package

```bash
# Add repository
wget -qO - https://repo.soc-firewall.com/gpg.key | sudo apt-key add -
echo "deb https://repo.soc-firewall.com/apt stable main" | sudo tee /etc/apt/sources.list.d/soc-firewall.list

# Update and install
sudo apt update
sudo apt install soc-firewall

# Start service
sudo systemctl start soc-firewall
sudo systemctl enable soc-firewall
```

### Option 2: Docker Deployment

```bash
# Pull image
docker pull soc-firewall:latest

# Run container
docker run -d \
  --name soc-firewall \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v /etc/soc-firewall:/etc/soc-firewall:ro \
  -v /var/log/soc-firewall:/var/log/soc-firewall \
  -v /var/lib/soc-firewall:/var/lib/soc-firewall \
  soc-firewall:latest
```

### Option 3: Manual Installation

```bash
# Clone repository
git clone https://github.com/yourorg/soc-firewall.git
cd soc-firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements/production.txt

# Create directories
sudo mkdir -p /etc/soc-firewall
sudo mkdir -p /var/log/soc-firewall
sudo mkdir -p /var/lib/soc-firewall

# Copy configuration
sudo cp config/production.yaml /etc/soc-firewall/
sudo cp -r config/rules /etc/soc-firewall/
sudo cp -r config/alerting /etc/soc-firewall/

# Create system user
sudo useradd -r -s /bin/false socfw

# Set permissions
sudo chown -R socfw:socfw /etc/soc-firewall
sudo chown -R socfw:socfw /var/log/soc-firewall
sudo chown -R socfw:socfw /var/lib/soc-firewall

# Install systemd service
sudo cp scripts/soc-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable soc-firewall
sudo systemctl start soc-firewall
```

## Production Deployment

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3-pip python3-dev libpcap-dev build-essential

# Increase system limits
cat >> /etc/security/limits.conf << EOF
socfw soft nofile 65536
socfw hard nofile 65536
EOF

# Optimize network settings
cat >> /etc/sysctl.conf << EOF
net.core.rmem_max = 134217728
net.core.rmem_default = 134217728
net.core.wmem_max = 134217728
net.core.wmem_default = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
EOF

sudo sysctl -p
```

### Step 2: Configure Network Interface

```bash
# Identify monitoring interface
ip link show

# Enable promiscuous mode
sudo ip link set eth0 promisc on

# Make persistent (Ubuntu)
cat >> /etc/network/interfaces << EOF
auto eth0
iface eth0 inet manual
    up ip link set eth0 promisc on
    down ip link set eth0 promisc off
EOF
```

### Step 3: Configure Firewall

Edit `/etc/soc-firewall/production.yaml`:

```yaml
firewall:
  interface: "eth0"
  num_workers: 4
  max_connections: 100000
  block_external_ping: true
  internal_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

detection:
  enable_ids: true
  enable_threat_intel: true
  port_scan_threshold: 50
  syn_flood_threshold: 100

response:
  enable_auto_response: true
  quarantine_default_duration: 3600
  alert_channels:
    - "log"
    - "email"
    - "slack"

api:
  enable_rest_api: true
  rest_host: "127.0.0.1"
  rest_port: 5000
  enable_auth: true

logging:
  log_dir: "/var/log/soc-firewall"
  log_level: "info"
  log_format: "json"
```

### Step 4: Configure Alerting

#### Email Configuration
Edit `/etc/soc-firewall/alerting/email_config.yaml`:

```yaml
smtp:
  server: "smtp.gmail.com"
  port: 587
  username: "${SMTP_USERNAME}"
  password: "${SMTP_PASSWORD}"
  from_addr: "soc-firewall@yourdomain.com"

default_recipients:
  - "security-team@yourdomain.com"
```

#### Slack Configuration
Edit `/etc/soc-firewall/alerting/slack_config.yaml`:

```yaml
slack:
  webhook_url: "${SLACK_WEBHOOK_URL}"
  default_channel: "#security-alerts"
  username: "SOC Firewall"

channels:
  critical:
    channel: "#security-critical"
    mention: "@channel"
  high:
    channel: "#security-high"
    mention: "@here"
```

### Step 5: Start Service

```bash
# Start with systemd
sudo systemctl start soc-firewall
sudo systemctl status soc-firewall

# Enable at boot
sudo systemctl enable soc-firewall

# Check logs
sudo journalctl -u soc-firewall -f
```

### Step 6: Verify Deployment

```bash
# Check API
curl http://localhost:5000/api/v1/status

# Check packet capture
sudo tcpdump -i eth0 -c 10

# Check logs
tail -f /var/log/soc-firewall/soc_firewall.log
```

## Configuration

### Environment Variables

Create `/etc/soc-firewall/env.sh`:

```bash
# Database
export POSTGRES_PASSWORD="secure_password"

# Alerting
export SMTP_USERNAME="alerts@yourdomain.com"
export SMTP_PASSWORD="smtp_password"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/xxx/yyy/zzz"

# API Tokens
export ADMIN_TOKEN="$(openssl rand -hex 32)"
export READONLY_TOKEN="$(openssl rand -hex 32)"

# Threat Intelligence
export OTX_API_KEY="your_otx_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

### Rule Configuration

Add custom rules to `/etc/soc-firewall/rules/custom_rules.yaml`:

```yaml
rules:
  - name: "allow_vpn_users"
    action: "ALLOW"
    priority: 25
    conditions:
      - field: "src_ip"
        operator: "cidr"
        value: "10.200.0.0/16"
  
  - name: "block_abusive_scanners"
    action: "DROP"
    priority: 450
    conditions:
      - field: "src_ip"
        operator: "in"
        value: ["192.0.2.1", "198.51.100.100"]
```

## Security Hardening

### 1. Run as Non-Root User

```bash
# Create dedicated user
sudo useradd -r -s /bin/false socfw

# Set ownership
sudo chown -R socfw:socfw /etc/soc-firewall
sudo chown -R socfw:socfw /var/log/soc-firewall
sudo chown -R socfw:socfw /var/lib/soc-firewall
```

### 2. File Permissions

```bash
# Restrict configuration files
sudo chmod 750 /etc/soc-firewall
sudo chmod 640 /etc/soc-firewall/*.yaml
sudo chmod 640 /etc/soc-firewall/rules/*.yaml

# Restrict logs
sudo chmod 750 /var/log/soc-firewall
sudo chmod 640 /var/log/soc-firewall/*.log
```

### 3. Network Security

```bash
# Use dedicated management interface
# Bind API to localhost or management network only
```

```yaml
api:
  rest_host: "127.0.0.1"  # Local only
  # rest_host: "10.0.0.10"  # Management network
```

### 4. TLS/SSL Configuration

```yaml
api:
  ssl_enabled: true
  ssl_cert: "/etc/ssl/certs/soc-firewall.crt"
  ssl_key: "/etc/ssl/private/soc-firewall.key"
```

Generate certificates:

```bash
# Self-signed for testing
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/ssl/private/soc-firewall.key \
  -out /etc/ssl/certs/soc-firewall.crt \
  -days 365 -nodes

# Set permissions
sudo chmod 600 /etc/ssl/private/soc-firewall.key
sudo chmod 644 /etc/ssl/certs/soc-firewall.crt
```

### 5. AppArmor/SELinux Profile

For Ubuntu with AppArmor:

```bash
# Create profile
sudo cat > /etc/apparmor.d/usr.bin.soc-firewall << EOF
#include <tunables/global>

/usr/bin/soc-firewall {
  #include <abstractions/base>
  #include <abstractions/python>
  
  capability net_admin,
  capability net_raw,
  
  network inet raw,
  network inet6 raw,
  network packet,
  
  /etc/soc-firewall/** r,
  /var/log/soc-firewall/** rw,
  /var/lib/soc-firewall/** rw,
  /proc/** r,
  
  deny /etc/shadow r,
}
EOF

# Enable profile
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.soc-firewall
```

### 6. Fail2ban Configuration

```bash
# Install fail2ban
sudo apt install fail2ban

# Create jail
sudo cat > /etc/fail2ban/jail.d/soc-firewall.conf << EOF
[soc-firewall]
enabled = true
port = 5000
filter = soc-firewall
logpath = /var/log/soc-firewall/access.log
maxretry = 5
bantime = 3600
EOF

# Create filter
sudo cat > /etc/fail2ban/filter.d/soc-firewall.conf << EOF
[Definition]
failregex = .* 401 .* client: <HOST>
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

## Monitoring

### Prometheus Configuration

Create `/etc/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'soc-firewall'
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
```

### Grafana Dashboard

Import the provided dashboard `grafana/dashboard.json`:

```bash
# Via API
curl -X POST \
  -H "Authorization: Bearer YOUR_GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @grafana/dashboard.json \
  http://localhost:3000/api/dashboards/db
```

### Log Monitoring with ELK

Filebeat configuration `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/soc-firewall/alerts.log
  json.keys_under_root: true
  tags: ["soc-firewall", "alerts"]

- type: log
  enabled: true
  paths:
    - /var/log/soc-firewall/access.log
  tags: ["soc-firewall", "access"]

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "soc-firewall-%{+yyyy.MM.dd}"
```

### Health Checks

```bash
# Simple health check script
#!/bin/bash
curl -f http://localhost:5000/api/v1/status || exit 1
pgrep -f "python main.py" || exit 1
ip link show eth0 | grep -q UP || exit 1
```

## Backup and Recovery

### Backup Script

Save as `/usr/local/bin/backup-soc-firewall.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/soc-firewall"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz /etc/soc-firewall/

# Backup data
tar -czf $BACKUP_DIR/data_$DATE.tar.gz /var/lib/soc-firewall/

# Backup logs (optional)
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz /var/log/soc-firewall/

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

# Encrypt backups (optional)
gpg --encrypt --recipient security@example.com \
  $BACKUP_DIR/config_$DATE.tar.gz
```

### Recovery Procedure

```bash
# Stop service
sudo systemctl stop soc-firewall

# Restore configuration
sudo tar -xzf /var/backups/soc-firewall/config_20240115.tar.gz -C /

# Restore data
sudo tar -xzf /var/backups/soc-firewall/data_20240115.tar.gz -C /

# Fix permissions
sudo chown -R socfw:socfw /etc/soc-firewall
sudo chown -R socfw:socfw /var/lib/soc-firewall
sudo chown -R socfw:socfw /var/log/soc-firewall

# Start service
sudo systemctl start soc-firewall
```

## Upgrading

### Minor Version Upgrade

```bash
# Stop service
sudo systemctl stop soc-firewall

# Backup configuration
sudo cp -r /etc/soc-firewall /etc/soc-firewall.backup

# Update package
sudo apt update
sudo apt upgrade soc-firewall

# Review configuration changes
