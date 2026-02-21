#!/bin/bash
#
# SOC Firewall Backup Script
# Creates encrypted backups of configuration and data
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
CONFIG_DIR="/etc/$APP_NAME"
DATA_DIR="/var/lib/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
BACKUP_DIR="/var/backups/$APP_NAME"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"  # GPG key for encryption
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.tar.gz"
BACKUP_FILE_ENCRYPTED="$BACKUP_FILE.gpg"

# Print banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         SOC Firewall Backup Script                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    error "Please run as root"
fi

# Create backup directory
create_backup_dir() {
    log "Creating backup directory..."
    mkdir -p $BACKUP_DIR
    chmod 750 $BACKUP_DIR
}

# Create temporary directory for backup
create_temp_dir() {
    log "Creating temporary directory..."
    TEMP_DIR=$(mktemp -d -t socfw-backup-XXXXXX)
    trap "rm -rf $TEMP_DIR" EXIT
}

# Backup configuration
backup_config() {
    log "Backing up configuration from $CONFIG_DIR..."
    
    mkdir -p $TEMP_DIR/config
    cp -r $CONFIG_DIR/* $TEMP_DIR/config/ 2>/dev/null || warn "No configuration files found"
    
    # Save current iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > $TEMP_DIR/iptables.rules
        log "Saved iptables rules"
    fi
    
    # Save current nftables rules
    if command -v nft &> /dev/null; then
        nft list ruleset > $TEMP_DIR/nftables.rules 2>/dev/null || true
    fi
}

# Backup data
backup_data() {
    log "Backing up data from $DATA_DIR..."
    
    mkdir -p $TEMP_DIR/data
    if [ -d "$DATA_DIR" ]; then
        cp -r $DATA_DIR/* $TEMP_DIR/data/ 2>/dev/null || warn "No data files found"
    fi
}

# Backup logs
backup_logs() {
    log "Backing up logs from $LOG_DIR..."
    
    mkdir -p $TEMP_DIR/logs
    if [ -d "$LOG_DIR" ]; then
        # Only backup recent logs (last 7 days)
        find $LOG_DIR -name "*.log" -type f -mtime -7 -exec cp {} $TEMP_DIR/logs/ \;
    fi
}

# Save system information
save_system_info() {
    log "Saving system information..."
    
    cat > $TEMP_DIR/system_info.txt <<EOF
SOC Firewall System Information
Backup Date: $(date)
Hostname: $(hostname)
OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Kernel: $(uname -r)

Installed Packages:
EOF
    
    # List installed packages
    if command -v dpkg &> /dev/null; then
        dpkg -l | grep -E "python3|libpcap|iptables" >> $TEMP_DIR/system_info.txt
    elif command -v rpm &> /dev/null; then
        rpm -qa | grep -E "python|libpcap|iptables" >> $TEMP_DIR/system_info.txt
    fi
    
    # Save service status
    systemctl status soc-firewall > $TEMP_DIR/service_status.txt 2>&1 || true
}

# Create archive
create_archive() {
    log "Creating backup archive..."
    
    cd $(dirname $TEMP_DIR)
    tar -czf "$BACKUP_FILE" -C $TEMP_DIR $(basename $TEMP_DIR)
    
    # Get archive size
    ARCHIVE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log "Backup archive created: $BACKUP_FILE ($ARCHIVE_SIZE)"
}

# Encrypt backup (if GPG key provided)
encrypt_backup() {
    if [ -n "$GPG_RECIPIENT" ]; then
        log "Encrypting backup with GPG..."
        
        if ! command -v gpg &> /dev/null; then
            warn "GPG not installed, skipping encryption"
            return
        fi
        
        gpg --encrypt \
            --recipient "$GPG_RECIPIENT" \
            --output "$BACKUP_FILE_ENCRYPTED" \
            "$BACKUP_FILE"
        
        # Remove unencrypted archive
        rm "$BACKUP_FILE"
        
        log "Backup encrypted: $BACKUP_FILE_ENCRYPTED"
        BACKUP_FILE="$BACKUP_FILE_ENCRYPTED"
    fi
}

# Create backup manifest
create_manifest() {
    log "Creating backup manifest..."
    
    MANIFEST_FILE="$BACKUP_DIR/manifest_$TIMESTAMP.txt"
    
    cat > $MANIFEST_FILE <<EOF
SOC Firewall Backup Manifest
============================
Backup ID: $TIMESTAMP
Date: $(date)
Hostname: $(hostname)
Backup File: $(basename $BACKUP_FILE)
Size: $ARCHIVE_SIZE

Contents:
- Configuration files
- Data files (quarantine, threat intelligence)
- Recent logs (last 7 days)
- System information
- Firewall rules

Verification:
$(sha256sum "$BACKUP_FILE")

Retention: $RETENTION_DAYS days
EOF
    
    chmod 600 $MANIFEST_FILE
    log "Manifest created: $MANIFEST_FILE"
}

# Clean old backups
cleanup_old_backups() {
    log "Cleaning backups older than $RETENTION_DAYS days..."
    
    find $BACKUP_DIR -name "backup_*.tar.gz*" -type f -mtime +$RETENTION_DAYS -delete
    find $BACKUP_DIR -name "manifest_*.txt" -type f -mtime +$RETENTION_DAYS -delete
    
    # Count remaining backups
    BACKUP_COUNT=$(find $BACKUP_DIR -name "backup_*.tar.gz*" -type f | wc -l)
    log "Retained $BACKUP_COUNT recent backups"
}

# Verify backup
verify_backup() {
    log "Verifying backup integrity..."
    
    if [ -f "$BACKUP_FILE" ]; then
        # Test archive integrity
        if tar -tzf "$BACKUP_FILE" > /dev/null 2>&1; then
            log "Backup integrity verified"
        else
            error "Backup integrity check failed"
        fi
    else
        error "Backup file not found"
    fi
}

# Upload to remote storage (optional)
upload_remote() {
    if [ -n "$REMOTE_BACKUP_URL" ]; then
        log "Uploading backup to remote storage..."
        
        if command -v aws &> /dev/null && [[ "$REMOTE_BACKUP_URL" == s3://* ]]; then
            aws s3 cp "$BACKUP_FILE" "$REMOTE_BACKUP_URL/"
            aws s3 cp "$MANIFEST_FILE" "$REMOTE_BACKUP_URL/"
            log "Uploaded to S3"
        elif command -v azcopy &> /dev/null && [[ "$REMOTE_BACKUP_URL" == https://*.blob.core.windows.net/* ]]; then
            azcopy copy "$BACKUP_FILE" "$REMOTE_BACKUP_URL"
            azcopy copy "$MANIFEST_FILE" "$REMOTE_BACKUP_URL"
            log "Uploaded to Azure Blob Storage"
        elif command -v rclone &> /dev/null; then
            rclone copy "$BACKUP_FILE" "$REMOTE_BACKUP_URL"
            rclone copy "$MANIFEST_FILE" "$REMOTE_BACKUP_URL"
            log "Uploaded with rclone"
        else
            warn "No remote upload tool found, skipping"
        fi
    fi
}

# Send notification
send_notification() {
    if [ -n "$NOTIFICATION_URL" ]; then
        curl -s -X POST "$NOTIFICATION_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"text\": \"SOC Firewall backup completed\",
                \"backup_file\": \"$(basename $BACKUP_FILE)\",
                \"size\": \"$ARCHIVE_SIZE\",
                \"timestamp\": \"$(date -Iseconds)\"
            }" > /dev/null || warn "Failed to send notification"
    fi
}

# Main backup function
main() {
    log "Starting SOC Firewall backup..."
    
    create_backup_dir
    create_temp_dir
    backup_config
    backup_data
    backup_logs
    save_system_info
    create_archive
    encrypt_backup
    create_manifest
    verify_backup
    cleanup_old_backups
    upload_remote
    send_notification
    
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║         Backup Completed Successfully!                     ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "Backup File: $BACKUP_FILE"
    echo "Manifest: $MANIFEST_FILE"
    echo "Size: $ARCHIVE_SIZE"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --gpg-key)
            GPG_RECIPIENT="$2"
            shift 2
            ;;
        --remote-url)
            REMOTE_BACKUP_URL="$2"
            shift 2
            ;;
        --retention-days)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        --notification-url)
            NOTIFICATION_URL="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --gpg-key KEY         GPG key for encryption"
            echo "  --remote-url URL      Remote storage URL (s3://, azure://)"
            echo "  --retention-days DAYS  Days to retain backups (default: 30)"
            echo "  --notification-url URL Webhook URL for notifications"
            echo "  --help                 Show this help"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Run main function
main
