# SOC Firewall Docker Deployment

This directory contains Docker configuration for containerized deployment of SOC Firewall.

## Quick Start

### Production Deployment

```bash
# Build and start production container
docker-compose up -d soc-firewall

# Check logs
docker-compose logs -f soc-firewall

# Stop
docker-compose down
Development Environment
# Start development environment with hot reload
docker-compose --profile development up -d

# Attach to container for debugging
docker exec -it soc-firewall-dev bash

# Run tests
docker-compose --profile test up soc-firewall-test

Full Stack with Monitoring
# Start all services including monitoring stack
docker-compose --profile monitoring up -d

# Access services:
# - SOC Firewall API: http://localhost:5000
# - Kibana: http://localhost:5601
# - Grafana: http://localhost:3000
# - Prometheus: http://localhost:9090
# - Portainer: http://localhost:9000

Docker Images
Build Stages
builder - Build dependencies

production - Production runtime (default)

development - Development with debug tools

test - Testing environment

# Build production image
docker build -f docker/Dockerfile --target production -t soc-firewall:latest ..

# Build development image
docker build -f docker/Dockerfile --target development -t soc-firewall:dev ..

# Build with build args
docker build \
  --build-arg VERSION=1.0.0 \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  -t soc-firewall:1.0.0 .
Configuration
Environment Variables
Variable	Description	Default
TARGET	Build target (production/development/test)	production
CONFIG_FILE	Configuration file name	production.yaml
SMTP_USERNAME	SMTP username for email alerts	-
SMTP_PASSWORD	SMTP password	-
SLACK_WEBHOOK_URL	Slack webhook URL	-
REDIS_PASSWORD	Redis password	redis123
POSTGRES_PASSWORD	PostgreSQL password	socfw123
Volumes
Volume	Path	Description
./config	/etc/soc-firewall	Configuration files
./data	/var/lib/soc-firewall	Persistent data
./logs	/var/log/soc-firewall	Log files
Ports
Port	Service	Description
5000	API	REST API
8765	WebSocket	Real-time events
5678	Debug	Python debugger (development)
Networking
The container requires host network mode or specific capabilities:

yaml
network_mode: host  # Simplest, uses host network
# OR
cap_add:
  - NET_ADMIN
  - NET_RAW
  - NET_BIND_SERVICE
Security
Capabilities
The container needs these Linux capabilities:

NET_ADMIN - Network administration

NET_RAW - Raw socket access

NET_BIND_SERVICE - Bind to privileged ports

Non-root User
The container runs as socfw user (UID 1000) for security.

Read-only Root Filesystem
For enhanced security, run with read-only root:

bash
docker run --read-only \
  -v /var/lib/soc-firewall:/var/lib/soc-firewall \
  -v /var/log/soc-firewall:/var/log/soc-firewall \
  soc-firewall:latest
Health Checks
The container includes a health check endpoint:

bash
# Manual health check
docker exec soc-firewall /docker/healthcheck.sh

# View health status
docker inspect --format='{{json .State.Health}}' soc-firewall
Troubleshooting
Common Issues
Permission denied for packet capture

bash
# Add NET_ADMIN and NET_RAW capabilities
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW ...
Interface not found

bash
# Use host networking or pass interface correctly
network_mode: host
Configuration file not found

bash
# Mount config directory
- ./config:/etc/soc-firewall:ro
Debug Commands
bash
# Check container logs
docker logs soc-firewall

# Execute inside container
docker exec -it soc-firewall bash

# Check network capabilities
docker exec soc-firewall cat /proc/self/status | grep Cap

# Test packet capture
docker exec soc-firewall tcpdump -i eth0 -c 10
Performance Tuning
Resource Limits
yaml
services:
  soc-firewall:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
System Parameters
bash
# Increase buffer sizes
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.rmem_default=26214400
Backup and Restore
Backup Volumes
bash
# Backup data
docker run --rm -v soc-firewall_data:/source -v $(pwd):/backup alpine \
  tar czf /backup/soc-firewall-data.tar.gz -C /source .

# Restore
docker run --rm -v soc-firewall_data:/target -v $(pwd):/backup alpine \
  tar xzf /backup/soc-firewall-data.tar.gz -C /target
Upgrading
bash
# Pull latest image
docker-compose pull

# Recreate containers
docker-compose up -d --force-recreate

# Database migrations (if applicable)
docker exec soc-firewall python -m alembic upgrade head
References
Docker Documentation

Docker Compose Documentation

SOC Firewall Documentation
