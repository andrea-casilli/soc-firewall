# SOC Firewall

Enterprise-grade Security Operations Center (SOC) Firewall written in Python. Provides real-time packet inspection, intrusion detection, automated threat response, and comprehensive network security monitoring.

[![CI Pipeline](https://github.com/yourorg/soc-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/yourorg/soc-firewall/actions/workflows/ci.yml)
[![CD Pipeline](https://github.com/yourorg/soc-firewall/actions/workflows/cd.yml/badge.svg)](https://github.com/yourorg/soc-firewall/actions/workflows/cd.yml)
[![Code Coverage](https://codecov.io/gh/yourorg/soc-firewall/branch/main/graph/badge.svg)](https://codecov.io/gh/yourorg/soc-firewall)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/yourorg/soc-firewall)](https://hub.docker.com/r/yourorg/soc-firewall)

## Features

### 🔒 Core Firewall
- **Real-time packet inspection** - Deep packet inspection with Scapy
- **External ping blocking** - Automatically blocks ICMP echo requests from external networks
- **Stateful connection tracking** - Full TCP state machine implementation
- **Rule-based filtering** - YAML-based rule configuration with priority ordering
- **Multi-threaded processing** - High-performance packet processing with worker pools

### 🛡️ Intrusion Detection
- **Signature-based detection** - SQL injection, XSS, directory traversal, command injection
- **Behavioral analysis** - Port scan, SYN flood, DoS, brute force detection
- **Protocol anomaly detection** - TCP flag anomalies, ICMP anomalies
- **Threat intelligence integration** - External threat feeds (FireHOL, AbuseIPDB, etc.)

### ⚡ Automated Response
- **Incident management** - Automated incident creation and tracking
- **Playbook execution** - Configurable response playbooks
- **IP quarantine** - Automatic IP blocking with expiration
- **Multi-channel alerts** - Email, Slack, PagerDuty, Webhook notifications

### 📊 Management API
- **RESTful API** - Full firewall management via HTTP
- **WebSocket streaming** - Real-time event monitoring
- **Authentication** - Token-based API security
- **Rate limiting** - Configurable request throttling

### 🔍 Monitoring & Observability
- **Comprehensive logging** - Structured JSON logs
- **Metrics collection** - Prometheus integration
- **Audit trail** - Tamper-evident audit logging
- **Health checks** - Built-in health monitoring

## Quick Start

### Docker (Recommended)

```bash
# Pull and run
docker run -d \
  --name soc-firewall \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v /etc/soc-firewall:/etc/soc-firewall:ro \
  -v /var/log/soc-firewall:/var/log/soc-firewall \
  ghcr.io/yourorg/soc-firewall:latest

# Check status
curl http://localhost:5000/api/v1/status
```

### Manual Installation

```bash
# Clone repository
git clone https://github.com/yourorg/soc-firewall.git
cd soc-firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements/production.txt

# Configure
cp config/production.yaml /etc/soc-firewall/
cp -r config/rules /etc/soc-firewall/

# Run
sudo python main.py --config /etc/soc-firewall/production.yaml
```

### Docker Compose

```bash
# Start full stack
docker-compose -f docker/docker-compose.yml up -d

# Access services
# - API: http://localhost:5000
# - Kibana: http://localhost:5601
# - Grafana: http://localhost:3000
```

## Documentation

- [API Documentation](docs/API.md) - Complete API reference
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment instructions
- [Architecture Overview](docs/ARCHITECTURE.md) - System design and components
- [Configuration Guide](docs/CONFIGURATION.md) - Configuration options
- [Development Guide](docs/DEVELOPMENT.md) - Setting up development environment

## Configuration Example

```yaml
# /etc/soc-firewall/production.yaml
firewall:
  interface: "eth0"
  num_workers: 4
  block_external_ping: true
  internal_networks:
    - "10.0.0.0/8"
    - "192.168.0.0/16"

detection:
  enable_ids: true
  port_scan_threshold: 50
  syn_flood_threshold: 100

response:
  enable_auto_response: true
  quarantine_default_duration: 3600
  alert_channels: ["slack", "email"]

api:
  enable_rest_api: true
  rest_host: "127.0.0.1"
  rest_port: 5000
```

## Rule Example

```yaml
# /etc/soc-firewall/rules/custom_rules.yaml
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
        operator: "not_cidr"
        value: "192.168.0.0/16"
```

## API Usage

```bash
# Authenticate
export TOKEN="your-api-token"

# Get status
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/v1/status

# List rules
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/v1/rules

# Quarantine IP
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"ip":"1.2.3.4","reason":"malicious","duration":3600}' \
     http://localhost:5000/api/v1/quarantine/ip
```

## Python SDK

```python
from soc_firewall import Client

client = Client(
    base_url="http://localhost:5000/api/v1",
    token="your-api-token"
)

# Get status
status = client.get_status()
print(f"Firewall status: {status['status']}")

# Quarantine IP
client.quarantine_ip("1.2.3.4", reason="malicious", duration=3600)
```

## System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Python**: 3.9 or higher
- **Memory**: 2GB minimum, 8GB recommended
- **Disk**: 20GB minimum, 100GB recommended
- **Network**: 1Gbps NIC minimum, 10Gbps recommended
- **Capabilities**: NET_ADMIN, NET_RAW for packet capture

## Performance

| Metric | Target |
|--------|--------|
| Packet processing | 100,000+ packets/second |
| Concurrent connections | 1,000,000+ |
| Rule matching | < 50µs per packet |
| API response time | < 50ms |
| Alert latency | < 100ms |

## Security Features

- **Authentication** - Token-based API authentication
- **TLS/SSL** - HTTPS support for API
- **Rate limiting** - Protection against DoS
- **Audit logging** - Tamper-evident logs
- **Capability dropping** - Principle of least privilege
- **Secure configuration** - Secrets via environment variables

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For available versions, see the [tags on this repository](https://github.com/yourorg/soc-firewall/tags).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for details on each release.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Authors

Casilli Andrea

## Acknowledgments

- Scapy for packet manipulation
- Flask for API framework
- All contributors and supporters


## Roadmap

- [x] Core packet engine
- [x] IDS signature matching
- [x] REST API
- [x] Docker support
- [ ] Machine learning detection
- [ ] Cloud-native deployment (Kubernetes)
- [ ] GUI dashboard
- [ ] Mobile app

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourorg/soc-firewall&type=Date)](https://star-history.com/#yourorg/soc-firewall&Date)
