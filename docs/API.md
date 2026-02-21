# SOC Firewall API Documentation

## Overview

The SOC Firewall provides a comprehensive REST API for managing and monitoring the firewall system. All API endpoints return JSON responses and require authentication unless configured otherwise.

**Base URL**: `http://<firewall-ip>:5000/api/v1`

## Authentication

### API Tokens

Most endpoints require authentication using Bearer tokens:

```http
Authorization: Bearer <your-api-token>
```

### Token Management

Tokens are configured in `config/production.yaml`:

```yaml
api:
  api_tokens:
    "admin_token_123":
      permissions: ["admin", "read", "write", "configure"]
      expiry: 4102444800
      user: "admin"
    "readonly_token_456":
      permissions: ["read"]
      expiry: 4102444800
      user: "readonly"
```

## Endpoints

### System Status

#### Get System Status
```http
GET /status
```

**Response**
```json
{
  "status": "running",
  "timestamp": 1705317825.123,
  "version": "1.0.0",
  "uptime": 3600
}
```

#### Get Statistics
```http
GET /stats
```

**Response**
```json
{
  "packet_engine": {
    "packets_received": 1500000,
    "packets_processed": 1498500,
    "packets_allowed": 1450000,
    "packets_blocked": 48500,
    "alerts_generated": 234
  },
  "connections": {
    "total_connections": 12500,
    "by_state": {
      "established": 8200,
      "new": 2300,
      "closed": 2000
    }
  },
  "ids": {
    "total_inspections": 1500000,
    "total_detections": 234,
    "detection_rate": 0.0156
  }
}
```

#### Start Firewall
```http
POST /start
```

**Response**
```json
{
  "status": "started",
  "message": "Firewall started"
}
```

#### Stop Firewall
```http
POST /stop
```

**Response**
```json
{
  "status": "stopped",
  "message": "Firewall stopped"
}
```

### Rule Management

#### List All Rules
```http
GET /rules
```

**Response**
```json
{
  "rules": [
    {
      "name": "block_external_ping",
      "action": "DROP",
      "priority": 10,
      "enabled": true,
      "description": "Block ICMP echo requests from external networks",
      "conditions": [
        {
          "field": "protocol",
          "operator": "eq",
          "value": "ICMP"
        },
        {
          "field": "flags",
          "operator": "contains",
          "value": "type=8"
        }
      ],
      "tags": ["icmp", "ping", "security"]
    }
  ],
  "count": 25
}
```

#### Get Specific Rule
```http
GET /rules/{rule_name}
```

**Response**
```json
{
  "name": "block_external_ping",
  "action": "DROP",
  "priority": 10,
  "enabled": true,
  "description": "Block ICMP echo requests from external networks",
  "conditions": [
    {
      "field": "protocol",
      "operator": "eq",
      "value": "ICMP"
    }
  ]
}
```

#### Create Rule
```http
POST /rules
Content-Type: application/json

{
  "name": "block_malicious_ips",
  "action": "DROP",
  "priority": 100,
  "description": "Block known malicious IPs",
  "conditions": [
    {
      "field": "src_ip",
      "operator": "in_threat_intel",
      "value": "malicious"
    }
  ]
}
```

**Response**
```json
{
  "status": "created",
  "rule": "block_malicious_ips"
}
```

#### Update Rule
```http
PUT /rules/{rule_name}
Content-Type: application/json

{
  "action": "DROP",
  "priority": 50,
  "enabled": true,
  "conditions": [
    {
      "field": "protocol",
      "operator": "eq",
      "value": "ICMP"
    }
  ]
}
```

**Response**
```json
{
  "status": "updated",
  "rule": "block_external_ping"
}
```

#### Delete Rule
```http
DELETE /rules/{rule_name}
```

**Response**
```json
{
  "status": "deleted",
  "rule": "block_external_ping"
}
```

### Alert Management

#### Get Alerts
```http
GET /alerts?severity=high&limit=10&unacknowledged=true
```

**Query Parameters**
- `severity`: Filter by severity (info, low, medium, high, critical)
- `source`: Filter by source (ids, anomaly, threat_intel)
- `limit`: Maximum number of alerts (default: 100)
- `unacknowledged`: Only unacknowledged alerts (true/false)

**Response**
```json
{
  "alerts": [
    {
      "id": "ALT-1705123456-0001",
      "timestamp": "2024-01-15T08:23:45.123Z",
      "severity": "high",
      "source": "ids",
      "title": "SQL Injection Attempt",
      "message": "Detected UNION SELECT SQL injection pattern",
      "signature_id": "SQLI-001",
      "signature_name": "SQL Injection - UNION SELECT",
      "src_ip": "203.0.113.10",
      "dst_ip": "192.168.1.100",
      "dst_port": 80,
      "protocol": "TCP",
      "acknowledged": false
    }
  ],
  "count": 1
}
```

#### Acknowledge Alert
```http
POST /alerts/{alert_id}/acknowledge
Content-Type: application/json

{
  "user": "analyst@example.com"
}
```

**Response**
```json
{
  "status": "acknowledged",
  "alert_id": "ALT-1705123456-0001"
}
```

### Incident Management

#### List Incidents
```http
GET /incidents?status=new&severity=high&limit=10
```

**Response**
```json
{
  "incidents": [
    {
      "id": "INC-1705123456",
      "title": "SQL Injection Attack",
      "description": "Multiple SQL injection attempts detected",
      "severity": "high",
      "status": "investigating",
      "source": "ids",
      "timestamp": 1705317825.123,
      "affected_ips": ["203.0.113.10"],
      "alerts": ["ALT-1705123456-0001", "ALT-1705123456-0002"],
      "tags": ["web", "sql_injection"]
    }
  ],
  "count": 1
}
```

#### Get Incident Details
```http
GET /incidents/{incident_id}
```

**Response**
```json
{
  "id": "INC-1705123456",
  "title": "SQL Injection Attack",
  "description": "Multiple SQL injection attempts detected",
  "severity": "high",
  "status": "investigating",
  "source": "ids",
  "timestamp": 1705317825.123,
  "updated_at": 1705317925.456,
  "affected_ips": ["203.0.113.10"],
  "affected_ports": [80, 443],
  "alerts": [
    {
      "id": "ALT-1705123456-0001",
      "title": "SQL Injection Attempt",
      "timestamp": 1705317825.123
    }
  ],
  "actions_taken": [
    {
      "action": "quarantine_ip",
      "timestamp": 1705317850.789,
      "result": "success"
    }
  ],
  "notes": [
    {
      "author": "analyst@example.com",
      "message": "Investigating source IP",
      "timestamp": 1705317900.123
    }
  ],
  "tags": ["web", "sql_injection"]
}
```

#### Update Incident Status
```http
PUT /incidents/{incident_id}/status
Content-Type: application/json

{
  "status": "resolved",
  "notes": "Blocked source IP and updated WAF rules"
}
```

**Response**
```json
{
  "status": "updated",
  "incident_id": "INC-1705123456"
}
```

#### Add Incident Note
```http
POST /incidents/{incident_id}/notes
Content-Type: application/json

{
  "note": "Found similar pattern from same IP",
  "author": "analyst@example.com"
}
```

**Response**
```json
{
  "status": "added",
  "incident_id": "INC-1705123456"
}
```

### Quarantine Management

#### List Quarantined Items
```http
GET /quarantine
```

**Response**
```json
{
  "quarantines": [
    {
      "id": "Q1705123456-185.130.5.133",
      "target": "185.130.5.133",
      "reason": "malicious",
      "action": "block_ip",
      "source": "threat_intel",
      "timestamp": 1705317825.123,
      "expires": 1705321425.123,
      "description": "Known C2 server",
      "active": true
    }
  ],
  "count": 1
}
```

#### Quarantine IP
```http
POST /quarantine/ip
Content-Type: application/json

{
  "ip": "185.130.5.133",
  "reason": "malicious",
  "duration": 3600,
  "description": "Known C2 server from threat feed"
}
```

**Response**
```json
{
  "status": "quarantined",
  "entry": {
    "id": "Q1705123456-185.130.5.133",
    "target": "185.130.5.133",
    "reason": "malicious",
    "expires": 1705321425.123
  }
}
```

#### Quarantine Subnet
```http
POST /quarantine/subnet
Content-Type: application/json

{
  "subnet": "185.130.5.0/24",
  "reason": "malicious",
  "duration": 7200,
  "description": "Known malicious subnet"
}
```

**Response**
```json
{
  "status": "quarantined",
  "entry": {
    "id": "Q1705123456-185.130.5.0/24",
    "target": "185.130.5.0/24",
    "action": "block_subnet"
  }
}
```

#### Release Quarantine
```http
POST /quarantine/{entry_id}/release
```

**Response**
```json
{
  "status": "released",
  "entry_id": "Q1705123456-185.130.5.133"
}
```

#### Check IP Status
```http
GET /quarantine/check/{ip}
```

**Response**
```json
{
  "ip": "185.130.5.133",
  "quarantined": true,
  "info": {
    "id": "Q1705123456-185.130.5.133",
    "reason": "malicious",
    "expires": 1705321425.123
  }
}
```

### Connection Tracking

#### Get Connection Statistics
```http
GET /connections
```

**Response**
```json
{
  "statistics": {
    "total_connections": 12500,
    "by_state": {
      "established": 8200,
      "new": 2300,
      "closed": 2000
    },
    "by_protocol": {
      "tcp": 10000,
      "udp": 2000,
      "icmp": 500
    },
    "utilization_percent": 12.5
  }
}
```

#### Get Connections for IP
```http
GET /connections/{ip}
```

**Response**
```json
{
  "ip": "192.168.1.100",
  "connections": [
    {
      "protocol": "TCP",
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 12345,
      "dst_port": 443,
      "state": "established",
      "first_seen": 1705317825.123,
      "last_seen": 1705317925.456,
      "packets_forward": 150,
      "packets_reverse": 145
    }
  ],
  "count": 5
}
```

### Threat Intelligence

#### Check IP Against Threat Feeds
```http
GET /threat-intel/check/{ip}
```

**Response**
```json
{
  "ip": "185.130.5.133",
  "threat": {
    "value": "185.130.5.133",
    "type": "ip",
    "source": "firehol_level1",
    "confidence": 0.95,
    "first_seen": 1705000000.0,
    "tags": ["malicious", "c2", "botnet"]
  }
}
```

### Configuration

#### Get Current Configuration
```http
GET /config
```

**Response**
```json
{
  "api_version": "v1",
  "components": {
    "firewall": {
      "interface": "eth0",
      "num_workers": 4,
      "block_external_ping": true
    },
    "detection": {
      "enable_ids": true,
      "port_scan_threshold": 50
    }
  }
}
```

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8765');

ws.onopen = function() {
    console.log('Connected to SOC Firewall');
    
    // Subscribe to events
    ws.send(JSON.stringify({
        type: 'subscribe',
        events: ['alert', 'incident', 'packet']
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

### Message Types

#### Subscribe
```json
{
  "type": "subscribe",
  "events": ["alert", "incident", "packet"]
}
```

#### Heartbeat
```json
{
  "type": "heartbeat"
}
```

### Event Formats

#### Alert Event
```json
{
  "type": "alert",
  "data": {
    "alert_id": "ALT-1705123456-0001",
    "severity": "high",
    "title": "SQL Injection Attempt"
  },
  "timestamp": 1705317825.123
}
```

#### Incident Event
```json
{
  "type": "incident",
  "data": {
    "incident_id": "INC-1705123456",
    "severity": "high",
    "title": "SQL Injection Attack"
  },
  "timestamp": 1705317825.123
}
```

#### Packet Event
```json
{
  "type": "packet",
  "data": {
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "dst_port": 443,
    "size": 64
  },
  "timestamp": 1705317825.123
}
```

## Error Handling

### Error Responses

```json
{
  "error": "not_found",
  "message": "Rule not found"
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests |
| 500 | Internal Server Error |

### Rate Limiting

When rate limiting is enabled, responses include headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705317925
```

## SDK Examples

### Python

```python
import requests

class SOCFirewallClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {'Authorization': f'Bearer {token}'}
    
    def get_status(self):
        response = requests.get(
            f'{self.base_url}/status',
            headers=self.headers
        )
        return response.json()
    
    def get_alerts(self, severity=None):
        params = {'severity': severity} if severity else {}
        response = requests.get(
            f'{self.base_url}/alerts',
            headers=self.headers,
            params=params
        )
        return response.json()
    
    def quarantine_ip(self, ip, reason, duration):
        response = requests.post(
            f'{self.base_url}/quarantine/ip',
            headers=self.headers,
            json={
                'ip': ip,
                'reason': reason,
                'duration': duration
            }
        )
        return response.json()

# Usage
client = SOCFirewallClient(
    'http://localhost:5000/api/v1',
    'your-api-token'
)

status = client.get_status()
print(f"Firewall status: {status['status']}")

alerts = client.get_alerts(severity='high')
for alert in alerts['alerts']:
    print(f"Alert: {alert['title']}")
```

### JavaScript

```javascript
class SOCFirewallClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }
    
    async getStatus() {
        const response = await fetch(`${this.baseUrl}/status`, {
            headers: this.headers
        });
        return response.json();
    }
    
    async getAlerts(severity) {
        const url = severity 
            ? `${this.baseUrl}/alerts?severity=${severity}`
            : `${this.baseUrl}/alerts`;
        
        const response = await fetch(url, {
            headers: this.headers
        });
        return response.json();
    }
    
    async quarantineIP(ip, reason, duration) {
        const response = await fetch(`${this.baseUrl}/quarantine/ip`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({ ip, reason, duration })
        });
        return response.json();
    }
}

// Usage
const client = new SOCFirewallClient(
    'http://localhost:5000/api/v1',
    'your-api-token'
);

client.getStatus().then(status => {
    console.log(`Firewall status: ${status.status}`);
});
```

### curl Examples

```bash
# Get status
curl -H "Authorization: Bearer your-token" \
     http://localhost:5000/api/v1/status

# List rules
curl -H "Authorization: Bearer your-token" \
     http://localhost:5000/api/v1/rules

# Create rule
curl -X POST \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"name":"test","action":"DROP","conditions":[]}' \
     http://localhost:5000/api/v1/rules

# Quarantine IP
curl -X POST \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"ip":"1.2.3.4","reason":"malicious","duration":3600}' \
     http://localhost:5000/api/v1/quarantine/ip

# WebSocket connection
wscat -c ws://localhost:8765 \
      -H "Authorization: Bearer your-token"
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release |
| 1.1.0 | 2024-02-01 | Added WebSocket events |
| 1.2.0 | 2024-03-01 | Added threat intelligence endpoints |

## Support

For API support, contact:
- Email: soc@example.com
- Slack: #soc-firewall-support
- GitHub Issues: [link to issues]
