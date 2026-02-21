# SOC Firewall Architecture

## Overview

SOC Firewall is a high-performance, modular network security system designed for enterprise environments. It provides real-time packet inspection, intrusion detection, automated threat response, and comprehensive monitoring capabilities.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         External Network                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Network Interface   │
                    │       (eth0)          │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────┐
│                         CORE LAYER                                 │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                    Packet Engine                              │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │  │
│  │  │    Capture   │─▶│   Process    │─▶│   Filter     │      │  │
│  │  │   (Scapy)    │  │   Workers    │  │   Rules      │      │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │  │
│  │                          │                                   │  │
│  │                          ▼                                   │  │
│  │              ┌─────────────────────┐                        │  │
│  │              │ Connection Tracker  │                        │  │
│  │              │   (Stateful)        │                        │  │
│  │              └─────────────────────┘                        │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                  │                                  │
│                                  ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                     DETECTION LAYER                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │  │
│  │  │     IDS      │  │   Threat     │  │   Anomaly    │      │  │
│  │  │   Engine     │  │ Intelligence │  │   Detector   │      │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                  │                                  │
│                                  ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                     RESPONSE LAYER                            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │  │
│  │  │    Alert     │  │   Incident   │  │  Quarantine  │      │  │
│  │  │   Manager    │  │   Handler    │  │   Manager    │      │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │     Management API     │
                    │   (REST + WebSocket)   │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────┐
│                      EXTERNAL INTEGRATIONS                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │    SIEM      │  │   Ticketing   │  │  Notification│           │
│  │  (Splunk/ELK)│  │   (Jira)     │  │  (Slack/Email)│           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Packet Engine

The Packet Engine is the heart of the system, responsible for capturing and processing network packets.

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Packet Engine                           │
├─────────────────────────────────────────────────────────────┤
│                      Capture Queue                            │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐          │
│  │Pkt 1│ │Pkt 2│ │Pkt 3│ │Pkt 4│ │Pkt 5│ │Pkt 6│          │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘          │
├─────────────────────────────────────────────────────────────┤
│                   Worker Thread Pool                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Worker 1   │  │   Worker 2   │  │   Worker 3   │      │
│  │  (Analysis)  │  │  (Analysis)  │  │  (Analysis)  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
├─────────────────────────────────────────────────────────────┤
│                    Filter Pipeline                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  │  Rule 1 │→│  Rule 2 │→│  Rule 3 │→│  Rule N │          │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘          │
└─────────────────────────────────────────────────────────────┘
```

**Key Features**:
- Multi-threaded packet capture using Scapy
- Configurable worker pool for parallel processing
- Lock-free queues for high throughput
- Zero-copy packet metadata extraction
- Support for multiple capture sources

**Class Diagram**:

```python
class PacketProcessor:
    - interface: str
    - num_workers: int
    - packet_queue: Queue
    - stats: Dict
    + start()
    + stop()
    + process_packet(packet)
    
class PacketMetadata:
    - timestamp: float
    - src_ip: str
    - dst_ip: str
    - protocol: str
    - flags: List[str]
    - packet_size: int
    + to_dict()
```

### 2. Connection Tracker

Stateful connection tracking system implementing full TCP state machine.

#### State Machine

```
                    ┌─────────┐
                    │  CLOSED │
                    └────┬────┘
                         │ SYN
                    ┌────▼────┐
                    │ SYN_SENT│
                    └────┬────┘
                         │ SYN+ACK
                    ┌────▼────┐
                    │ESTABLISHED│
                    └────┬────┘
                    ┌────┴────┐
                    │  FIN    │
                    └────┬────┘
               ┌─────────┴─────────┐
         ┌─────▼─────┐       ┌─────▼─────┐
         │ FIN_WAIT_1│       │ CLOSE_WAIT│
         └─────┬─────┘       └─────┬─────┘
               │ ACK                │ FIN
         ┌─────▼─────┐       ┌─────▼─────┐
         │ FIN_WAIT_2│       │  LAST_ACK │
         └─────┬─────┘       └─────┬─────┘
               │ FIN                │ ACK
         ┌─────▼─────┐       ┌─────▼─────┐
         │ TIME_WAIT │       │   CLOSED  │
         └───────────┘       └───────────┘
```

**Data Structures**:

```python
class ConnectionTracker:
    - connections: Dict[str, ConnectionEntry]
    - timeouts: Dict[ConnectionState, int]
    - stats: Dict
    + get_or_create_connection()
    + update_connection_state()
    + cleanup_expired()
    
class ConnectionEntry:
    - protocol: ConnectionProtocol
    - src_ip: str
    - dst_ip: str
    - src_port: int
    - dst_port: int
    - state: ConnectionState
    - first_seen: float
    - last_seen: float
    - packets_forward: int
    - packets_reverse: int
```

### 3. Filter Rules Engine

Rule-based filtering system with condition matching and priority ordering.

#### Rule Structure

```yaml
Rule:
  name: string
  action: ALLOW|DROP|REJECT|LOG|ALERT
  priority: int
  enabled: boolean
  conditions: List[Condition]
  
Condition:
  field: string
  operator: eq|ne|gt|lt|in|contains|matches|cidr
  value: any
```

**Matching Algorithm**:
1. Rules sorted by priority
2. Packet checked against each enabled rule
3. First matching rule determines action
4. Default action if no match

**Performance**:
- O(n) where n = number of rules
- Rule caching for frequent packets
- Optimized condition evaluation

### 4. IDS Engine

Multi-layered intrusion detection with signature matching and behavioral analysis.

#### Detection Layers

```
┌─────────────────────────────────────────────────────────────┐
│                     IDS Engine                               │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Signature Matching                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ • SQL Injection patterns                             │   │
│  │ • XSS patterns                                       │   │
│  │ • Directory traversal                                │   │
│  │ • Command injection                                  │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Behavioral Analysis                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ • Port scan detection                               │   │
│  │ • SYN flood detection                               │   │
│  │ • DoS detection                                     │   │
│  │ • Brute force detection                             │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Protocol Analysis                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ • TCP flag anomalies                                │   │
│  │ • ICMP anomalies                                    │   │
│  │ • Protocol violations                               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Signature Format**:

```python
class AttackSignature:
    - id: str
    - name: str
    - severity: SeverityLevel
    - protocol: List[str]
    - pattern: str
    - pattern_type: str  # regex, exact, binary
    - ports: List[int]
    - confidence: float
```

**Behavioral Trackers**:
- Port scan: `Dict[str, Set[int]]`
- SYN flood: `Dict[str, List[float]]`
- DoS: `Dict[str, List[float]]`
- Brute force: `Dict[str, List[Tuple[float, str]]]`

### 5. Threat Intelligence

Integration with external threat feeds for IP reputation.

#### Feed Processing Pipeline

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Download │───▶│  Parse   │───▶│ Validate │───▶│   Store  │
│   Feed   │    │          │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

**Database Schema**:

```sql
CREATE TABLE indicators (
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    expires REAL,
    tags TEXT,
    UNIQUE(value, type, source)
);

CREATE INDEX idx_value ON indicators(value);
CREATE INDEX idx_expires ON indicators(expires);
```

### 6. Alert Manager

Alert generation and notification system with multi-channel support.

#### Alert Flow

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Detection│───▶│  Create  │───▶│   Route  │───▶│  Notify  │
│  Event   │    │  Alert   │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                      │
                            ┌─────────┴─────────┐
                            ▼                   ▼
                    ┌──────────────┐    ┌──────────────┐
                    │    Email     │    │    Slack     │
                    └──────────────┘    └──────────────┘
                            ▼                   ▼
                    ┌──────────────┐    ┌──────────────┐
                    │   Webhook    │    │    PagerDuty │
                    └──────────────┘    └──────────────┘
```

**Alert Structure**:

```python
class Alert:
    - id: str
    - timestamp: float
    - source: str
    - severity: AlertSeverity
    - title: str
    - message: str
    - signature_id: Optional[str]
    - src_ip: Optional[str]
    - dst_ip: Optional[str]
    - acknowledged: bool
```

### 7. Incident Handler

Automated incident response with playbook execution.

#### Incident Lifecycle

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Create  │───▶│Investigate│───▶│ Contain  │───▶│  Resolve │
│ Incident │    │          │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │
     ▼               ▼               ▼               ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   New    │    │Investig- │    │Contained │    │ Resolved │
│          │    │  ating   │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

**Playbook Example**:

```yaml
name: "quarantine_malicious_ip"
triggers:
  - type: "severity"
    value: "high"
steps:
  - action: "quarantine_ip"
    params:
      duration: 3600
  - action: "notify_soc"
    params:
      channel: "slack"
  - action: "create_ticket"
    params:
      priority: "high"
```

### 8. Quarantine Manager

IP and subnet isolation with automatic expiration.

#### Quarantine Database

```sql
CREATE TABLE quarantine (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp REAL NOT NULL,
    expires REAL,
    description TEXT,
    active INTEGER DEFAULT 1
);

CREATE INDEX idx_target ON quarantine(target);
CREATE INDEX idx_expires ON quarantine(expires);
```

### 9. REST API

Flask-based REST API for management and monitoring.

#### API Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       REST API                               │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Routes      │  │  Middleware  │  │  Handlers    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Auth        │  │ Rate Limit   │  │    CORS      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

**Middleware Pipeline**:
1. Authentication
2. Rate limiting
3. Request logging
4. CORS handling
5. Error handling

### 10. WebSocket Server

Real-time event streaming using WebSockets.

#### Connection Management

```
┌─────────────────────────────────────────────────────────────┐
│                    WebSocket Server                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Client 1   │  │   Client 2   │  │   Client 3   │      │
│  │ (subscribed) │  │ (subscribed) │  │ (subscribed) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
├─────────────────────────────────────────────────────────────┤
│                    Broadcast Manager                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Alert Events │  │IncidentEvents│  │ Packet Events│      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### Packet Processing Pipeline

```
1. Capture
   ↓
2. Extract Metadata
   ↓
3. Connection Tracking
   ↓
4. IDS Inspection
   ↓
5. Rule Matching
   ↓
6. Action Decision
   ↓
7. Response (Allow/Block/Alert)
   ↓
8. Logging
```

### Alert Flow

```
1. Detection Event
   ↓
2. Alert Creation
   ↓
3. Enrichment (add context)
   ↓
4. Severity Assessment
   ↓
5. Channel Routing
   ↓
6. Notification
   ↓
7. Storage
```

## Performance Considerations

### Threading Model

```
┌─────────────────────────────────────────────────────────────┐
│                      Main Thread                             │
│  • Configuration management                                 │
│  • API server                                               │
│  • Health checks                                            │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Capture Thread│    │Worker Pool    │    │ Alert Thread  │
│ • Sniff       │    │• Process      │    │• Notify       │
│ • Queue       │    │• Filter       │    │• Route        │
└───────────────┘    └───────────────┘    └───────────────┘
```

### Queue Sizes

| Queue | Default Size | Purpose |
|-------|--------------|---------|
| Packet Queue | 10,000 | Incoming packets |
| Alert Queue | 1,000 | Alerts awaiting processing |
| Event Queue | 5,000 | WebSocket events |

### Performance Targets

| Metric | Target |
|--------|--------|
| Packets per second | 100,000+ |
| Connection tracking | 1,000,000+ |
| Alert latency | < 100ms |
| API response time | < 50ms |
| Memory usage | < 1GB baseline |

## Security Architecture

### Defense in Depth

```
Layer 1: Network Interface
    • Promiscuous mode
    • Hardware offloading
    
Layer 2: Packet Filtering
    • Stateful inspection
    • Rule-based filtering
    
Layer 3: Intrusion Detection
    • Signature matching
    • Behavioral analysis
    
Layer 4: Threat Intelligence
    • External feeds
    • Reputation scoring
    
Layer 5: Automated Response
    • Quarantine
    • Alerting
```

### Authentication & Authorization

```python
class AuthManager:
    - tokens: Dict[str, TokenData]
    + validate_token(token)
    + check_permission(token, resource)
    + rate_limit(client_ip)
```

### Data Protection

- TLS for API endpoints
- Encrypted configuration secrets
- Hashed audit logs
- Secure credential storage

## Scalability

### Horizontal Scaling

```
┌─────────────────────────────────────────────────────────────┐
│                      Load Balancer                           │
└─────────────────────────────────────────────────────────────┘
              │                 │                 │
        ┌─────▼─────┐     ┌─────▼─────┐     ┌─────▼─────┐
        │  Node 1   │     │  Node 2   │     │  Node 3   │
        │(active)   │     │(active)   │     │(active)   │
        └───────────┘     └───────────┘     └───────────┘
              │                 │                 │
        ┌─────┴─────────────────┴─────────────────┴─────┐
        │              Distributed Cache                  │
        │                   (Redis)                       │
        └─────────────────────────────────────────────────┘
```

### Vertical Scaling

- Increase worker threads
- Larger queue sizes
- More connection tracking
- Bigger memory allocation

## Monitoring & Observability

### Metrics Collected

| Category | Metrics |
|----------|---------|
| System | CPU, Memory, Disk, Network |
| Packet | Packets/sec, Drops, Errors |
| Connections | Active, New, Closed |
| Detection | Alerts, Signatures, Sources |
| API | Requests, Latency, Errors |

### Health Checks

```python
def health_check():
    checks = [
        check_service_running(),
        check_interface_up(),
        check_disk_space(),
        check_memory_usage(),
        check_api_responding()
    ]
    return all(checks)
```

## Deployment Architecture

### Single Node

```
┌─────────────────────────────────────┐
│         Single Server                │
│  ┌───────────────────────────────┐  │
│  │    SOC Firewall Instance      │  │
│  │  • Packet Engine              │  │
│  │  • Detection                  │  │
│  │  • Response                   │  │
│  │  • API                        │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### Distributed

```
┌─────────────────────────────────────────────────────────────┐
│                      Management Network                      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Sensor Node 1│    │ Sensor Node 2│    │ Sensor Node N│  │
│  │ • Capture    │    │ • Capture    │    │ • Capture    │  │
│  │ • Detection  │    │ • Detection  │    │ • Detection  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│           │                  │                  │           │
│           └──────────────────┼──────────────────┘           │
│                              ▼                              │
│                    ┌──────────────────┐                     │
│                    │  Central Server  │                     │
│                    │ • Correlation    │                     │
│                    │ • Response       │                     │
│                    │ • API            │                     │
│                    └──────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Packet Capture | Scapy | Network packet manipulation |
| Web Framework | Flask | REST API |
| Real-time | WebSockets | Event streaming |
| Database | SQLite/PostgreSQL | Data persistence |
| Caching | Redis | Rate limiting, sessions |
| Serialization | JSON, YAML | Configuration |
| Monitoring | Prometheus | Metrics |
| Logging | Python logging | Audit trail |
| Testing | pytest | Unit/integration tests |
| Container | Docker | Deployment |

## Design Decisions

### Why Scapy?
- Comprehensive packet manipulation
- Protocol support
- Active community
- Python integration

### Why Flask?
- Lightweight
- Extensible
- Well-documented
- Production-ready

### Why SQLite?
- Zero configuration
- ACID compliance
- Good performance
- Built-in Python support

### Why Multi-threaded?
- Efficient CPU utilization
- Parallel processing
- Queue-based architecture
- Scalability

## Error Handling

### Strategy
1. Graceful degradation
2. Comprehensive logging
3. Automatic recovery
4. Alert on critical errors

### Error Categories

```python
class ErrorCategory(Enum):
    NETWORK = "network_error"
    CONFIG = "configuration_error"
    RESOURCE = "resource_exhaustion"
    SECURITY = "security_violation"
    INTERNAL = "internal_error"
```

## Development Workflow

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Feature │───▶│   Code   │───▶│   Test   │───▶│  Review  │
│  Branch  │    │          │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                    │
                                              ┌─────▼─────┐
                                              │   Merge   │
                                              │ to Main   │
                                              └───────────┘
```

## Versioning

- **Major**: Breaking changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../LICENSE) file.
