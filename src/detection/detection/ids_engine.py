import re
import time
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import threading
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SeverityLevel(Enum):
    """Severity levels for detected attacks"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AttackSignature:
    """Signature for attack detection"""
    id: str
    name: str
    description: str
    severity: SeverityLevel
    protocol: List[str]
    pattern: str
    pattern_type: str  # regex, exact, binary
    ports: List[int] = field(default_factory=list)
    reference: Optional[str] = None
    confidence: float = 0.8
    enabled: bool = True
    category: str = "generic"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "protocol": self.protocol,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "ports": self.ports,
            "reference": self.reference,
            "confidence": self.confidence,
            "category": self.category
        }


@dataclass
class DetectionResult:
    """Result of IDS inspection"""
    detected: bool
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.INFO
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    payload_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging"""
        return {
            "detected": self.detected,
            "signature_id": self.signature_id,
            "signature_name": self.signature_name,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "port": self.port,
            "metadata": self.metadata
        }


class IDSEngine:
    """
    Intrusion Detection System Engine
    Detects various network attacks using multiple detection methods
    
    Features:
    - Signature-based detection (regex patterns)
    - Protocol anomaly detection
    - Port scan detection
    - DoS/DDoS detection
    - Brute force detection
    - Custom rules support
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize IDS engine
        
        Args:
            config_path: Path to configuration file
        """
        self.signatures: List[AttackSignature] = []
        self.signatures_by_id: Dict[str, AttackSignature] = {}
        
        # Detection thresholds
        self.port_scan_threshold = 50  # ports per source
        self.syn_flood_threshold = 100  # SYNs per second
        self.dos_threshold = 1000  # packets per second
        self.bruteforce_threshold = 10  # attempts per minute
        self.icmp_flood_threshold = 50  # ICMP packets per second
        
        # Behavioral trackers
        self.port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self.syn_flood_tracker: Dict[str, List[float]] = defaultdict(list)
        self.dos_tracker: Dict[str, List[float]] = defaultdict(list)
        self.bruteforce_tracker: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.icmp_tracker: Dict[str, List[float]] = defaultdict(list)
        self.connection_rate_tracker: Dict[str, List[float]] = defaultdict(list)
        
        # Statistics
        self.stats = {
            "total_inspections": 0,
            "total_detections": 0,
            "detections_by_severity": defaultdict(int),
            "detections_by_signature": defaultdict(int),
            "false_positives": 0
        }
        
        self.lock = threading.RLock()
        
        # Load signatures
        self._load_default_signatures()
        if config_path:
            self.load_signatures_from_file(config_path)
        
        # Start cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="IDS-Cleanup"
        )
        self.cleanup_thread.start()
        
        logger.info(f"IDS Engine initialized with {len(self.signatures)} signatures")
    
    def _load_default_signatures(self) -> None:
        """Load default attack signatures"""
        default_signatures = [
            # SQL Injection signatures
            AttackSignature(
                id="SQLI-001",
                name="SQL Injection - UNION SELECT",
                description="UNION SELECT SQL injection attempt",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"(?i)union.*select.*from|select.*from.*where",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="sql_injection",
                confidence=0.85
            ),
            AttackSignature(
                id="SQLI-002",
                name="SQL Injection - OR/AND",
                description="OR/AND based SQL injection",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"(?i).*'.*or.*'='.*|.*'.*and.*'='.*",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="sql_injection",
                confidence=0.80
            ),
            AttackSignature(
                id="SQLI-003",
                name="SQL Injection - Comments",
                description="SQL comment injection",
                severity=SeverityLevel.MEDIUM,
                protocol=["TCP"],
                pattern=r"--+|#|/\*.*\*/",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="sql_injection",
                confidence=0.70
            ),
            
            # XSS signatures
            AttackSignature(
                id="XSS-001",
                name="Cross-Site Scripting - Script Tag",
                description="Script tag injection",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"(?i)<script.*>.*</script>",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="xss",
                confidence=0.95
            ),
            AttackSignature(
                id="XSS-002",
                name="Cross-Site Scripting - JavaScript Events",
                description="JavaScript event handler injection",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"(?i)onerror=|onload=|onclick=|onmouseover=|javascript:",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="xss",
                confidence=0.90
            ),
            AttackSignature(
                id="XSS-003",
                name="Cross-Site Scripting - Alert",
                description="JavaScript alert/prompt/confirm",
                severity=SeverityLevel.MEDIUM,
                protocol=["TCP"],
                pattern=r"(?i)alert\(|prompt\(|confirm\(",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="xss",
                confidence=0.85
            ),
            
            # Directory traversal signatures
            AttackSignature(
                id="DIR-001",
                name="Directory Traversal - Dot Dot Slash",
                description="Directory traversal using ../",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443, 21, 22],
                category="directory_traversal",
                confidence=0.95
            ),
            AttackSignature(
                id="DIR-002",
                name="Directory Traversal - System Files",
                description="Attempt to access system files",
                severity=SeverityLevel.CRITICAL,
                protocol=["TCP"],
                pattern=r"/(?:etc|proc|var|usr)/.*(?:passwd|shadow|config|password)",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443, 21, 22],
                category="directory_traversal",
                confidence=0.98
            ),
            
            # Command injection signatures
            AttackSignature(
                id="CMD-001",
                name="Command Injection - Shell Metacharacters",
                description="Shell command injection",
                severity=SeverityLevel.CRITICAL,
                protocol=["TCP"],
                pattern=r"[;&|`]|\$\(.*\)|\${.*}",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="command_injection",
                confidence=0.90
            ),
            AttackSignature(
                id="CMD-002",
                name="Command Injection - System Commands",
                description="Common system commands",
                severity=SeverityLevel.CRITICAL,
                protocol=["TCP"],
                pattern=r"(?i)(?:cat|ls|dir|wget|curl|nc|netcat|bash|sh|python|perl|ruby)\s+",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="command_injection",
                confidence=0.85
            ),
            
            # Path traversal in URLs
            AttackSignature(
                id="PATH-001",
                name="Path Traversal - Encoded",
                description="Encoded path traversal attempts",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"%2e%2e%2f|%252e%252e%252f|%%32%65%%32%65%%32%66",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="path_traversal",
                confidence=0.90
            ),
            
            # Shellshock signatures
            AttackSignature(
                id="SHELLSHOCK-001",
                name="Shellshock - Environment Variable",
                description="Shellshock vulnerability exploitation",
                severity=SeverityLevel.CRITICAL,
                protocol=["TCP"],
                pattern=r"\(\s*\)\s*\{",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="shellshock",
                confidence=0.95
            ),
            
            # Heartbleed detection (simplified)
            AttackSignature(
                id="HEARTBLEED-001",
                name="Heartbleed - TLS Heartbeat",
                description="Possible Heartbleed exploitation",
                severity=SeverityLevel.CRITICAL,
                protocol=["TCP"],
                pattern=r".*heartbeat.*",
                pattern_type="regex",
                ports=[443],
                category="heartbleed",
                confidence=0.70
            ),
            
            # Common web attacks
            AttackSignature(
                id="WEB-001",
                name="Web Attack - PHP Injection",
                description="PHP code injection attempt",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"(?i)(?:system|exec|passthru|shell_exec|eval)\(.*\)",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="web_attack",
                confidence=0.85
            ),
            AttackSignature(
                id="WEB-002",
                name="Web Attack - File Inclusion",
                description="Local/Remote file inclusion",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r"(?i)(?:include|require)(?:_once)?\s*\(.*(?:http|ftp|\.\./)",
                pattern_type="regex",
                ports=[80, 443, 8080, 8443],
                category="web_attack",
                confidence=0.80
            ),
            
            # Buffer overflow attempts
            AttackSignature(
                id="BOF-001",
                name="Buffer Overflow - Long String",
                description="Unusually long string (potential buffer overflow)",
                severity=SeverityLevel.HIGH,
                protocol=["TCP"],
                pattern=r".{500,}",  # 500+ characters
                pattern_type="regex",
                ports=[80, 443, 21, 22, 25, 110],
                category="buffer_overflow",
                confidence=0.60
            )
        ]
        
        for sig in default_signatures:
            self.add_signature(sig)
    
    def add_signature(self, signature: AttackSignature) -> None:
        """Add a signature to the engine"""
        with self.lock:
            self.signatures.append(signature)
            self.signatures_by_id[signature.id] = signature
        logger.debug(f"Added signature: {signature.id} - {signature.name}")
    
    def load_signatures_from_file(self, filepath: str) -> int:
        """
        Load signatures from JSON/YAML file
        
        Args:
            filepath: Path to signature file
            
        Returns:
            Number of signatures loaded
        """
        try:
            path = Path(filepath)
            if not path.exists():
                logger.warning(f"Signature file not found: {filepath}")
                return 0
            
            with open(path, 'r') as f:
                if filepath.endswith('.json'):
                    data = json.load(f)
                else:
                    import yaml
                    data = yaml.safe_load(f)
            
            count = 0
            for sig_data in data.get('signatures', []):
                try:
                    signature = AttackSignature(
                        id=sig_data['id'],
                        name=sig_data['name'],
                        description=sig_data.get('description', ''),
                        severity=SeverityLevel(sig_data.get('severity', 'medium')),
                        protocol=sig_data.get('protocol', ['TCP']),
                        pattern=sig_data['pattern'],
                        pattern_type=sig_data.get('pattern_type', 'regex'),
                        ports=sig_data.get('ports', []),
                        reference=sig_data.get('reference'),
                        confidence=sig_data.get('confidence', 0.8),
                        category=sig_data.get('category', 'generic')
                    )
                    self.add_signature(signature)
                    count += 1
                except Exception as e:
                    logger.error(f"Error loading signature: {e}")
            
            logger.info(f"Loaded {count} signatures from {filepath}")
            return count
            
        except Exception as e:
            logger.error(f"Error loading signatures from {filepath}: {e}")
            return 0
    
    def inspect_packet(self, packet_metadata, payload: Optional[bytes] = None) -> DetectionResult:
        """
        Inspect a packet for attacks
        
        Args:
            packet_metadata: Packet metadata
            payload: Raw packet payload
            
        Returns:
            DetectionResult
        """
        with self.lock:
            self.stats["total_inspections"] += 1
        
        result = DetectionResult(
            detected=False,
            src_ip=packet_metadata.src_ip,
            dst_ip=packet_metadata.dst_ip,
            protocol=packet_metadata.protocol,
            port=packet_metadata.dst_port,
            timestamp=time.time()
        )
        
        # 1. Check behavioral anomalies
        behavioral_result = self._check_behavioral_anomalies(packet_metadata)
        if behavioral_result.detected:
            return behavioral_result
        
        # 2. Check signatures if payload exists
        if payload:
            signature_result = self._check_signatures(packet_metadata, payload)
            if signature_result.detected:
                return signature_result
        
        # 3. Check protocol anomalies
        protocol_result = self._check_protocol_anomalies(packet_metadata)
        if protocol_result.detected:
            return protocol_result
        
        return result
    
    def _check_signatures(self, packet_metadata, payload: bytes) -> DetectionResult:
        """
        Check packet against signatures
        
        Args:
            packet_metadata: Packet metadata
            payload: Packet payload
            
        Returns:
            DetectionResult
        """
        try:
            # Convert payload to string for regex matching (if text)
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                payload_str = payload.hex()
            
            # Check each signature
            for signature in self.signatures:
                if not signature.enabled:
                    continue
                
                # Check protocol match
                if packet_metadata.protocol not in signature.protocol:
                    continue
                
                # Check port match (if specified)
                if signature.ports and packet_metadata.dst_port not in signature.ports:
                    continue
                
                # Apply pattern matching
                matched = False
                if signature.pattern_type == "regex":
                    if re.search(signature.pattern, payload_str, re.IGNORECASE):
                        matched = True
                elif signature.pattern_type == "exact":
                    if signature.pattern.encode() in payload:
                        matched = True
                elif signature.pattern_type == "binary":
                    pattern_bytes = bytes.fromhex(signature.pattern.replace(' ', ''))
                    if pattern_bytes in payload:
                        matched = True
                
                if matched:
                    # Create detection result
                    result = DetectionResult(
                        detected=True,
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        confidence=signature.confidence,
                        src_ip=packet_metadata.src_ip,
                        dst_ip=packet_metadata.dst_ip,
                        protocol=packet_metadata.protocol,
                        port=packet_metadata.dst_port,
                        payload_snippet=payload_str[:100] + "..." if len(payload_str) > 100 else payload_str,
                        metadata={
                            "pattern": signature.pattern,
                            "category": signature.category
                        }
                    )
                    
                    # Update statistics
                    with self.lock:
                        self.stats["total_detections"] += 1
                        self.stats["detections_by_severity"][signature.severity.value] += 1
                        self.stats["detections_by_signature"][signature.id] += 1
                    
                    logger.warning(f"IDS Detection: {signature.name} from {packet_metadata.src_ip}")
                    return result
            
        except Exception as e:
            logger.error(f"Error in signature check: {e}")
        
        return DetectionResult(detected=False)
    
    def _check_behavioral_anomalies(self, packet_metadata) -> DetectionResult:
        """
        Check for behavioral anomalies (port scans, DoS, etc.)
        
        Args:
            packet_metadata: Packet metadata
            
        Returns:
            DetectionResult
        """
        src_ip = packet_metadata.src_ip
        dst_port = packet_metadata.dst_port
        protocol = packet_metadata.protocol
        flags = packet_metadata.flags
        current_time = time.time()
        
        # Clean old entries
        self._cleanup_trackers(current_time)
        
        # 1. Port scan detection
        if dst_port:
            self.port_scan_tracker[src_ip].add(dst_port)
            if len(self.port_scan_tracker[src_ip]) > self.port_scan_threshold:
                return DetectionResult(
                    detected=True,
                    signature_id="BEH-001",
                    signature_name="Port Scan Detected",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    src_ip=src_ip,
                    protocol=protocol,
                    metadata={"ports_scanned": len(self.port_scan_tracker[src_ip])}
                )
        
        # 2. SYN flood detection
        if protocol == "TCP" and 'SYN' in flags and 'ACK' not in flags:
            self.syn_flood_tracker[src_ip].append(current_time)
            recent_syn = [t for t in self.syn_flood_tracker[src_ip] if current_time - t <= 1]
            if len(recent_syn) > self.syn_flood_threshold:
                return DetectionResult(
                    detected=True,
                    signature_id="BEH-002",
                    signature_name="SYN Flood Detected",
                    severity=SeverityLevel.HIGH,
                    confidence=0.95,
                    src_ip=src_ip,
                    protocol=protocol,
                    metadata={"syn_rate": len(recent_syn)}
                )
        
        # 3. DoS detection
        self.dos_tracker[src_ip].append(current_time)
        recent_packets = [t for t in self.dos_tracker[src_ip] if current_time - t <= 1]
        if len(recent_packets) > self.dos_threshold:
            return DetectionResult(
                detected=True,
                signature_id="BEH-003",
                signature_name="DoS Attack Detected",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                src_ip=src_ip,
                protocol=protocol,
                metadata={"packet_rate": len(recent_packets)}
            )
        
        # 4. ICMP flood detection
        if protocol == "ICMP":
            self.icmp_tracker[src_ip].append(current_time)
            recent_icmp = [t for t in self.icmp_tracker[src_ip] if current_time - t <= 1]
            if len(recent_icmp) > self.icmp_flood_threshold:
                return DetectionResult(
                    detected=True,
                    signature_id="BEH-004",
                    signature_name="ICMP Flood Detected",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.85,
                    src_ip=src_ip,
                    protocol=protocol,
                    metadata={"icmp_rate": len(recent_icmp)}
                )
        
        return DetectionResult(detected=False)
    
    def _check_protocol_anomalies(self, packet_metadata) -> DetectionResult:
        """
        Check for protocol anomalies
        
        Args:
            packet_metadata: Packet metadata
            
        Returns:
            DetectionResult
        """
        # TCP anomalies
        if packet_metadata.protocol == "TCP":
            flags = packet_metadata.flags
            
            # Check for invalid flag combinations
            if 'SYN' in flags and 'FIN' in flags:
                return DetectionResult(
                    detected=True,
                    signature_id="PROTO-001",
                    signature_name="Invalid TCP Flags (SYN+FIN)",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.95,
                    src_ip=packet_metadata.src_ip,
                    protocol="TCP",
                    metadata={"flags": flags}
                )
            
            if 'RST' in flags and 'ACK' not in flags:
                # RST without ACK is unusual
                return DetectionResult(
                    detected=True,
                    signature_id="PROTO-002",
                    signature_name="TCP RST without ACK",
                    severity=SeverityLevel.LOW,
                    confidence=0.7,
                    src_ip=packet_metadata.src_ip,
                    protocol="TCP",
                    metadata={"flags": flags}
                )
        
        # ICMP anomalies
        elif packet_metadata.protocol == "ICMP":
            # Check for large ICMP packets (potential covert channel)
            if packet_metadata.packet_size > 1000:
                return DetectionResult(
                    detected=True,
                    signature_id="PROTO-003",
                    signature_name="Large ICMP Packet",
                    severity=SeverityLevel.LOW,
                    confidence=0.6,
                    src_ip=packet_metadata.src_ip,
                    protocol="ICMP",
                    metadata={"size": packet_metadata.packet_size}
                )
        
        return DetectionResult(detected=False)
    
    def detect_bruteforce(self, src_ip: str, service: str) -> DetectionResult:
        """
        Detect brute force attacks
        
        Args:
            src_ip: Source IP
            service: Service being attacked (ssh, ftp, http, etc.)
            
        Returns:
            DetectionResult
        """
        current_time = time.time()
        
        with self.lock:
            self.bruteforce_tracker[src_ip].append((current_time, service))
            
            # Count attempts in last minute
            recent_attempts = [
                (t, s) for t, s in self.bruteforce_tracker[src_ip]
                if current_time - t <= 60 and s == service
            ]
            
            if len(recent_attempts) > self.bruteforce_threshold:
                return DetectionResult(
                    detected=True,
                    signature_id="BEH-005",
                    signature_name=f"Brute Force Attack - {service.upper()}",
                    severity=SeverityLevel.HIGH,
                    confidence=0.9,
                    src_ip=src_ip,
                    metadata={
                        "service": service,
                        "attempts": len(recent_attempts),
                        "time_window": 60
                    }
                )
        
        return DetectionResult(detected=False)
    
    def _cleanup_trackers(self, current_time: float) -> None:
        """Remove old entries from behavioral trackers"""
        # Clean port scan tracker (keep for 5 minutes)
        for ip in list(self.port_scan_tracker.keys()):
            if len(self.port_scan_tracker[ip]) > 1000:
                # Reset if too many ports (probably scanning)
                self.port_scan_tracker[ip] = set()
        
        # Clean SYN flood tracker
        for ip in list(self.syn_flood_tracker.keys()):
            self.syn_flood_tracker[ip] = [
                t for t in self.syn_flood_tracker[ip]
                if current_time - t <= 10
            ]
            if not self.syn_flood_tracker[ip]:
                del self.syn_flood_tracker[ip]
        
        # Clean DoS tracker
        for ip in list(self.dos_tracker.keys()):
            self.dos_tracker[ip] = [
                t for t in self.dos_tracker[ip]
                if current_time - t <= 5
            ]
            if not self.dos_tracker[ip]:
                del self.dos_tracker[ip]
        
        # Clean ICMP tracker
        for ip in list(self.icmp_tracker.keys()):
            self.icmp_tracker[ip] = [
                t for t in self.icmp_tracker[ip]
                if current_time - t <= 5
            ]
            if not self.icmp_tracker[ip]:
                del self.icmp_tracker[ip]
    
    def _cleanup_loop(self) -> None:
        """Periodic cleanup of behavioral trackers"""
        while self.running:
            time.sleep(60)
            current_time = time.time()
            self._cleanup_trackers(current_time)
    
    def get_statistics(self) -> Dict:
        """Get IDS statistics"""
        with self.lock:
            return {
                "total_inspections": self.stats["total_inspections"],
                "total_detections": self.stats["total_detections"],
                "detection_rate": (self.stats["total_detections"] / max(1, self.stats["total_inspections"])) * 100,
                "detections_by_severity": dict(self.stats["detections_by_severity"]),
                "detections_by_signature": dict(self.stats["detections_by_signature"]),
                "active_signatures": len(self.signatures),
                "false_positives": self.stats["false_positives"]
            }
    
    def shutdown(self) -> None:
        """Shutdown IDS engine"""
        logger.info("Shutting down IDS engine...")
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        logger.info("IDS engine stopped")
