"""
Packet Engine Module
Core packet processing engine for SOC firewall
"""

import socket
import struct
import threading
import queue
import time
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from collections import defaultdict
import hashlib

from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from scapy.error import Scapy_Exception

from src.utils.logger import get_logger
from src.config.settings import config
from src.core.connection_tracker import ConnectionTracker, ConnectionState
from src.detection.ids_engine import IDSEngine
from src.response.incident_handler import IncidentHandler

logger = get_logger(__name__)

class PacketAction(Enum):
    """Actions to take on packets"""
    ALLOW = "allow"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    ALERT = "alert"
    QUARANTINE = "quarantine"

@dataclass
class PacketMetadata:
    """Comprehensive packet metadata"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "unknown"
    ttl: int = 0
    flags: List[str] = field(default_factory=list)
    packet_size: int = 0
    payload_hash: Optional[str] = None
    interface: str = ""
    vlan_id: Optional[int] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging"""
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "ttl": self.ttl,
            "flags": self.flags,
            "packet_size": self.packet_size,
            "interface": self.interface,
            "vlan_id": self.vlan_id
        }

class PacketProcessor:
    """
    High-performance packet processing engine
    Implements multi-threaded packet handling with configurable pipelines
    """
    
    def __init__(self, interface: str = "eth0", config_path: Optional[str] = None):
        """
        Initialize the packet processor
        
        Args:
            interface: Network interface to monitor
            config_path: Optional custom configuration path
        """
        self.interface = interface
        self.running = False
        self.processor_id = hashlib.md5(f"{interface}_{time.time()}".encode()).hexdigest()[:8]
        
        # Processing queues
        self.packet_queue = queue.Queue(maxsize=10000)
        self.alert_queue = queue.Queue(maxsize=1000)
        
        # Statistics
        self.stats = {
            "packets_received": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "packets_allowed": 0,
            "packets_blocked": 0,
            "alerts_generated": 0,
            "processing_errors": 0
        }
        
        # Lock for thread-safe operations
        self.stats_lock = threading.Lock()
        
        # Initialize components
        self.connection_tracker = ConnectionTracker()
        self.ids_engine = IDSEngine()
        self.incident_handler = IncidentHandler()
        
        # Load configuration
        self._load_configuration()
        
        # Initialize filter chains
        self.filter_chains = self._initialize_filter_chains()
        
        # Threat intelligence cache
        self.threat_intel_cache = {}
        self._load_threat_intelligence()
        
        logger.info(f"Packet Processor initialized on interface {interface} [ID: {self.processor_id}]")
    
    def _load_configuration(self) -> None:
        """Load processor configuration"""
        self.buffer_size = config.get("packet_engine.buffer_size", 65536)
        self.promiscuous_mode = config.get("packet_engine.promiscuous", False)
        self.snapshot_length = config.get("packet_engine.snapshot_length", 0)
        self.timeout = config.get("packet_engine.timeout", None)
        
        # Filtering rules
        self.block_external_ping = config.get("filtering.block_external_ping", True)
        self.internal_networks = config.get("network.internal_ranges", [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8"
        ])
        
        # Performance tuning
        self.num_workers = config.get("performance.num_workers", 4)
        self.queue_timeout = config.get("performance.queue_timeout", 1.0)
    
    def _initialize_filter_chains(self) -> Dict:
        """Initialize packet filter chains"""
        return {
            "pre_filter": [],
            "inspection": [],
            "post_filter": [],
            "alert": []
        }
    
    def _load_threat_intelligence(self) -> None:
        """Load threat intelligence feeds"""
        try:
            # Load known malicious IPs
            threat_file = config.get("threat_intel.malicious_ips", "/etc/soc-firewall/threats/malicious_ips.txt")
            with open(threat_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.threat_intel_cache[ip] = {
                            "source": "threat_feed",
                            "confidence": 0.9,
                            "timestamp": time.time()
                        }
            logger.info(f"Loaded {len(self.threat_intel_cache)} threat intelligence entries")
        except Exception as e:
            logger.warning(f"Could not load threat intelligence: {e}")
    
    def extract_packet_metadata(self, packet) -> Optional[PacketMetadata]:
        """
        Extract comprehensive metadata from packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            PacketMetadata object or None if extraction fails
        """
        try:
            if IP not in packet:
                return None
            
            ip_layer = packet[IP]
            
            metadata = PacketMetadata(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                ttl=ip_layer.ttl,
                packet_size=len(packet),
                interface=self.interface
            )
            
            # Determine protocol and extract transport layer info
            if TCP in packet:
                tcp_layer = packet[TCP]
                metadata.protocol = "TCP"
                metadata.src_port = tcp_layer.sport
                metadata.dst_port = tcp_layer.dport
                metadata.flags = self._extract_tcp_flags(tcp_layer)
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                metadata.protocol = "UDP"
                metadata.src_port = udp_layer.sport
                metadata.dst_port = udp_layer.dport
                
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                metadata.protocol = "ICMP"
                metadata.flags = [f"type={icmp_layer.type}", f"code={icmp_layer.code}"]
            
            # Extract payload hash for deep inspection
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                metadata.payload_hash = hashlib.sha256(payload).hexdigest()[:16]
            
            # Extract VLAN tag if present
            if Ether in packet and packet[Ether].type == 0x8100:
                metadata.vlan_id = (packet[Ether].payload.vlan & 0xFFF)
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting packet metadata: {e}")
            return None
    
    def _extract_tcp_flags(self, tcp_layer) -> List[str]:
        """Extract TCP flags from packet"""
        flags = []
        if tcp_layer.flags & 0x01:
            flags.append('FIN')
        if tcp_layer.flags & 0x02:
            flags.append('SYN')
        if tcp_layer.flags & 0x04:
            flags.append('RST')
        if tcp_layer.flags & 0x08:
            flags.append('PSH')
        if tcp_layer.flags & 0x10:
            flags.append('ACK')
        if tcp_layer.flags & 0x20:
            flags.append('URG')
        if tcp_layer.flags & 0x40:
            flags.append('ECE')
        if tcp_layer.flags & 0x80:
            flags.append('CWR')
        return flags
    
    def is_internal_ip(self, ip_address: str) -> bool:
        """
        Check if IP address belongs to internal network
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if internal, False otherwise
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            for network in self.internal_networks:
                if ip in ipaddress.IPv4Network(network):
                    return True
            return False
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Invalid IP address format: {ip_address} - {e}")
            return False
    
    def check_threat_intelligence(self, ip_address: str) -> Optional[Dict]:
        """
        Check IP against threat intelligence feeds
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Threat information if found, None otherwise
        """
        if ip_address in self.threat_intel_cache:
            threat_info = self.threat_intel_cache[ip_address]
            # Check if threat info is still valid (e.g., not expired)
            if time.time() - threat_info.get("timestamp", 0) < 86400:  # 24 hours
                return threat_info
        return None
    
    def should_block_ping(self, metadata: PacketMetadata) -> Tuple[bool, str]:
        """
        Determine if ICMP echo request should be blocked
        
        Args:
            metadata: Packet metadata
            
        Returns:
            Tuple of (should_block, reason)
        """
        if not self.block_external_ping:
            return False, "ping_blocking_disabled"
        
        if metadata.protocol != "ICMP":
            return False, "not_icmp"
        
        # ICMP type 8 is echo request (ping)
        if "type=8" in metadata.flags:
            # Allow internal ping
            if self.is_internal_ip(metadata.src_ip):
                return False, "internal_ping"
            
            # Check if source is in threat intel
            threat_info = self.check_threat_intelligence(metadata.src_ip)
            if threat_info:
                return True, f"threat_intelligence_{threat_info['source']}"
            
            # Block external ping
            return True, "external_ping_blocked"
        
        return False, "non_ping_icmp"
    
    def apply_filter_rules(self, metadata: PacketMetadata) -> Tuple[PacketAction, str]:
        """
        Apply configured filter rules to packet
        
        Args:
            metadata: Packet metadata
            
        Returns:
            Tuple of (action, reason)
        """
        # Priority 1: Threat intelligence check
        threat_info = self.check_threat_intelligence(metadata.src_ip)
        if threat_info:
            return PacketAction.BLOCK, f"threat_intel_{threat_info['source']}_{threat_info.get('confidence', 0)}"
        
        # Priority 2: External ping blocking
        should_block, reason = self.should_block_ping(metadata)
        if should_block:
            return PacketAction.BLOCK, reason
        
        # Priority 3: Connection state tracking
        connection_state = self.connection_tracker.get_state(metadata)
        if connection_state == ConnectionState.INVALID:
            return PacketAction.DROP, "invalid_connection_state"
        
        # Priority 4: IDS inspection
        ids_result = self.ids_engine.inspect(metadata)
        if ids_result.detected:
            return PacketAction.ALERT, f"ids_{ids_result.signature}"
        
        # Priority 5: Custom rule matching (implement based on your rules)
        # ... custom rule logic here
        
        return PacketAction.ALLOW, "no_matching_rules"
    
    def packet_callback(self, packet) -> None:
        """
        Callback for intercepted packets
        Queues packets for processing by worker threads
        
        Args:
            packet: Scapy packet object
        """
        try:
            with self.stats_lock:
                self.stats["packets_received"] += 1
            
            # Queue packet for processing
            self.packet_queue.put(packet, timeout=1)
            
        except queue.Full:
            with self.stats_lock:
                self.stats["packets_dropped"] += 1
            logger.warning("Packet queue full, dropping packet")
    
    def process_packet_worker(self, worker_id: int) -> None:
        """
        Worker thread for processing packets from queue
        
        Args:
            worker_id: Worker thread identifier
        """
        logger.info(f"Worker {worker_id} started")
        
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=self.queue_timeout)
                
                # Extract metadata
                metadata = self.extract_packet_metadata(packet)
                if not metadata:
                    continue
                
                # Apply filtering rules
                action, reason = self.apply_filter_rules(metadata)
                
                # Take action based on result
                if action in [PacketAction.BLOCK, PacketAction.DROP, PacketAction.REJECT]:
                    with self.stats_lock:
                        self.stats["packets_blocked"] += 1
                    
                    # Log blocked packet
                    logger.info(f"BLOCKED - {metadata.src_ip}:{metadata.src_port} -> "
                               f"{metadata.dst_ip}:{metadata.dst_port} | {reason}")
                    
                    # Generate alert if needed
                    if action == PacketAction.ALERT:
                        self.alert_queue.put({
                            "metadata": metadata.to_dict(),
                            "reason": reason,
                            "severity": "high",
                            "timestamp": time.time()
                        })
                        with self.stats_lock:
                            self.stats["alerts_generated"] += 1
                    
                    # Here you would implement actual packet dropping
                    # This requires kernel-level integration or NFQUEUE
                    
                elif action == PacketAction.ALLOW:
                    with self.stats_lock:
                        self.stats["packets_allowed"] += 1
                    
                    # Update connection tracker
                    self.connection_tracker.update(metadata)
                    
                    logger.debug(f"ALLOWED - {metadata.src_ip}:{metadata.src_port} -> "
                                f"{metadata.dst_ip}:{metadata.dst_port}")
                
                with self.stats_lock:
                    self.stats["packets_processed"] += 1
                    
            except queue.Empty:
                continue
            except Exception as e:
                with self.stats_lock:
                    self.stats["processing_errors"] += 1
                logger.error(f"Worker {worker_id} error: {e}")
        
        logger.info(f"Worker {worker_id} stopped")
    
    def alert_processor(self) -> None:
        """
        Process alerts from the alert queue
        """
        logger.info("Alert processor started")
        
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                
                # Process alert through incident handler
                self.incident_handler.handle_alert(alert)
                
                # Log alert
                logger.warning(f"ALERT: {alert}")
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Alert processor error: {e}")
    
    def start(self) -> None:
        """Start the packet processor"""
        self.running = True
        
        logger.info("=" * 60)
        logger.info("SOC FIREWALL PACKET ENGINE STARTING")
        logger.info("=" * 60)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Workers: {self.num_workers}")
        logger.info(f"Block External Ping: {self.block_external_ping}")
        logger.info("=" * 60)
        
        # Start worker threads
        self.workers = []
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self.process_packet_worker,
                args=(i,),
                daemon=True,
                name=f"PacketWorker-{i}"
            )
            worker.start()
            self.workers.append(worker)
        
        # Start alert processor
        self.alert_thread = threading.Thread(
            target=self.alert_processor,
            daemon=True,
            name="AlertProcessor"
        )
        self.alert_thread.start()
        
        # Start statistics reporter
        self.stats_thread = threading.Thread(
            target=self._report_statistics,
            daemon=True,
            name="StatsReporter"
        )
        self.stats_thread.start()
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                promisc=self.promiscuous_mode,
                timeout=self.timeout,
                stop_filter=lambda x: not self.running
            )
        except Scapy_Exception as e:
            logger.error(f"Packet capture error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            self.stop()
    
    def _report_statistics(self) -> None:
        """Periodically report statistics"""
        last_stats = self.stats.copy()
        last_time = time.time()
        
        while self.running:
            time.sleep(60)  # Report every minute
            
            current_time = time.time()
            time_diff = current_time - last_time
            
            with self.stats_lock:
                current_stats = self.stats.copy()
            
            # Calculate rates
            packets_per_sec = (current_stats["packets_received"] - last_stats["packets_received"]) / time_diff
            blocked_per_sec = (current_stats["packets_blocked"] - last_stats["packets_blocked"]) / time_diff
            
            logger.info("=" * 50)
            logger.info("STATISTICS REPORT")
            logger.info("=" * 50)
            logger.info(f"Packets received: {current_stats['packets_received']} ({packets_per_sec:.2f}/s)")
            logger.info(f"Packets processed: {current_stats['packets_processed']}")
            logger.info(f"Packets allowed: {current_stats['packets_allowed']}")
            logger.info(f"Packets blocked: {current_stats['packets_blocked']} ({blocked_per_sec:.2f}/s)")
            logger.info(f"Alerts generated: {current_stats['alerts_generated']}")
            logger.info(f"Processing errors: {current_stats['processing_errors']}")
            logger.info("=" * 50)
            
            last_stats = current_stats
            last_time = current_time
    
    def stop(self) -> None:
        """Stop the packet processor"""
        logger.info("Stopping packet processor...")
        self.running = False
        
        # Wait for queue to empty
        if hasattr(self, 'packet_queue'):
            self.packet_queue.join()
        
        logger.info("Packet processor stopped")
        self._log_final_statistics()
    
    def _log_final_statistics(self) -> None:
        """Log final statistics"""
        with self.stats_lock:
            logger.info("=" * 50)
            logger.info("FINAL STATISTICS")
            logger.info("=" * 50)
            logger.info(f"Total packets received: {self.stats['packets_received']}")
            logger.info(f"Total packets processed: {self.stats['packets_processed']}")
            logger.info(f"Total packets allowed: {self.stats['packets_allowed']}")
            logger.info(f"Total packets blocked: {self.stats['packets_blocked']}")
            logger.info(f"Total alerts generated: {self.stats['alerts_generated']}")
            logger.info(f"Total processing errors: {self.stats['processing_errors']}")
            logger.info("=" * 50)
