"""
Packet Engine Module
Core packet processing engine for SOC firewall
"""

import socket
import struct
import threading
import queue
import time
import hashlib
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from scapy.error import Scapy_Exception

from src.utils.logger import get_logger
from src.core.connection_tracker import ConnectionTracker, ConnectionState
from src.core.filter_rules import FilterRules, RuleAction

logger = get_logger(__name__)

class PacketAction(Enum):
    """Actions to take on packets"""
    ALLOW = "allow"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    ALERT = "alert"

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
            "interface": self.interface
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
            "packets_allowed": 0,
            "packets_blocked": 0,
            "alerts_generated": 0,
            "processing_errors": 0
        }
        
        self.stats_lock = threading.Lock()
        
        # Initialize components
        self.connection_tracker = ConnectionTracker()
        self.filter_rules = FilterRules()
        
        # Load configuration
        self._load_configuration()
        
        logger.info(f"Packet Processor initialized on interface {interface} [ID: {self.processor_id}]")
    
    def _load_configuration(self) -> None:
        """Load processor configuration"""
        self.buffer_size = 65536
        self.promiscuous_mode = False
        self.snapshot_length = 0
        self.num_workers = 4
        self.queue_timeout = 1.0
        
        # Filtering rules
        self.block_external_ping = True
        self.internal_networks = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8"
        ]
    
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
        except (ipaddress.AddressValueError, ValueError):
            return False
    
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
        # Priority 1: External ping blocking
        should_block, reason = self.should_block_ping(metadata)
        if should_block:
            return PacketAction.DROP, reason
        
        # Priority 2: Custom filter rules
        rule_action, rule_name = self.filter_rules.check_packet(metadata)
        
        if rule_action == RuleAction.DROP:
            return PacketAction.DROP, f"rule_match_{rule_name}"
        elif rule_action == RuleAction.REJECT:
            return PacketAction.REJECT, f"rule_match_{rule_name}"
        elif rule_action == RuleAction.ALERT:
            return PacketAction.ALERT, f"rule_match_{rule_name}"
        
        # Priority 3: Connection state tracking
        connection_state = self.connection_tracker.get_state(metadata)
        if connection_state == ConnectionState.INVALID:
            return PacketAction.DROP, "invalid_connection_state"
        
        return PacketAction.ALLOW, "no_matching_rules"
    
    def packet_callback(self, packet) -> None:
        """
        Callback for intercepted packets
        
        Args:
            packet: Scapy packet object
        """
        try:
            with self.stats_lock:
                self.stats["packets_received"] += 1
            
            self.packet_queue.put(packet, timeout=1)
            
        except queue.Full:
            with self.stats_lock:
                self.stats["packets_blocked"] += 1
            logger.warning("Packet queue full, dropping packet")
    
    def process_packet_worker(self, worker_id: int) -> None:
        """
        Worker thread for processing packets
        
        Args:
            worker_id: Worker thread identifier
        """
        logger.info(f"Worker {worker_id} started")
        
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=self.queue_timeout)
                
                metadata = self.extract_packet_metadata(packet)
                if not metadata:
                    continue
                
                action, reason = self.apply_filter_rules(metadata)
                
                if action in [PacketAction.DROP, PacketAction.REJECT]:
                    with self.stats_lock:
                        self.stats["packets_blocked"] += 1
                    
                    logger.info(f"BLOCKED - {metadata.src_ip}:{metadata.src_port} -> "
                               f"{metadata.dst_ip}:{metadata.dst_port} | {reason}")
                    
                    if action == PacketAction.ALERT:
                        self.alert_queue.put({
                            "metadata": metadata.to_dict(),
                            "reason": reason,
                            "timestamp": time.time()
                        })
                        with self.stats_lock:
                            self.stats["alerts_generated"] += 1
                    
                elif action == PacketAction.ALLOW:
                    with self.stats_lock:
                        self.stats["packets_allowed"] += 1
                    
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
    
    def start(self) -> None:
        """Start the packet processor"""
        self.running = True
        
        logger.info("=" * 50)
        logger.info("SOC FIREWALL PACKET ENGINE STARTING")
        logger.info("=" * 50)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Workers: {self.num_workers}")
        logger.info(f"Block External Ping: {self.block_external_ping}")
        logger.info("=" * 50)
        
        # Start worker threads
        self.workers = []
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self.process_packet_worker,
                args=(i,),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                promisc=self.promiscuous_mode,
                stop_filter=lambda x: not self.running
            )
        except Scapy_Exception as e:
            logger.error(f"Packet capture error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the packet processor"""
        logger.info("Stopping packet processor...")
        self.running = False
        logger.info("Packet processor stopped")
