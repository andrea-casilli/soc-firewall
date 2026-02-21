import socket
import struct
import threading
import time
from typing import Dict, Set, Optional, Tuple
from dataclasses import dataclass
from contextlib import contextmanager
import ipaddress

from scapy.all import sniff, ICMP, IP, Ether
from scapy.error import Scapy_Exception

from src.utils.logger import get_logger
from src.config.settings import config

logger = get_logger(__name__)

@dataclass
class ICMPPacketInfo:
    """Data structure for ICMP packet information"""
    src_ip: str
    dst_ip: str
    icmp_type: int
    icmp_code: int
    packet_id: int
    sequence: int

  class ICMPBlocker:
    """
    Handles detection and blocking of external ICMP echo requests.
    Implements multiple blocking strategies for different network environments.
    """
    
    def __init__(self, interface: str = "eth0", config_path: Optional[str] = None):
        """
        Initialize the ICMP blocker
        
        Args:
            interface: Network interface to monitor
            config_path: Optional path to custom configuration
        """
        self.interface = interface
        self.running = False
        self.blocked_packets: int = 0
        self.allowed_packets: int = 0
        
        # Internal network ranges (modify based on your network)
        self.internal_networks: Set[ipaddress.IPv4Network] = {
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
            ipaddress.IPv4Network("127.0.0.0/8")
        }
        
        # Whitelist for allowed external IPs (monitoring systems, etc.)
        self.whitelist: Set[str] = set()
        
        # Statistics tracking
        self.stats_lock = threading.Lock()
        self.stats: Dict[str, int] = {
            "total_icmp_received": 0,
            "external_ping_blocked": 0,
            "internal_ping_allowed": 0,
            "whitelisted_ping_allowed": 0,
            "other_icmp_allowed": 0
        }
        
        self._load_configuration()
        logger.info(f"ICMP Blocker initialized on interface {interface}")
    
    def _load_configuration(self) -> None:
        """Load configuration from settings"""
        # Load whitelist from config
        whitelist_ips = config.get("icmp.whitelist", [])
        for ip in whitelist_ips:
            self.whitelist.add(ip)
        
        # Add custom internal networks if configured
        custom_networks = config.get("network.internal_ranges", [])
        for network in custom_networks:
            try:
                self.internal_networks.add(ipaddress.IPv4Network(network))
            except ValueError as e:
                logger.error(f"Invalid network range {network}: {e}")
    
    def is_internal_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address belongs to internal network
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is internal, False otherwise
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            for network in self.internal_networks:
                if ip in network:
                    return True
            return False
        except ipaddress.AddressValueError:
            logger.error(f"Invalid IP address format: {ip_address}")
            return False
    
    def should_block_ping(self, packet_info: ICMPPacketInfo) -> Tuple[bool, str]:
        """
        Determine if a ping packet should be blocked
        
        Args:
            packet_info: ICMP packet information
            
        Returns:
            Tuple of (should_block, reason)
        """
        # Always allow internal pings
        if self.is_internal_ip(packet_info.src_ip):
            return False, "internal_network"
        
        # Check whitelist
        if packet_info.src_ip in self.whitelist:
            return False, "whitelisted"
        
        # Block external ping requests (type 8 = echo request)
        if packet_info.icmp_type == 8:
            return True, "external_ping"
        
        # Allow other ICMP types (destination unreachable, time exceeded, etc.)
        return False, "non_ping_icmp"
    
    def process_packet(self, packet) -> None:
        """
        Process a single packet and decide whether to block it
        
        Args:
            packet: Scapy packet object
        """
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return
        
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]
        
        packet_info = ICMPPacketInfo(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            icmp_type=icmp_layer.type,
            icmp_code=icmp_layer.code,
            packet_id=getattr(icmp_layer, 'id', 0),
            sequence=getattr(icmp_layer, 'seq', 0),
            timestamp=time.time(),
            size=len(packet)
        )
        
        with self.stats_lock:
            self.stats["total_icmp_received"] += 1
        
        should_block, reason = self.should_block_ping(packet_info)
        
        if should_block:
            self._handle_blocked_packet(packet_info, reason)
        else:
            self._handle_allowed_packet(packet_info, reason)
    
    def _handle_blocked_packet(self, packet_info: ICMPPacketInfo, reason: str) -> None:
        """
        Handle a packet that should be blocked
        
        Args:
            packet_info: Packet information
            reason: Reason for blocking
        """
        with self.stats_lock:
            self.blocked_packets += 1
            if reason == "external_ping":
                self.stats["external_ping_blocked"] += 1
        
        logger.debug(
            f"Blocked ICMP packet - Source: {packet_info.src_ip}, "
            f"Type: {packet_info.icmp_type}, Reason: {reason}"
        )
        
        # Here you could implement actual packet dropping
        # This would require additional kernel-level integration
        # For now, we just log and count
    
    def _handle_allowed_packet(self, packet_info: ICMPPacketInfo, reason: str) -> None:
        """
        Handle a packet that should be allowed
        
        Args:
            packet_info: Packet information
            reason: Reason for allowing
        """
        with self.stats_lock:
            self.allowed_packets += 1
            if reason == "internal_network":
                self.stats["internal_ping_allowed"] += 1
            elif reason == "whitelisted":
                self.stats["whitelisted_ping_allowed"] += 1
            else:
                self.stats["other_icmp_allowed"] += 1
        
        logger.debug(
            f"Allowed ICMP packet - Source: {packet_info.src_ip}, "
            f"Type: {packet_info.icmp_type}, Reason: {reason}"
        )
    
    def start(self) -> None:
        """Start the ICMP packet monitoring and blocking"""
        self.running = True
        logger.info("ICMP Blocker started - Monitoring for ping requests")
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                filter="icmp",
                prn=self.process_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Scapy_Exception as e:
            logger.error(f"Error during packet capture: {e}")
            self.running = False
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self) -> None:
        """Stop the ICMP blocker"""
        self.running = False
        logger.info("ICMP Blocker stopped")
        self._log_statistics()
    
    def _log_statistics(self) -> None:
        """Log current statistics"""
        logger.info("=" * 50)
        logger.info("ICMP Blocker Statistics")
        logger.info("=" * 50)
        logger.info(f"Total ICMP packets received: {self.stats['total_icmp_received']}")
        logger.info(f"External pings blocked: {self.stats['external_ping_blocked']}")
        logger.info(f"Internal pings allowed: {self.stats['internal_ping_allowed']}")
        logger.info(f"Whitelisted pings allowed: {self.stats['whitelisted_ping_allowed']}")
        logger.info(f"Other ICMP allowed: {self.stats['other_icmp_allowed']}")
        logger.info("=" * 50)
    
    def add_to_whitelist(self, ip_address: str) -> bool:
        """
        Add an IP address to the whitelist
        
        Args:
            ip_address: IP address to whitelist
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_address)
            self.whitelist.add(ip_address)
            logger.info(f"Added {ip_address} to whitelist")
            return True
        except ipaddress.AddressValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return False
    
    def remove_from_whitelist(self, ip_address: str) -> bool:
        """
        Remove an IP address from the whitelist
        
        Args:
            ip_address: IP address to remove
            
        Returns:
            True if removed successfully, False otherwise
        """
        if ip_address in self.whitelist:
            self.whitelist.remove(ip_address)
            logger.info(f"Removed {ip_address} from whitelist")
            return True
        return False
    timestamp: float
    size: int
