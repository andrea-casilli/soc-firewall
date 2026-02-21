import time
import threading
from enum import Enum
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ConnectionState(Enum):
    """TCP connection states based on RFC 793"""
    CLOSED = "closed"
    LISTEN = "listen"
    SYN_SENT = "syn_sent"
    SYN_RECEIVED = "syn_received"
    ESTABLISHED = "established"
    FIN_WAIT_1 = "fin_wait_1"
    FIN_WAIT_2 = "fin_wait_2"
    CLOSE_WAIT = "close_wait"
    CLOSING = "closing"
    LAST_ACK = "last_ack"
    TIME_WAIT = "time_wait"
    
    # Additional states for UDP/ICMP
    NEW = "new"
    RELATED = "related"
    INVALID = "invalid"


class ConnectionProtocol(Enum):
    """Supported protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    UNKNOWN = "unknown"


@dataclass
class ConnectionEntry:
    """
    Entry in connection tracking table
    Contains full state information for a single connection
    """
    # Connection identifiers
    protocol: ConnectionProtocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    
    # State information
    state: ConnectionState
    state_timestamp: float
    
    # Timing information
    first_seen: float
    last_seen: float
    last_state_change: float
    
    # Packet counters
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    
    # TCP-specific fields
    tcp_state_flags: Dict[str, Any] = field(default_factory=dict)
    sequence_numbers: Dict[str, int] = field(default_factory=dict)
    
    # Timeout values (per state)
    timeout: int = 300
    
    # Mark for NAT/forwarding
    mark: int = 0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging"""
        return {
            "protocol": self.protocol.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "state": self.state.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets_forward": self.packets_forward,
            "packets_reverse": self.packets_reverse,
            "bytes_forward": self.bytes_forward,
            "bytes_reverse": self.bytes_reverse
        }


class ConnectionTracker:
    """
    Stateful connection tracking system
    Implements full TCP state machine and connection timeout management
    
    Features:
    - Full TCP state tracking (SYN, SYN-ACK, ESTABLISHED, FIN, RST)
    - UDP pseudo-connection tracking
    - ICMP tracking for error messages
    - Configurable timeouts per state
    - Automatic cleanup of expired connections
    - Connection statistics and monitoring
    """
    
    # Default timeouts (in seconds) for different states
    DEFAULT_TIMEOUTS = {
        ConnectionState.CLOSED: 10,
        ConnectionState.LISTEN: 60,
        ConnectionState.SYN_SENT: 30,
        ConnectionState.SYN_RECEIVED: 30,
        ConnectionState.ESTABLISHED: 300,
        ConnectionState.FIN_WAIT_1: 30,
        ConnectionState.FIN_WAIT_2: 30,
        ConnectionState.CLOSE_WAIT: 30,
        ConnectionState.CLOSING: 30,
        ConnectionState.LAST_ACK: 30,
        ConnectionState.TIME_WAIT: 60,
        ConnectionState.NEW: 30,
        ConnectionState.RELATED: 180,
        ConnectionState.INVALID: 10
    }
    
    def __init__(
        self,
        max_connections: int = 100000,
        cleanup_interval: int = 60,
        custom_timeouts: Optional[Dict[ConnectionState, int]] = None,
        enable_stats: bool = True
    ):
        """
        Initialize connection tracker
        
        Args:
            max_connections: Maximum number of tracked connections
            cleanup_interval: Seconds between cleanup cycles
            custom_timeouts: Custom timeout values per state
            enable_stats: Enable statistics collection
        """
        self.max_connections = max_connections
        self.cleanup_interval = cleanup_interval
        self.enable_stats = enable_stats
        
        # Connection storage
        self.connections: Dict[str, ConnectionEntry] = {}
        self.connections_by_ip: Dict[str, set] = defaultdict(set)
        
        # Timeouts
        self.timeouts = self.DEFAULT_TIMEOUTS.copy()
        if custom_timeouts:
            self.timeouts.update(custom_timeouts)
        
        # Statistics
        self.stats = {
            "total_connections_created": 0,
            "total_connections_expired": 0,
            "current_connections": 0,
            "peak_connections": 0,
            "tcp_connections": 0,
            "udp_connections": 0,
            "icmp_connections": 0,
            "state_transitions": defaultdict(int),
            "cleanup_cycles": 0
        }
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="ConnectionTracker-Cleanup"
        )
        self.cleanup_thread.start()
        
        logger.info(f"Connection tracker initialized (max: {max_connections} connections)")
    
    def _make_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: ConnectionProtocol
    ) -> str:
        """
        Create unique key for connection (bidirectional)
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol
            
        Returns:
            Unique connection identifier
        """
        # Sort IPs and ports for bidirectional tracking
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol.value}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol.value}"
    
    def _get_protocol_from_string(self, protocol_str: str) -> ConnectionProtocol:
        """Convert string protocol to enum"""
        protocol_str = protocol_str.upper()
        if protocol_str == "TCP":
            return ConnectionProtocol.TCP
        elif protocol_str == "UDP":
            return ConnectionProtocol.UDP
        elif protocol_str == "ICMP":
            return ConnectionProtocol.ICMP
        else:
            return ConnectionProtocol.UNKNOWN
    
    def get_or_create_connection(self, packet_metadata) -> Tuple[ConnectionEntry, bool]:
        """
        Get existing connection or create new one
        
        Args:
            packet_metadata: Packet metadata object
            
        Returns:
            Tuple of (connection_entry, is_new)
        """
        protocol = self._get_protocol_from_string(packet_metadata.protocol)
        
        key = self._make_key(
            packet_metadata.src_ip,
            packet_metadata.dst_ip,
            packet_metadata.src_port,
            packet_metadata.dst_port,
            protocol
        )
        
        with self.lock:
            if key in self.connections:
                return self.connections[key], False
            
            # Check if we've reached max connections
            if len(self.connections) >= self.max_connections:
                logger.warning("Maximum connections reached, cannot create new entry")
                return None, False
            
            # Determine initial state based on protocol and flags
            initial_state = self._determine_initial_state(packet_metadata)
            
            # Create new connection entry
            now = time.time()
            entry = ConnectionEntry(
                protocol=protocol,
                src_ip=packet_metadata.src_ip,
                dst_ip=packet_metadata.dst_ip,
                src_port=packet_metadata.src_port,
                dst_port=packet_metadata.dst_port,
                state=initial_state,
                state_timestamp=now,
                first_seen=now,
                last_seen=now,
                last_state_change=now,
                timeout=self.timeouts.get(initial_state, 300)
            )
            
            # Store connection
            self.connections[key] = entry
            self.connections_by_ip[packet_metadata.src_ip].add(key)
            self.connections_by_ip[packet_metadata.dst_ip].add(key)
            
            # Update statistics
            if self.enable_stats:
                self.stats["total_connections_created"] += 1
                self.stats["current_connections"] = len(self.connections)
                self.stats["peak_connections"] = max(
                    self.stats["peak_connections"],
                    len(self.connections)
                )
                
                if protocol == ConnectionProtocol.TCP:
                    self.stats["tcp_connections"] += 1
                elif protocol == ConnectionProtocol.UDP:
                    self.stats["udp_connections"] += 1
                elif protocol == ConnectionProtocol.ICMP:
                    self.stats["icmp_connections"] += 1
            
            logger.debug(f"New connection created: {key} [{initial_state.value}]")
            return entry, True
    
    def _determine_initial_state(self, packet_metadata) -> ConnectionState:
        """
        Determine initial connection state based on packet
        
        Args:
            packet_metadata: Packet metadata
            
        Returns:
            Initial connection state
        """
        if packet_metadata.protocol == "TCP":
            # TCP initial state based on SYN flag
            if 'SYN' in packet_metadata.flags and 'ACK' not in packet_metadata.flags:
                return ConnectionState.SYN_SENT
            else:
                return ConnectionState.NEW
        elif packet_metadata.protocol == "UDP":
            return ConnectionState.NEW
        elif packet_metadata.protocol == "ICMP":
            return ConnectionState.RELATED
        else:
            return ConnectionState.INVALID
    
    def update_connection_state(self, packet_metadata) -> Optional[ConnectionEntry]:
        """
        Update connection state based on packet
        
        Args:
            packet_metadata: Packet metadata
            
        Returns:
            Updated connection entry or None
        """
        protocol = self._get_protocol_from_string(packet_metadata.protocol)
        
        key = self._make_key(
            packet_metadata.src_ip,
            packet_metadata.dst_ip,
            packet_metadata.src_port,
            packet_metadata.dst_port,
            protocol
        )
        
        with self.lock:
            if key not in self.connections:
                return None
            
            entry = self.connections[key]
            old_state = entry.state
            now = time.time()
            
            # Update packet counters (determine direction)
            if (packet_metadata.src_ip == entry.src_ip and 
                packet_metadata.src_port == entry.src_port):
                # Forward direction
                entry.packets_forward += 1
                entry.bytes_forward += packet_metadata.packet_size
            else:
                # Reverse direction
                entry.packets_reverse += 1
                entry.bytes_reverse += packet_metadata.packet_size
            
            # Update state based on protocol
            if protocol == ConnectionProtocol.TCP:
                self._update_tcp_state(entry, packet_metadata)
            elif protocol == ConnectionProtocol.UDP:
                self._update_udp_state(entry)
            elif protocol == ConnectionProtocol.ICMP:
                self._update_icmp_state(entry)
            
            # Update timestamps
            entry.last_seen = now
            if entry.state != old_state:
                entry.last_state_change = now
                entry.state_timestamp = now
                entry.timeout = self.timeouts.get(entry.state, 300)
                
                if self.enable_stats:
                    self.stats["state_transitions"][f"{old_state.value}->{entry.state.value}"] += 1
                
                logger.debug(f"Connection {key} state changed: {old_state.value} -> {entry.state.value}")
            
            return entry
    
    def _update_tcp_state(self, entry: ConnectionEntry, packet_metadata) -> None:
        """
        Update TCP connection state based on TCP flags
        Implements TCP state machine
        
        Args:
            entry: Connection entry
            packet_metadata: Packet metadata
        """
        flags = packet_metadata.flags
        current_state = entry.state
        
        # TCP state machine
        if current_state == ConnectionState.CLOSED:
            if 'SYN' in flags and 'ACK' not in flags:
                entry.state = ConnectionState.SYN_SENT
                
        elif current_state == ConnectionState.LISTEN:
            if 'SYN' in flags and 'ACK' not in flags:
                entry.state = ConnectionState.SYN_RECEIVED
                
        elif current_state == ConnectionState.SYN_SENT:
            if 'SYN' in flags and 'ACK' in flags:
                entry.state = ConnectionState.ESTABLISHED
            elif 'RST' in flags:
                entry.state = ConnectionState.CLOSED
                
        elif current_state == ConnectionState.SYN_RECEIVED:
            if 'ACK' in flags:
                entry.state = ConnectionState.ESTABLISHED
            elif 'RST' in flags:
                entry.state = ConnectionState.CLOSED
                
        elif current_state == ConnectionState.ESTABLISHED:
            if 'FIN' in flags:
                entry.state = ConnectionState.FIN_WAIT_1
            elif 'RST' in flags:
                entry.state = ConnectionState.CLOSED
                
        elif current_state == ConnectionState.FIN_WAIT_1:
            if 'ACK' in flags and 'FIN' not in flags:
                entry.state = ConnectionState.FIN_WAIT_2
            elif 'FIN' in flags and 'ACK' in flags:
                entry.state = ConnectionState.TIME_WAIT
            elif 'RST' in flags:
                entry.state = ConnectionState.CLOSED
                
        elif current_state == ConnectionState.FIN_WAIT_2:
            if 'FIN' in flags:
                entry.state = ConnectionState.TIME_WAIT
            elif 'RST' in flags:
                entry.state = ConnectionState.CLOSED
                
        elif current_state == ConnectionState.CLOSE_WAIT:
            if 'FIN' in flags:
                entry.state = ConnectionState.LAST_ACK
                
        elif current_state == ConnectionState.LAST_ACK:
            if 'ACK' in flags:
                entry.state = ConnectionState.CLOSED
                
        elif current_state == ConnectionState.TIME_WAIT:
            # After timeout, will be cleaned up
            pass
    
    def _update_udp_state(self, entry: ConnectionEntry) -> None:
        """
        Update UDP pseudo-connection state
        
        Args:
            entry: Connection entry
        """
        # UDP is stateless, just mark as established after first packet
        if entry.state == ConnectionState.NEW:
            entry.state = ConnectionState.ESTABLISHED
    
    def _update_icmp_state(self, entry: ConnectionEntry) -> None:
        """
        Update ICMP state
        
        Args:
            entry: Connection entry
        """
        # ICMP is typically related to other connections
        entry.state = ConnectionState.RELATED
    
    def get_connection_state(self, packet_metadata) -> ConnectionState:
        """
        Get state of connection for packet
        
        Args:
            packet_metadata: Packet metadata
            
        Returns:
            Connection state
        """
        protocol = self._get_protocol_from_string(packet_metadata.protocol)
        
        # For UDP and ICMP, treat specially
        if protocol == ConnectionProtocol.UDP:
            return ConnectionState.RELATED
        elif protocol == ConnectionProtocol.ICMP:
            return ConnectionState.RELATED
        
        key = self._make_key(
            packet_metadata.src_ip,
            packet_metadata.dst_ip,
            packet_metadata.src_port,
            packet_metadata.dst_port,
            protocol
        )
        
        with self.lock:
            if key in self.connections:
                entry = self.connections[key]
                
                # Check if entry is expired
                if time.time() - entry.last_seen > entry.timeout:
                    del self.connections[key]
                    self._remove_from_ip_index(key, entry)
                    return ConnectionState.INVALID
                
                return entry.state
            
            # Check reverse direction
            reverse_key = self._make_key(
                packet_metadata.dst_ip,
                packet_metadata.src_ip,
                packet_metadata.dst_port,
                packet_metadata.src_port,
                protocol
            )
            
            if reverse_key in self.connections:
                return ConnectionState.ESTABLISHED
            
            return ConnectionState.NEW
    
    def _remove_from_ip_index(self, key: str, entry: ConnectionEntry) -> None:
        """Remove connection from IP index"""
        if entry.src_ip in self.connections_by_ip:
            self.connections_by_ip[entry.src_ip].discard(key)
        if entry.dst_ip in self.connections_by_ip:
            self.connections_by_ip[entry.dst_ip].discard(key)
    
    def _cleanup_loop(self) -> None:
        """Periodic cleanup of expired connections"""
        while self.running:
            time.sleep(self.cleanup_interval)
            self._cleanup_expired()
    
    def _cleanup_expired(self) -> int:
        """
        Remove expired connections
        
        Returns:
            Number of connections removed
        """
        with self.lock:
            now = time.time()
            expired_keys = []
            
            for key, entry in self.connections.items():
                if now - entry.last_seen > entry.timeout:
                    expired_keys.append(key)
            
            # Remove expired connections
            for key in expired_keys:
                entry = self.connections[key]
                del self.connections[key]
                self._remove_from_ip_index(key, entry)
                
                if self.enable_stats:
                    self.stats["total_connections_expired"] += 1
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired connections")
            
            if self.enable_stats:
                self.stats["cleanup_cycles"] += 1
                self.stats["current_connections"] = len(self.connections)
            
            return len(expired_keys)
    
    def get_connection_by_key(self, key: str) -> Optional[ConnectionEntry]:
        """Get connection by key"""
        with self.lock:
            return self.connections.get(key)
    
    def get_connections_by_ip(self, ip_address: str) -> List[ConnectionEntry]:
        """
        Get all connections involving an IP address
        
        Args:
            ip_address: IP address
            
        Returns:
            List of connection entries
        """
        with self.lock:
            if ip_address not in self.connections_by_ip:
                return []
            
            return [
                self.connections[key]
                for key in self.connections_by_ip[ip_address]
                if key in self.connections
            ]
    
    def get_statistics(self) -> Dict:
        """
        Get connection tracking statistics
        
        Returns:
            Dictionary of statistics
        """
        with self.lock:
            # Count current states
            state_counts = defaultdict(int)
            protocol_counts = defaultdict(int)
            
            for entry in self.connections.values():
                state_counts[entry.state.value] += 1
                protocol_counts[entry.protocol.value] += 1
            
            stats = {
                "current_connections": len(self.connections),
                "peak_connections": self.stats["peak_connections"],
                "total_connections_created": self.stats["total_connections_created"],
                "total_connections_expired": self.stats["total_connections_expired"],
                "cleanup_cycles": self.stats["cleanup_cycles"],
                "state_distribution": dict(state_counts),
                "protocol_distribution": dict(protocol_counts),
                "state_transitions": dict(self.stats["state_transitions"]),
                "utilization_percent": (len(self.connections) / self.max_connections) * 100,
                "max_connections": self.max_connections
            }
            
            # Add TCP/UDP/ICMP counts
            stats.update({
                "tcp_connections": protocol_counts.get("tcp", 0),
                "udp_connections": protocol_counts.get("udp", 0),
                "icmp_connections": protocol_counts.get("icmp", 0)
            })
            
            return stats
    
    def shutdown(self) -> None:
        """Shutdown connection tracker"""
        logger.info("Shutting down connection tracker...")
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        
        # Log final statistics
        stats = self.get_statistics()
        logger.info(f"Final connection statistics: {stats}")
    
    def flush_all(self) -> int:
        """
        Remove all connections
        
        Returns:
            Number of connections removed
        """
        with self.lock:
            count = len(self.connections)
            self.connections.clear()
            self.connections_by_ip.clear()
            
            if self.enable_stats:
                self.stats["current_connections"] = 0
            
            logger.info(f"Flushed {count} connections")
            return count
    
    def is_valid_connection(self, packet_metadata) -> bool:
        """
        Check if packet belongs to a valid connection
        
        Args:
            packet_metadata: Packet metadata
            
        Returns:
            True if connection is valid
        """
        state = self.get_connection_state(packet_metadata)
        return state not in [ConnectionState.INVALID, ConnectionState.CLOSED]
    
    def get_timeout_for_state(self, state: ConnectionState) -> int:
        """Get timeout value for a connection state"""
        return self.timeouts.get(state, 300)
    
    def set_timeout_for_state(self, state: ConnectionState, timeout: int) -> None:
        """
        Set custom timeout for a connection state
        
        Args:
            state: Connection state
            timeout: Timeout in seconds
        """
        with self.lock:
            self.timeouts[state] = timeout
            logger.info(f"Set timeout for {state.value} to {timeout}s")
