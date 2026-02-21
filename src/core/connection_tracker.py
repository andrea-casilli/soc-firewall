import time
from enum import Enum
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import threading

from src.utils.logger import get_logger

logger = get_logger(__name__)

class ConnectionState(Enum):
    """TCP connection states"""
    NEW = "new"
    ESTABLISHED = "established"
    RELATED = "related"
    INVALID = "invalid"
    CLOSED = "closed"

@dataclass
class ConnectionEntry:
    """Entry in connection tracking table"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: ConnectionState
    first_seen: float
    last_seen: float
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

class ConnectionTracker:
    """
    Tracks stateful connections for firewall
    Implements connection tracking similar to conntrack
    """
    
    def __init__(self, timeout_new: int = 30, timeout_established: int = 300, 
                 timeout_closed: int = 10, max_entries: int = 100000):
        """
        Initialize connection tracker
        
        Args:
            timeout_new: Timeout for NEW connections (seconds)
            timeout_established: Timeout for ESTABLISHED connections (seconds)
            timeout_closed: Timeout for CLOSED connections (seconds)
            max_entries: Maximum number of tracked connections
        """
        self.timeout_new = timeout_new
        self.timeout_established = timeout_established
        self.timeout_closed = timeout_closed
        self.max_entries = max_entries
        
        self.connections: Dict[str, ConnectionEntry] = {}
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        logger.info(f"Connection tracker initialized (max: {max_entries} connections)")
    
    def _make_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Create unique key for connection"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    
    def get_state(self, metadata) -> ConnectionState:
        """
        Get state of connection for packet
        
        Args:
            metadata: Packet metadata
            
        Returns:
            Connection state
        """
        with self.lock:
            # For UDP and ICMP, treat as connectionless
            if metadata.protocol in ["UDP", "ICMP"]:
                return ConnectionState.RELATED
            
            # For TCP, check if we have existing connection
            key = self._make_key(
                metadata.src_ip, metadata.dst_ip,
                metadata.src_port, metadata.dst_port,
                metadata.protocol
            )
            
            if key in self.connections:
                entry = self.connections[key]
                
                # Check if connection is still valid
                if time.time() - entry.last_seen > self._get_timeout(entry.state):
                    del self.connections[key]
                    return ConnectionState.NEW
                
                # Update state based on TCP flags
                if 'SYN' in metadata.flags and 'ACK' not in metadata.flags:
                    entry.state = ConnectionState.NEW
                elif 'SYN' in metadata.flags and 'ACK' in metadata.flags:
                    entry.state = ConnectionState.ESTABLISHED
                elif 'FIN' in metadata.flags or 'RST' in metadata.flags:
                    entry.state = ConnectionState.CLOSED
                
                return entry.state
            
            # Check if this is a response to an existing connection
            reverse_key = self._make_key(
                metadata.dst_ip, metadata.src_ip,
                metadata.dst_port, metadata.src_port,
                metadata.protocol
            )
            
            if reverse_key in self.connections:
                entry = self.connections[reverse_key]
                entry.state = ConnectionState.ESTABLISHED
                return ConnectionState.ESTABLISHED
            
            return ConnectionState.NEW
    
    def update(self, metadata) -> None:
        """
        Update connection tracking with packet
        
        Args:
            metadata: Packet metadata
        """
        with self.lock:
            key = self._make_key(
                metadata.src_ip, metadata.dst_ip,
                metadata.src_port, metadata.dst_port,
                metadata.protocol
            )
            
            current_time = time.time()
            
            if key in self.connections:
                # Update existing entry
                entry = self.connections[key]
                entry.last_seen = current_time
                entry.packets_in += 1
                entry.bytes_in += metadata.packet_size
                
                # Update state based on TCP flags
                if metadata.protocol == "TCP":
                    if 'SYN' in metadata.flags and 'ACK' not in metadata.flags:
                        entry.state = ConnectionState.NEW
                    elif 'SYN' in metadata.flags and 'ACK' in metadata.flags:
                        entry.state = ConnectionState.ESTABLISHED
                    elif 'FIN' in metadata.flags or 'RST' in metadata.flags:
                        entry.state = ConnectionState.CLOSED
            else:
                # Create new entry if under limit
                if len(self.connections) < self.max_entries:
                    self.connections[key] = ConnectionEntry(
                        src_ip=metadata.src_ip,
                        dst_ip=metadata.dst_ip,
                        src_port=metadata.src_port,
                        dst_port=metadata.dst_port,
                        protocol=metadata.protocol,
                        state=ConnectionState.NEW,
                        first_seen=current_time,
                        last_seen=current_time,
                        packets_in=1,
                        bytes_in=metadata.packet_size
                    )
            
            # Update reverse direction packet count if this is a response
            reverse_key = self._make_key(
                metadata.dst_ip, metadata.src_ip,
                metadata.dst_port, metadata.src_port,
                metadata.protocol
            )
            
            if reverse_key in self.connections:
                entry = self.connections[reverse_key]
                entry.last_seen = current_time
                entry.packets_out += 1
                entry.bytes_out += metadata.packet_size
    
    def _get_timeout(self, state: ConnectionState) -> int:
        """Get timeout for connection state"""
        if state == ConnectionState.NEW:
            return self.timeout_new
        elif state == ConnectionState.ESTABLISHED:
            return self.timeout_established
        elif state == ConnectionState.CLOSED:
            return self.timeout_closed
        else:
            return 30
    
    def _cleanup_loop(self) -> None:
        """Periodically clean up expired connections"""
        while True:
            time.sleep(60)
            self._cleanup_expired()
    
    def _cleanup_expired(self) -> None:
        """Remove expired connections"""
        with self.lock:
            current_time = time.time()
            expired = []
            
            for key, entry in self.connections.items():
                timeout = self._get_timeout(entry.state)
                if current_time - entry.last_seen > timeout:
                    expired.append(key)
            
            for key in expired:
                del self.connections[key]
            
            if expired:
                logger.debug(f"Cleaned up {len(expired)} expired connections")
    
    def get_connection_count(self) -> int:
        """Get current number of tracked connections"""
        with self.lock:
            return len(self.connections)
    
    def get_statistics(self) -> Dict:
        """Get connection tracking statistics"""
        with self.lock:
            state_counts = defaultdict(int)
            protocol_counts = defaultdict(int)
            
            for entry in self.connections.values():
                state_counts[entry.state.value] += 1
                protocol_counts[entry.protocol] += 1
            
            return {
                "total_connections": len(self.connections),
                "by_state": dict(state_counts),
                "by_protocol": dict(protocol_counts),
                "max_entries": self.max_entries,
                "utilization_percent": (len(self.connections) / self.max_entries) * 100
            }
    
    def get_connection(self, src_ip: str, dst_ip: str, src_port: int, 
                       dst_port: int, protocol: str) -> Optional[ConnectionEntry]:
        """
        Get specific connection entry
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol
            
        Returns:
            Connection entry or None
        """
        key = self._make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        with self.lock:
            return self.connections.get(key)
