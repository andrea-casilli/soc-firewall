"""
Unit tests for connection tracker module
"""

import pytest
import time
from src.core.connection_tracker import ConnectionTracker, ConnectionState, ConnectionProtocol


class TestConnectionTracker:
    """Tests for ConnectionTracker class"""
    
    def test_initialization(self):
        """Test tracker initialization"""
        tracker = ConnectionTracker(max_connections=1000)
        assert tracker.max_connections == 1000
        assert tracker.get_connection_count() == 0
    
    def test_tcp_state_machine(self):
        """Test TCP state transitions"""
        tracker = ConnectionTracker()
        
        # Create mock packet metadata
        class MockMetadata:
            def __init__(self, protocol, src_ip, dst_ip, src_port, dst_port, flags):
                self.protocol = protocol
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                self.src_port = src_port
                self.dst_port = dst_port
                self.flags = flags
                self.packet_size = 64
        
        # SYN packet
        syn_packet = MockMetadata(
            protocol="TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            flags=["SYN"]
        )
        
        # Get or create connection
        entry, is_new = tracker.get_or_create_connection(syn_packet)
        assert is_new == True
        assert entry.state == ConnectionState.SYN_SENT
        
        # Update with SYN-ACK
        synack_packet = MockMetadata(
            protocol="TCP",
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            flags=["SYN", "ACK"]
        )
        
        tracker.update_connection_state(synack_packet)
        
        # Check state
        state = tracker.get_connection_state(syn_packet)
        assert state == ConnectionState.ESTABLISHED
        
        # Update with FIN
        fin_packet = MockMetadata(
            protocol="TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            flags=["FIN"]
        )
        
        tracker.update_connection_state(fin_packet)
        state = tracker.get_connection_state(syn_packet)
        assert state == ConnectionState.FIN_WAIT_1
    
    def test_udp_handling(self):
        """Test UDP pseudo-connection tracking"""
        tracker = ConnectionTracker()
        
        class MockMetadata:
            def __init__(self, protocol, src_ip, dst_ip, src_port, dst_port):
                self.protocol = protocol
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                self.src_port = src_port
                self.dst_port = dst_port
                self.packet_size = 64
                self.flags = []
        
        # UDP packet
        udp_packet = MockMetadata(
            protocol="UDP",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53
        )
        
        # Get connection
        entry, is_new = tracker.get_or_create_connection(udp_packet)
        assert is_new == True
        assert entry.state == ConnectionState.NEW
        
        # Update should set to RELATED
        tracker.update_connection_state(udp_packet)
        state = tracker.get_connection_state(udp_packet)
        assert state == ConnectionState.RELATED
    
    def test_connection_expiry(self):
        """Test connection expiry"""
        tracker = ConnectionTracker(timeout_new=1, timeout_established=2)
        
        class MockMetadata:
            def __init__(self, protocol, src_ip, dst_ip, src_port, dst_port):
                self.protocol = protocol
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                self.src_port = src_port
                self.dst_port = dst_port
                self.packet_size = 64
                self.flags = ["SYN"]
        
        # Create connection
        packet = MockMetadata(
            protocol="TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80
        )
        
        tracker.get_or_create_connection(packet)
        assert tracker.get_connection_count() == 1
        
        # Wait for expiry
        time.sleep(2)
        
        # Force cleanup
        tracker._cleanup_expired()
        
        assert tracker.get_connection_count() == 0
    
    def test_max_connections(self):
        """Test maximum connections limit"""
        tracker = ConnectionTracker(max_connections=2)
        
        class MockMetadata:
            def __init__(self, protocol, src_ip, dst_ip, src_port, dst_port):
                self.protocol = protocol
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                self.src_port = src_port
                self.dst_port = dst_port
                self.packet_size = 64
                self.flags = ["SYN"]
        
        # Create first connection
        packet1 = MockMetadata("TCP", "1.1.1.1", "2.2.2.2", 1000, 80)
        tracker.get_or_create_connection(packet1)
        
        # Create second connection
        packet2 = MockMetadata("TCP", "3.3.3.3", "4.4.4.4", 2000, 80)
        tracker.get_or_create_connection(packet2)
        
        assert tracker.get_connection_count() == 2
        
        # Third should be rejected
        packet3 = MockMetadata("TCP", "5.5.5.5", "6.6.6.6", 3000, 80)
        entry, is_new = tracker.get_or_create_connection(packet3)
        assert entry is None
    
    def test_get_statistics(self):
        """Test statistics retrieval"""
        tracker = ConnectionTracker()
        
        class MockMetadata:
            def __init__(self, protocol, src_ip, dst_ip, src_port, dst_port):
                self.protocol = protocol
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                self.src_port = src_port
                self.dst_port = dst_port
                self.packet_size = 64
                self.flags = ["SYN"]
        
        # Add some connections
        for i in range(5):
            packet = MockMetadata("TCP", f"192.168.1.{i}", "10.0.0.1", 1000 + i, 80)
            tracker.get_or_create_connection(packet)
        
        stats = tracker.get_statistics()
        assert stats["total_connections"] == 5
        assert stats["by_protocol"]["tcp"] == 5
        assert "by_state" in stats
