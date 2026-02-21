import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from scapy.all import IP, TCP, UDP, ICMP, Ether

from src.core.packet_engine import PacketProcessor, PacketMetadata, PacketAction


class TestPacketMetadata:
    """Tests for PacketMetadata class"""
    
    def test_metadata_creation(self):
        """Test packet metadata creation"""
        metadata = PacketMetadata(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            ttl=64,
            flags=["SYN"],
            packet_size=1500,
            interface="eth0"
        )
        
        assert metadata.src_ip == "192.168.1.1"
        assert metadata.dst_ip == "10.0.0.1"
        assert metadata.protocol == "TCP"
        assert metadata.dst_port == 80
        
        # Test to_dict
        data = metadata.to_dict()
        assert data["src_ip"] == "192.168.1.1"
        assert data["protocol"] == "TCP"


class TestPacketProcessor:
    """Tests for PacketProcessor class"""
    
    def test_initialization(self):
        """Test packet processor initialization"""
        processor = PacketProcessor(interface="lo")
        assert processor.interface == "lo"
        assert processor.running == False
        assert processor.num_workers == 4
        assert processor.stats["packets_received"] == 0
    
    def test_is_internal_ip(self, packet_processor):
        """Test internal IP detection"""
        # Internal IPs
        assert packet_processor.is_internal_ip("127.0.0.1") == True
        assert packet_processor.is_internal_ip("192.168.1.100") == True
        assert packet_processor.is_internal_ip("10.0.0.5") == True
        
        # External IPs
        assert packet_processor.is_internal_ip("8.8.8.8") == False
        assert packet_processor.is_internal_ip("1.1.1.1") == False
        
        # Invalid IP
        assert packet_processor.is_internal_ip("invalid") == False
    
    def test_should_block_ping_internal(self, packet_processor):
        """Test ping blocking for internal IPs"""
        # Create internal ping packet metadata
        metadata = PacketMetadata(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="ICMP",
            flags=["type=8", "code=0"],
            packet_size=64,
            interface="eth0"
        )
        
        should_block, reason = packet_processor.should_block_ping(metadata)
        assert should_block == False
        assert reason == "internal_ping"
    
    def test_should_block_ping_external(self, packet_processor):
        """Test ping blocking for external IPs"""
        # Create external ping packet metadata
        metadata = PacketMetadata(
            timestamp=time.time(),
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            protocol="ICMP",
            flags=["type=8", "code=0"],
            packet_size=64,
            interface="eth0"
        )
        
        should_block, reason = packet_processor.should_block_ping(metadata)
        assert should_block == True
        assert reason == "external_ping_blocked"
    
    def test_should_block_ping_disabled(self, packet_processor):
        """Test when ping blocking is disabled"""
        packet_processor.block_external_ping = False
        
        metadata = PacketMetadata(
            timestamp=time.time(),
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            protocol="ICMP",
            flags=["type=8", "code=0"],
            packet_size=64,
            interface="eth0"
        )
        
        should_block, reason = packet_processor.should_block_ping(metadata)
        assert should_block == False
        assert reason == "ping_blocking_disabled"
    
    def test_extract_tcp_flags(self, packet_processor):
        """Test TCP flag extraction"""
        mock_tcp = MagicMock()
        
        # Test SYN flag
        mock_tcp.flags = 0x02
        flags = packet_processor._extract_tcp_flags(mock_tcp)
        assert "SYN" in flags
        assert len(flags) == 1
        
        # Test SYN-ACK
        mock_tcp.flags = 0x12  # SYN + ACK
        flags = packet_processor._extract_tcp_flags(mock_tcp)
        assert "SYN" in flags
        assert "ACK" in flags
        assert len(flags) == 2
        
        # Test FIN
        mock_tcp.flags = 0x01
        flags = packet_processor._extract_tcp_flags(mock_tcp)
        assert "FIN" in flags
    
    @patch('src.core.packet_engine.sniff')
    def test_start_stop(self, mock_sniff, packet_processor):
        """Test starting and stopping processor"""
        # Mock sniff to raise exception to stop
        mock_sniff.side_effect = KeyboardInterrupt()
        
        # Start should handle keyboard interrupt
        packet_processor.start()
        
        assert packet_processor.running == False
    
    def test_apply_filter_rules_ping(self, packet_processor):
        """Test filter rules for ping packets"""
        metadata = PacketMetadata(
            timestamp=time.time(),
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            protocol="ICMP",
            flags=["type=8", "code=0"],
            packet_size=64,
            interface="eth0"
        )
        
        action, reason = packet_processor.apply_filter_rules(metadata)
        assert action == PacketAction.DROP
        assert "external_ping" in reason
    
    def test_apply_filter_rules_allowed(self, packet_processor):
        """Test filter rules for allowed packets"""
        metadata = PacketMetadata(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="TCP",
            src_port=12345,
            dst_port=443,
            flags=["SYN"],
            packet_size=64,
            interface="eth0"
        )
        
        action, reason = packet_processor.apply_filter_rules(metadata)
        assert action == PacketAction.ALLOW
        assert reason == "no_matching_rules"
