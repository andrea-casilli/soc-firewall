

import pytest
import time

from src.detection.ids_engine import IDSEngine, DetectionResult, SeverityLevel


class TestIDSEngine:
    """Tests for IDSEngine class"""
    
    def test_initialization(self):
        """Test engine initialization"""
        engine = IDSEngine()
        assert len(engine.signatures) > 0
        assert engine.stats["total_inspections"] == 0
    
    def test_signature_detection_sql_injection(self):
        """Test SQL injection detection"""
        engine = IDSEngine()
        
        class MockMetadata:
            def __init__(self):
                self.protocol = "TCP"
                self.src_ip = "192.168.1.100"
                self.dst_ip = "10.0.0.1"
                self.dst_port = 80
                self.flags = []
                self.packet_size = 200
        
        metadata = MockMetadata()
        payload = b"GET /page.php?id=1 UNION SELECT * FROM users --"
        
        result = engine.inspect_packet(metadata, payload)
        assert result.detected == True
        assert "SQL" in result.signature_name
        assert result.severity == SeverityLevel.HIGH
    
    def test_signature_detection_xss(self):
        """Test XSS detection"""
        engine = IDSEngine()
        
        class MockMetadata:
            def __init__(self):
                self.protocol = "TCP"
                self.src_ip = "192.168.1.100"
                self.dst_ip = "10.0.0.1"
                self.dst_port = 80
                self.flags = []
                self.packet_size = 200
        
        metadata = MockMetadata()
        payload = b"POST /comment.php <script>alert('XSS')</script>"
        
        result = engine.inspect_packet(metadata, payload)
        assert result.detected == True
        assert "XSS" in result.signature_name
    
    def test_port_scan_detection(self):
        """Test port scan detection"""
        engine = IDSEngine()
        
        class MockMetadata:
            def __init__(self, src_ip, dst_port):
                self.src_ip = src_ip
                self.dst_port = dst_port
                self.protocol = "TCP"
                self.dst_ip = "10.0.0.1"
                self.flags = ["SYN"]
                self.packet_size = 64
        
        src_ip = "192.168.1.100"
        
        # Simulate port scan
        for port in range(1, 60):
            metadata = MockMetadata(src_ip, port)
            result = engine.inspect_packet(metadata)
            if result.detected:
                assert result.signature_id == "BEH-001"
                assert "Port Scan" in result.signature_name
                return
        
        pytest.fail("Port scan not detected")
    
    def test_syn_flood_detection(self):
        """Test SYN flood detection"""
        engine = IDSEngine()
        
        class MockMetadata:
            def __init__(self, src_ip):
                self.src_ip = src_ip
                self.dst_ip = "10.0.0.1"
                self.dst_port = 80
                self.protocol = "TCP"
                self.flags = ["SYN"]
                self.packet_size = 64
        
        src_ip = "192.168.1.200"
        
        # Simulate SYN flood
        detected = False
        for i in range(150):
            metadata = MockMetadata(src_ip)
            result = engine.inspect_packet(metadata)
            if result.detected:
                assert result.signature_id == "BEH-002"
                assert "SYN Flood" in result.signature_name
                detected = True
                break
        
        assert detected == True
    
    def test_get_statistics(self):
        """Test statistics retrieval"""
        engine = IDSEngine()
        
        class MockMetadata:
            def __init__(self):
                self.protocol = "TCP"
                self.src_ip = "1.1.1.1"
                self.dst_ip = "2.2.2.2"
                self.dst_port = 80
                self.flags = []
                self.packet_size = 100
        
        metadata = MockMetadata()
        
        # Run some inspections
        for i in range(10):
            engine.inspect_packet(metadata)
        
        stats = engine.get_statistics()
        assert stats["total_inspections"] >= 10
        assert "total_detections" in stats
        assert "detections_by_severity" in stats
