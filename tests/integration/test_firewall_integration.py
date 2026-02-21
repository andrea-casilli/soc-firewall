"""
Integration tests for SOC Firewall
Tests interaction between multiple components
"""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock

from src.core.packet_engine import PacketProcessor
from src.core.filter_rules import FilterRules
from src.core.connection_tracker import ConnectionTracker
from src.detection.ids_engine import IDSEngine
from src.response.alert_manager import AlertManager
from src.response.incident_handler import IncidentHandler
from src.response.quarantine import QuarantineManager


class TestFirewallIntegration:
    """Integration tests for firewall components"""
    
    @pytest.fixture
    def components(self, tmp_path):
        """Setup all components"""
        filter_rules = FilterRules(str(tmp_path / "rules.yaml"))
        connection_tracker = ConnectionTracker()
        ids_engine = IDSEngine()
        quarantine_manager = QuarantineManager(str(tmp_path / "quarantine"))
        alert_manager = AlertManager(str(tmp_path / "alerts.json"))
        incident_handler = IncidentHandler(quarantine_manager)
        
        return {
            'filter_rules': filter_rules,
            'connection_tracker': connection_tracker,
            'ids_engine': ids_engine,
            'quarantine_manager': quarantine_manager,
            'alert_manager': alert_manager,
            'incident_handler': incident_handler
        }
    
    def test_packet_processing_pipeline(self, components):
        """Test complete packet processing pipeline"""
        
        # Create mock packet metadata
        class MockMetadata:
            def __init__(self):
                self.protocol = "ICMP"
                self.src_ip = "8.8.8.8"
                self.dst_ip = "192.168.1.100"
                self.src_port = 0
                self.dst_port = 0
                self.flags = ["type=8", "code=0"]
                self.packet_size = 64
                self.timestamp = time.time()
                self.interface = "eth0"
            
            def to_dict(self):
                return {
                    'protocol': self.protocol,
                    'src_ip': self.src_ip,
                    'dst_ip': self.dst_ip,
                    'src_port': self.src_port,
                    'dst_port': self.dst_port,
                    'flags': self.flags,
                    'packet_size': self.packet_size,
                    'timestamp': self.timestamp,
                    'interface': self.interface
                }
        
        # Create external ping packet
        packet = MockMetadata()
        
        # 1. Check filter rules
        action, rule_name = components['filter_rules'].check_packet(packet)
        
        # 2. Check connection state
        state = components['connection_tracker'].get_connection_state(packet)
        
        # 3. Check IDS
        detection = components['ids_engine'].inspect_packet(packet, b"")
        
        # 4. Create alert if detected
        if detection.detected:
            from src.response.alert_manager import AlertSeverity
            alert = components['alert_manager'].create_alert(
                source="ids",
                severity=AlertSeverity.MEDIUM,
                title=detection.signature_name,
                message=detection.signature_name,
                src_ip=packet.src_ip
            )
            
            # 5. Create incident from alert
            incident = components['incident_handler'].create_from_alert(alert)
            
            # 6. Check quarantine
            if components['quarantine_manager'].is_quarantined(packet.src_ip):
                components['quarantine_manager'].quarantine_ip(
                    ip=packet.src_ip,
                    reason="malicious",
                    source="integration_test"
                )
        
        # Assertions
        assert action.value == "allow" or action.value == "drop"
        assert state.value in ["new", "established", "related"]
    
    def test_alert_to_incident_flow(self, components):
        """Test alert to incident creation flow"""
        
        from src.response.alert_manager import AlertSeverity
        
        # Create alert
        alert = components['alert_manager'].create_alert(
            source="test",
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            message="This is a test alert",
            src_ip="192.168.1.100",
            signature_id="TEST-001"
        )
        
        # Create incident from alert
        incident = components['incident_handler'].create_from_alert(alert)
        
        assert incident is not None
        assert incident.title == "Alert: Test Alert"
        assert incident.severity.value == "high"
        assert len(incident.alerts) == 1
        assert incident.alerts[0].id == alert.id
    
    def test_quarantine_integration(self, components):
        """Test quarantine integration with other components"""
        
        # Quarantine an IP
        entry = components['quarantine_manager'].quarantine_ip(
            ip="1.2.3.4",
            reason="malicious",
            source="test",
            duration=60
        )
        
        assert entry is not None
        assert components['quarantine_manager'].is_quarantined("1.2.3.4") == True
        
        # Check that incident handler can access quarantine
        components['incident_handler'].quarantine = components['quarantine_manager']
        
        # Create incident with affected IP
        from src.response.incident_handler import IncidentSeverity
        incident = components['incident_handler'].create_incident(
            title="Test Incident",
            description="Test",
            severity=IncidentSeverity.HIGH,
            source="test",
            affected_ips=["1.2.3.4"]
        )
        
        # Incident handler should be able to quarantine
        assert incident.affected_ips[0] == "1.2.3.4"
