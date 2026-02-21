"""
Pytest configuration and fixtures
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any

from src.core.packet_engine import PacketProcessor
from src.core.filter_rules import FilterRules
from src.core.connection_tracker import ConnectionTracker
from src.detection.ids_engine import IDSEngine
from src.detection.threat_intel import ThreatIntelligence
from src.detection.anomaly_detector import AnomalyDetector
from src.response.incident_handler import IncidentHandler
from src.response.alert_manager import AlertManager
from src.response.quarantine import QuarantineManager
from src.config.settings import Settings, ConfigManager
from src.utils.logger import setup_logging


@pytest.fixture(scope="session")
def test_dir() -> Generator[Path, None, None]:
    """Create temporary test directory"""
    test_dir = Path(tempfile.mkdtemp(prefix="soc_firewall_test_"))
    yield test_dir
    shutil.rmtree(test_dir)


@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Provide test configuration"""
    return {
        "firewall": {
            "interface": "lo",
            "num_workers": 2,
            "queue_size": 1000,
            "max_connections": 10000,
            "block_external_ping": True,
            "internal_networks": ["127.0.0.0/8", "192.168.0.0/16"]
        },
        "detection": {
            "enable_ids": True,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 20,
            "dos_threshold": 50,
            "bruteforce_threshold": 5
        },
        "response": {
            "enable_auto_response": True,
            "quarantine_default_duration": 60,
            "alert_channels": ["log"]
        },
        "api": {
            "enable_rest_api": False,
            "enable_websocket": False
        },
        "logging": {
            "log_level": "debug",
            "console_output": False,
            "log_dir": "test_logs"
        }
    }


@pytest.fixture
def config_manager(test_config, test_dir) -> ConfigManager:
    """Create config manager with test configuration"""
    config_path = test_dir / "test_config.yaml"
    import yaml
    with open(config_path, 'w') as f:
        yaml.dump(test_config, f)
    
    return ConfigManager(str(config_path))


@pytest.fixture
def packet_processor() -> PacketProcessor:
    """Create packet processor instance"""
    return PacketProcessor(interface="lo")


@pytest.fixture
def filter_rules(test_dir) -> FilterRules:
    """Create filter rules instance"""
    rules_file = test_dir / "test_rules.yaml"
    return FilterRules(str(rules_file))


@pytest.fixture
def connection_tracker() -> ConnectionTracker:
    """Create connection tracker instance"""
    return ConnectionTracker(max_connections=1000, cleanup_interval=5)


@pytest.fixture
def ids_engine() -> IDSEngine:
    """Create IDS engine instance"""
    return IDSEngine()


@pytest.fixture
def threat_intel(test_dir) -> ThreatIntelligence:
    """Create threat intelligence instance"""
    db_path = test_dir / "test_threat_intel.db"
    return ThreatIntelligence(str(db_path))


@pytest.fixture
def anomaly_detector() -> AnomalyDetector:
    """Create anomaly detector instance"""
    return AnomalyDetector()


@pytest.fixture
def alert_manager(test_dir) -> AlertManager:
    """Create alert manager instance"""
    config_path = test_dir / "test_alerts.json"
    return AlertManager(str(config_path))


@pytest.fixture
def quarantine_manager(test_dir) -> QuarantineManager:
    """Create quarantine manager instance"""
    data_dir = test_dir / "quarantine_data"
    return QuarantineManager(str(data_dir))


@pytest.fixture
def incident_handler(quarantine_manager) -> IncidentHandler:
    """Create incident handler instance"""
    return IncidentHandler(quarantine_manager)


@pytest.fixture(autouse=True)
def setup_test_logging(test_dir):
    """Setup logging for tests"""
    log_dir = test_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    setup_logging(
        log_dir=str(log_dir),
        log_level="debug",
        console_output=False
    )
    yield
