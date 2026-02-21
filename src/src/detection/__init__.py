"""
Detection module for SOC Firewall
Provides intrusion detection, threat intelligence, and anomaly detection capabilities
"""

from src.detection.ids_engine import IDSEngine, DetectionResult, AttackSignature
from src.detection.threat_intel import ThreatIntelligence, ThreatFeed, ThreatIndicator
from src.detection.anomaly_detector import AnomalyDetector, BehavioralProfile, AnomalyScore

__all__ = [
    'IDSEngine',
    'DetectionResult',
    'AttackSignature',
    'ThreatIntelligence',
    'ThreatFeed',
    'ThreatIndicator',
    'AnomalyDetector',
    'BehavioralProfile',
    'AnomalyScore'
]
