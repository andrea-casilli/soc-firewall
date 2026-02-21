import time
import uuid
import json
import threading
import subprocess
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import defaultdict
import queue

from src.utils.logger import get_logger
from src.response.alert_manager import Alert, AlertSeverity
from src.response.quarantine import QuarantineManager, QuarantineReason

logger = get_logger(__name__)


class IncidentSeverity(Enum):
    """Incident severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(Enum):
    """Incident status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


@dataclass
class Incident:
    """Security incident"""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    source: str  # ids, threat_intel, anomaly, manual
    alerts: List[Alert] = field(default_factory=list)
    affected_ips: List[str] = field(default_factory=list)
    affected_ports: List[int] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    assigned_to: Optional[str] = None
    notes: List[Dict] = field(default_factory=list)
    actions_taken: List[Dict] = field(default_factory=list)
    playbook_executed: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "source": self.source,
            "alerts": [a.to_dict() for a in self.alerts],
            "affected_ips": self.affected_ips,
            "affected_ports": self.affected_ports,
            "affected_hosts": self.affected_hosts,
            "timestamp": self.timestamp,
            "updated_at": self.updated_at,
            "assigned_to": self.assigned_to,
            "notes": self.notes,
            "actions_taken": self.actions_taken,
            "playbook_executed": self.playbook_executed,
            "tags": self.tags
        }


@dataclass
class Playbook:
    """Automated response playbook"""
    name: str
    description: str
    triggers: List[Dict]  # Conditions that trigger this playbook
    steps: List[Dict]  # Steps to execute
    enabled: bool = True
    timeout: int = 300  # Maximum execution time in seconds
    
    def matches_incident(self, incident: Incident) -> bool:
        """Check if playbook matches incident"""
        for trigger in self.triggers:
            trigger_type = trigger.get("type")
            
            if trigger_type == "severity":
                if incident.severity.value == trigger.get("value"):
                    return True
                    
            elif trigger_type == "source":
                if incident.source == trigger.get("value"):
                    return True
                    
            elif trigger_type == "tag":
                if trigger.get("value") in incident.tags:
                    return True
                    
            elif trigger_type == "alert_signature":
                for alert in incident.alerts:
                    if alert.signature_id == trigger.get("value"):
                        return True
        
        return False


class IncidentHandler:
    """
    Automated incident response handler
    Manages incidents and executes response playbooks
    
    Features:
    - Incident creation and tracking
    - Playbook automation
    - Multi-step response actions
    - Integration with quarantine
    - Notification routing
    - Incident timeline
    """
    
    def __init__(self, quarantine_manager: Optional[QuarantineManager] = None):
        """
        Initialize incident handler
        
        Args:
            quarantine_manager: Quarantine manager instance
        """
        self.quarantine = quarantine_manager
        self.incidents: Dict[str, Incident] = {}
        self.playbooks: Dict[str, Playbook] = {}
        self.incident_queue = queue.Queue()
        self.active_incidents: Dict[str, threading.Thread] = {}
        
        # Statistics
        self.stats = {
            "total_incidents": 0,
            "open_incidents": 0,
            "resolved_incidents": 0,
            "false_positives": 0,
            "playbooks_executed": 0
        }
        
        self.lock = threading.RLock()
        
        # Load default playbooks
        self._load_default_playbooks()
        
        # Start worker thread
        self.running = True
        self.worker = threading.Thread(target=self._process_incidents, daemon=True)
        self.worker.start()
        
        logger.info("Incident Handler initialized")
    
    def _load_default_playbooks(self) -> None:
        """Load default response playbooks"""
        default_playbooks = [
            Playbook(
                name="quarantine_malicious_ip",
                description="Quarantine IP address detected as malicious",
                triggers=[
                    {"type": "severity", "value": "high"},
                    {"type": "severity", "value": "critical"},
                    {"type": "source", "value": "threat_intel"}
                ],
                steps=[
                    {"action": "quarantine_ip", "params": {"duration": 3600}},
                    {"action": "block_firewall", "params": {"permanent": False}},
                    {"action": "notify_soc", "params": {"channel": "slack"}},
                    {"action": "create_ticket", "params": {"priority": "high"}}
                ]
            ),
            Playbook(
                name="port_scan_response",
                description="Respond to port scan detection",
                triggers=[
                    {"type": "alert_signature", "value": "BEH-001"}  # Port scan signature
                ],
                steps=[
                    {"action": "log_incident", "params": {}},
                    {"action": "increase_monitoring", "params": {"duration": 300}},
                    {"action": "notify_admin", "params": {"channel": "email"}}
                ]
            ),
            Playbook(
                name="brute_force_response",
                description="Respond to brute force attack",
                triggers=[
                    {"type": "alert_signature", "value": "BEH-005"}  # Brute force signature
                ],
                steps=[
                    {"action": "temporary_block", "params": {"duration": 900}},
                    {"action": "rate_limit", "params": {"limit": "5/minute"}},
                    {"action": "notify_security", "params": {"channel": "slack"}}
                ]
            ),
            Playbook(
                name="critical_incident_response",
                description="Response for critical security incidents",
                triggers=[
                    {"type": "severity", "value": "critical"}
                ],
                steps=[
                    {"action": "immediate_quarantine", "params": {}},
                    {"action": "block_all_traffic", "params": {"direction": "both"}},
                    {"action": "notify_soc_leader", "params": {"channel": "pager"}},
                    {"action": "create_emergency_ticket", "params": {}},
                    {"action": "capture_forensics", "params": {"depth": "full"}}
                ]
            )
        ]
        
        for playbook in default_playbooks:
            self.add_playbook(playbook)
    
    def add_playbook(self, playbook: Playbook) -> None:
        """Add a response playbook"""
        with self.lock:
            self.playbooks[playbook.name] = playbook
        logger.info(f"Added playbook: {playbook.name}")
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        source: str,
        alerts: Optional[List[Alert]] = None,
        affected_ips: Optional[List[str]] = None,
        affected_ports: Optional[List[int]] = None,
        tags: Optional[List[str]] = None
    ) -> Incident:
        """
        Create a new incident
        
        Args:
            title: Incident title
            description: Incident description
            severity: Incident severity
            source: Incident source
            alerts: Related alerts
            affected_ips: Affected IP addresses
            affected_ports: Affected ports
            tags: Incident tags
            
        Returns:
            Created incident
        """
        incident_id = f"INC-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        
        incident = Incident(
            id=incident_id,
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.NEW,
            source=source,
            alerts=alerts or [],
            affected_ips=affected_ips or [],
            affected_ports=affected_ports or [],
            tags=tags or []
        )
        
        with self.lock:
            self.incidents[incident_id] = incident
            self.stats["total_incidents"] += 1
            self.stats["open_incidents"] += 1
        
        # Queue for processing
        self.incident_queue.put(incident)
        
        logger.warning(f"Incident created: {incident_id} - {title} [{severity.value}]")
        return incident
    
    def create_from_alert(self, alert: Alert) -> Optional[Incident]:
        """
        Create incident from alert
        
        Args:
            alert: Alert object
            
        Returns:
            Created incident or None
        """
        # Determine severity mapping
        severity_map = {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW,
            "info": IncidentSeverity.INFO
        }
        
        severity = severity_map.get(alert.severity.value, IncidentSeverity.MEDIUM)
        
        # Create incident
        return self.create_incident(
            title=f"Alert: {alert.signature_name or alert.rule_name}",
            description=alert.message,
            severity=severity,
            source=alert.source,
            alerts=[alert],
            affected_ips=[alert.src_ip] if alert.src_ip else None,
            affected_ports=[alert.dst_port] if alert.dst_port else None,
            tags=[alert.category] if alert.category else None
        )
    
    def _process_incidents(self) -> None:
        """Worker thread to process incidents"""
        while self.running:
            try:
                incident = self.incident_queue.get(timeout=1)
                self._handle_incident(incident)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing incident: {e}")
    
    def _handle_incident(self, incident: Incident) -> None:
        """
        Handle an incident by executing matching playbooks
        
        Args:
            incident: Incident to handle
        """
        logger.info(f"Handling incident: {incident.id}")
        
        # Find matching playbooks
        matching_playbooks = []
        for playbook in self.playbooks.values():
            if playbook.enabled and playbook.matches_incident(incident):
                matching_playbooks.append(playbook)
        
        # Sort by specificity (more triggers = more specific)
        matching_playbooks.sort(key=lambda p: len(p.triggers), reverse=True)
        
        if matching_playbooks:
            # Execute first matching playbook
            playbook = matching_playbooks[0]
            incident.playbook_executed = playbook.name
            self._execute_playbook(incident, playbook)
        else:
            logger.info(f"No matching playbook for incident: {incident.id}")
    
    def _execute_playbook(self, incident: Incident, playbook: Playbook) -> None:
        """
        Execute a response playbook
        
        Args:
            incident: Incident
            playbook: Playbook to execute
        """
        logger.info(f"Executing playbook '{playbook.name}' for incident {incident.id}")
        
        incident.status = IncidentStatus.INVESTIGATING
        incident.updated_at = time.time()
        
        for step in playbook.steps:
            try:
                action = step.get("action")
                params = step.get("params", {})
                
                result = self._execute_action(incident, action, params)
                
                incident.actions_taken.append({
                    "action": action,
                    "params": params,
                    "result": result,
                    "timestamp": time.time()
                })
                
                logger.info(f"Executed action: {action} for incident {incident.id}")
                
            except Exception as e:
                logger.error(f"Error executing action {step.get('action')}: {e}")
                incident.notes.append({
                    "type": "error",
                    "message": f"Action failed: {step.get('action')} - {e}",
                    "timestamp": time.time()
                })
        
        with self.lock:
            self.stats["playbooks_executed"] += 1
        
        logger.info(f"Playbook execution completed for incident {incident.id}")
    
    def _execute_action(self, incident: Incident, action: str, params: Dict) -> Any:
        """
        Execute a single response action
        
        Args:
            incident: Incident
            action: Action name
            params: Action parameters
            
        Returns:
            Action result
        """
        if action == "quarantine_ip":
            if self.quarantine and incident.affected_ips:
                return self.quarantine.quarantine_ip(
                    ip=incident.affected_ips[0],
                    reason=QuarantineReason.MALICIOUS,
                    source="incident_handler",
                    duration=params.get("duration", 3600),
                    description=f"Quarantined by incident {incident.id}"
                )
        
        elif action == "temporary_block":
            # Implement temporary blocking
            if incident.affected_ips:
                logger.info(f"Temporarily blocking {incident.affected_ips[0]} for {params.get('duration', 900)}s")
                # Add to firewall temporarily
                return {"status": "blocked", "ip": incident.affected_ips[0]}
        
        elif action == "block_firewall":
            # Implement firewall blocking
            if incident.affected_ips:
                logger.info(f"Adding firewall block for {incident.affected_ips[0]}")
                return {"status": "blocked", "permanent": params.get("permanent", False)}
        
        elif action == "rate_limit":
            # Implement rate limiting
            if incident.affected_ips:
                logger.info(f"Rate limiting {incident.affected_ips[0]} to {params.get('limit')}")
                return {"status": "rate_limited", "ip": incident.affected_ips[0]}
        
        elif action == "notify_soc":
            # Send notification to SOC
            channel = params.get("channel", "slack")
            logger.info(f"Notifying SOC via {channel} about incident {incident.id}")
            return {"status": "notified", "channel": channel}
        
        elif action == "notify_admin":
            channel = params.get("channel", "email")
            logger.info(f"Notifying admin via {channel} about incident {incident.id}")
            return {"status": "notified", "channel": channel}
        
        elif action == "create_ticket":
            # Create ticket in external system
            priority = params.get("priority", "medium")
            logger.info(f"Creating {priority} priority ticket for incident {incident.id}")
            return {"status": "ticket_created", "ticket_id": f"TKT-{int(time.time())}"}
        
        elif action == "increase_monitoring":
            # Increase monitoring for affected IPs
            duration = params.get("duration", 300)
            if incident.affected_ips:
                logger.info(f"Increasing monitoring for {incident.affected_ips[0]} for {duration}s")
                return {"status": "monitoring_increased", "duration": duration}
        
        elif action == "capture_forensics":
            # Capture forensic data
            depth = params.get("depth", "basic")
            logger.info(f"Capturing forensic data (depth: {depth}) for incident {incident.id}")
            return {"status": "forensics_captured", "depth": depth}
        
        elif action == "log_incident":
            # Just log the incident
            logger.info(f"Incident logged: {incident.id}")
            return {"status": "logged"}
        
        else:
            logger.warning(f"Unknown action: {action}")
            return {"status": "unknown_action"}
    
    def update_incident_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        notes: Optional[str] = None
    ) -> bool:
        """
        Update incident status
        
        Args:
            incident_id: Incident ID
            status: New status
            notes: Optional notes
            
        Returns:
            True if updated
        """
        with self.lock:
            if incident_id not in self.incidents:
                return False
            
            incident = self.incidents[incident_id]
            old_status = incident.status
            incident.status = status
            incident.updated_at = time.time()
            
            if notes:
                incident.notes.append({
                    "type": "status_change",
                    "message": notes,
                    "timestamp": time.time()
                })
            
            # Update statistics
            if old_status != status:
                if status == IncidentStatus.RESOLVED or status == IncidentStatus.CLOSED:
                    self.stats["open_incidents"] -= 1
                    self.stats["resolved_incidents"] += 1
                elif status == IncidentStatus.FALSE_POSITIVE:
                    self.stats["open_incidents"] -= 1
                    self.stats["false_positives"] += 1
            
            logger.info(f"Incident {incident_id} status changed: {old_status.value} -> {status.value}")
            return True
    
    def add_incident_note(self, incident_id: str, note: str, author: str = "system") -> bool:
        """
        Add note to incident
        
        Args:
            incident_id: Incident ID
            note: Note text
            author: Note author
            
        Returns:
            True if added
        """
        with self.lock:
            if incident_id not in self.incidents:
                return False
            
            self.incidents[incident_id].notes.append({
                "type": "note",
                "author": author,
                "message": note,
                "timestamp": time.time()
            })
            
            return True
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        with self.lock:
            return self.incidents.get(incident_id)
    
    def get_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        limit: int = 100
    ) -> List[Incident]:
        """
        Get incidents with filters
        
        Args:
            status: Filter by status
            severity: Filter by severity
            limit: Maximum number to return
            
        Returns:
            List of incidents
        """
        with self.lock:
            incidents = list(self.incidents.values())
            
            if status:
                incidents = [i for i in incidents if i.status == status]
            
            if severity:
                incidents = [i for i in incidents if i.severity == severity]
            
            # Sort by timestamp (newest first)
            incidents.sort(key=lambda i: i.timestamp, reverse=True)
            
            return incidents[:limit]
    
    def get_statistics(self) -> Dict:
        """Get incident statistics"""
        with self.lock:
            severity_counts = defaultdict(int)
            status_counts = defaultdict(int)
            
            for incident in self.incidents.values():
                severity_counts[incident.severity.value] += 1
                status_counts[incident.status.value] += 1
            
            return {
                "total_incidents": self.stats["total_incidents"],
                "open_incidents": self.stats["open_incidents"],
                "resolved_incidents": self.stats["resolved_incidents"],
                "false_positives": self.stats["false_positives"],
                "playbooks_executed": self.stats["playbooks_executed"],
                "by_severity": dict(severity_counts),
                "by_status": dict(status_counts)
            }
    
    def shutdown(self) -> None:
        """Shutdown incident handler"""
        logger.info("Shutting down incident handler...")
        self.running = False
        if self.worker.is_alive():
            self.worker.join(timeout=5)
        logger.info("Incident handler stopped")
