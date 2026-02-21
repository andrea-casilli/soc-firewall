import time
import json
import smtplib
import requests
import threading
import queue
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(Enum):
    """Alert notification channels"""
    LOG = "log"
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SYSLOG = "syslog"
    SNMP = "snmp"
    PAGER = "pager"


@dataclass
class Alert:
    """Security alert"""
    id: str
    timestamp: float
    source: str  # ids, threat_intel, anomaly, system
    severity: AlertSeverity
    title: str
    message: str
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None
    rule_name: Optional[str] = None
    category: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    raw_data: Optional[Dict] = None
    tags: List[str] = field(default_factory=list)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[float] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "signature_id": self.signature_id,
            "signature_name": self.signature_name,
            "rule_name": self.rule_name,
            "category": self.category,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "tags": self.tags,
            "acknowledged": self.acknowledged
        }


@dataclass
class AlertRule:
    """Alert generation rule"""
    name: str
    condition: Callable[[Any], bool]
    severity: AlertSeverity
    template: str
    enabled: bool = True
    throttle_seconds: int = 0
    last_triggered: float = 0


class AlertManager:
    """
    Alert management and notification system
    
    Features:
    - Alert generation from multiple sources
    - Multi-channel notifications
    - Alert deduplication and throttling
    - Persistent storage
    - Acknowledgement tracking
    - Escalation policies
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize alert manager
        
        Args:
            config_path: Path to configuration file
        """
        self.alerts: Dict[str, Alert] = {}
        self.alert_queue = queue.Queue()
        self.rules: List[AlertRule] = []
        
        # Notification channels
        self.channels: Dict[AlertChannel, Dict] = {
            AlertChannel.LOG: {"enabled": True},
            AlertChannel.EMAIL: {"enabled": False},
            AlertChannel.SLACK: {"enabled": False},
            AlertChannel.WEBHOOK: {"enabled": False}
        }
        
        # Statistics
        self.stats = {
            "total_alerts": 0,
            "alerts_by_severity": defaultdict(int),
            "alerts_by_source": defaultdict(int),
            "notifications_sent": 0
        }
        
        self.lock = threading.RLock()
        
        # Load configuration
        if config_path:
            self._load_config(config_path)
        
        # Load default rules
        self._load_default_rules()
        
        # Start worker thread
        self.running = True
        self.worker = threading.Thread(target=self._process_alerts, daemon=True)
        self.worker.start()
        
        logger.info("Alert Manager initialized")
    
    def _load_config(self, config_path: str) -> None:
        """Load configuration from file"""
        try:
            path = Path(config_path)
            if path.exists():
                with open(path, 'r') as f:
                    config = json.load(f)
                
                # Load channel configurations
                channel_config = config.get("channels", {})
                
                if "email" in channel_config:
                    self.channels[AlertChannel.EMAIL] = {
                        "enabled": True,
                        "smtp_server": channel_config["email"].get("smtp_server", "localhost"),
                        "smtp_port": channel_config["email"].get("smtp_port", 25),
                        "from_addr": channel_config["email"].get("from_addr"),
                        "to_addrs": channel_config["email"].get("to_addrs", []),
                        "username": channel_config["email"].get("username"),
                        "password": channel_config["email"].get("password"),
                        "use_tls": channel_config["email"].get("use_tls", False)
                    }
                
                if "slack" in channel_config:
                    self.channels[AlertChannel.SLACK] = {
                        "enabled": True,
                        "webhook_url": channel_config["slack"].get("webhook_url"),
                        "channel": channel_config["slack"].get("channel", "#alerts"),
                        "username": channel_config["slack"].get("username", "SOC Firewall")
                    }
                
                if "webhook" in channel_config:
                    self.channels[AlertChannel.WEBHOOK] = {
                        "enabled": True,
                        "url": channel_config["webhook"].get("url"),
                        "headers": channel_config["webhook"].get("headers", {}),
                        "method": channel_config["webhook"].get("method", "POST")
                    }
                
                logger.info("Alert manager configuration loaded")
                
        except Exception as e:
            logger.error(f"Error loading alert config: {e}")
    
    def _load_default_rules(self) -> None:
        """Load default alert rules"""
        # These would be defined based on your detection logic
        pass
    
    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule"""
        with self.lock:
            self.rules.append(rule)
    
    def create_alert(
        self,
        source: str,
        severity: AlertSeverity,
        title: str,
        message: str,
        signature_id: Optional[str] = None,
        signature_name: Optional[str] = None,
        rule_name: Optional[str] = None,
        category: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        raw_data: Optional[Dict] = None,
        tags: Optional[List[str]] = None
    ) -> Alert:
        """
        Create a new alert
        
        Args:
            source: Alert source
            severity: Alert severity
            title: Alert title
            message: Alert message
            signature_id: Signature ID
            signature_name: Signature name
            rule_name: Rule name
            category: Alert category
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol
            raw_data: Raw data
            tags: Alert tags
            
        Returns:
            Created alert
        """
        alert_id = f"ALT-{int(time.time())}-{hash(title + str(time.time())) % 10000:04d}"
        
        alert = Alert(
            id=alert_id,
            timestamp=time.time(),
            source=source,
            severity=severity,
            title=title,
            message=message,
            signature_id=signature_id,
            signature_name=signature_name,
            rule_name=rule_name,
            category=category,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            raw_data=raw_data,
            tags=tags or []
        )
        
        with self.lock:
            self.alerts[alert_id] = alert
            self.stats["total_alerts"] += 1
            self.stats["alerts_by_severity"][severity.value] += 1
            self.stats["alerts_by_source"][source] += 1
        
        # Queue for processing
        self.alert_queue.put(alert)
        
        # Log alert
        log_level = {
            AlertSeverity.INFO: "info",
            AlertSeverity.LOW: "info",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.HIGH: "error",
            AlertSeverity.CRITICAL: "critical"
        }.get(severity, "info")
        
        logger.log(
            getattr(logging, log_level.upper()),
            f"Alert [{severity.value.upper()}]: {title} - {message}"
        )
        
        return alert
    
    def create_from_detection(self, detection_result, packet_metadata) -> Optional[Alert]:
        """
        Create alert from IDS detection result
        
        Args:
            detection_result: Detection result
            packet_metadata: Packet metadata
            
        Returns:
            Created alert or None
        """
        if not detection_result.detected:
            return None
        
        severity_map = {
            "info": AlertSeverity.INFO,
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL
        }
        
        severity = severity_map.get(detection_result.severity.value, AlertSeverity.MEDIUM)
        
        return self.create_alert(
            source="ids",
            severity=severity,
            title=detection_result.signature_name or "IDS Alert",
            message=f"Detection: {detection_result.signature_name}",
            signature_id=detection_result.signature_id,
            signature_name=detection_result.signature_name,
            category=detection_result.metadata.get("category"),
            src_ip=detection_result.src_ip,
            dst_ip=detection_result.dst_ip,
            protocol=detection_result.protocol,
            dst_port=detection_result.port,
            raw_data=detection_result.metadata,
            tags=[detection_result.severity.value, "ids"]
        )
    
    def _process_alerts(self) -> None:
        """Worker thread to process alerts"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._send_notifications(alert)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    
    def _send_notifications(self, alert: Alert) -> None:
        """
        Send alert notifications to configured channels
        
        Args:
            alert: Alert to notify about
        """
        # Log channel
        if self.channels[AlertChannel.LOG]["enabled"]:
            self._send_log(alert)
        
        # Email channel
        if self.channels[AlertChannel.EMAIL]["enabled"]:
            if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                self._send_email(alert)
        
        # Slack channel
        if self.channels[AlertChannel.SLACK]["enabled"]:
            if alert.severity != AlertSeverity.INFO:
                self._send_slack(alert)
        
        # Webhook channel
        if self.channels[AlertChannel.WEBHOOK]["enabled"]:
            if alert.severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                self._send_webhook(alert)
        
        with self.lock:
            self.stats["notifications_sent"] += 1
    
    def _send_log(self, alert: Alert) -> None:
        """Send alert to log"""
        # Already logged in create_alert
        pass
    
    def _send_email(self, alert: Alert) -> None:
        """Send alert via email"""
        try:
            config = self.channels[AlertChannel.EMAIL]
            
            msg = MIMEMultipart()
            msg["From"] = config["from_addr"]
            msg["To"] = ", ".join(config["to_addrs"])
            msg["Subject"] = f"[SOC ALERT] {alert.severity.value.upper()}: {alert.title}"
            
            body = f"""
            Alert ID: {alert.id}
            Time: {time.ctime(alert.timestamp)}
            Severity: {alert.severity.value}
            Source: {alert.source}
            
            Title: {alert.title}
            Message: {alert.message}
            
            Details:
            - Signature: {alert.signature_name} ({alert.signature_id})
            - Category: {alert.category}
            - Source IP: {alert.src_ip}
            - Destination IP: {alert.dst_ip}
            - Protocol: {alert.protocol}
            - Port: {alert.dst_port}
            
            Tags: {', '.join(alert.tags)}
            """
            
            msg.attach(MIMEText(body, "plain"))
            
            # Send email
            server = smtplib.SMTP(config["smtp_server"], config["smtp_port"])
            if config.get("use_tls"):
                server.starttls()
            if config.get("username") and config.get("password"):
                server.login(config["username"], config["password"])
            
            server.send_message(msg)
            server.quit()
            
            logger.debug(f"Email notification sent for alert {alert.id}")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
    
    def _send_slack(self, alert: Alert) -> None:
        """Send alert via Slack"""
        try:
            config = self.channels[AlertChannel.SLACK]
            
            # Determine color based on severity
            colors = {
                "info": "#808080",
                "low": "#0000FF",
                "medium": "#FFFF00",
                "high": "#FFA500",
                "critical": "#FF0000"
            }
            color = colors.get(alert.severity.value, "#808080")
            
            # Create message
            message = {
                "channel": config["channel"],
                "username": config["username"],
                "attachments": [
                    {
                        "color": color,
                        "title": f"[{alert.severity.value.upper()}] {alert.title}",
                        "text": alert.message,
                        "fields": [
                            {"title": "Alert ID", "value": alert.id, "short": True},
                            {"title": "Source", "value": alert.source, "short": True},
                            {"title": "Signature", "value": alert.signature_name or "N/A", "short": True},
                            {"title": "Category", "value": alert.category or "N/A", "short": True},
                            {"title": "Source IP", "value": alert.src_ip or "N/A", "short": True},
                            {"title": "Destination", "value": f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_ip else "N/A", "short": True}
                        ],
                        "footer": "SOC Firewall",
                        "ts": int(alert.timestamp)
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(
                config["webhook_url"],
                json=message,
                timeout=5
            )
            
            if response.status_code != 200:
                logger.error(f"Slack API error: {response.status_code} - {response.text}")
            
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    def _send_webhook(self, alert: Alert) -> None:
        """Send alert via webhook"""
        try:
            config = self.channels[AlertChannel.WEBHOOK]
            
            # Prepare payload
            payload = alert.to_dict()
            
            # Send webhook
            if config["method"].upper() == "POST":
                response = requests.post(
                    config["url"],
                    json=payload,
                    headers=config["headers"],
                    timeout=5
                )
            else:
                response = requests.get(
                    config["url"],
                    params=payload,
                    headers=config["headers"],
                    timeout=5
                )
            
            if response.status_code not in [200, 201, 202, 204]:
                logger.error(f"Webhook error: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """
        Acknowledge an alert
        
        Args:
            alert_id: Alert ID
            user: User acknowledging
            
        Returns:
            True if acknowledged
        """
        with self.lock:
            if alert_id not in self.alerts:
                return False
            
            alert = self.alerts[alert_id]
            alert.acknowledged = True
            alert.acknowledged_by = user
            alert.acknowledged_at = time.time()
            
            logger.info(f"Alert {alert_id} acknowledged by {user}")
            return True
    
    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        source: Optional[str] = None,
        limit: int = 100,
        unacknowledged_only: bool = False
    ) -> List[Alert]:
        """
        Get alerts with filters
        
        Args:
            severity: Filter by severity
            source: Filter by source
            limit: Maximum number to return
            unacknowledged_only: Only unacknowledged alerts
            
        Returns:
            List of alerts
        """
        with self.lock:
            alerts = list(self.alerts.values())
            
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            if source:
                alerts = [a for a in alerts if a.source == source]
            
            if unacknowledged_only:
                alerts = [a for a in alerts if not a.acknowledged]
            
            # Sort by timestamp (newest first)
            alerts.sort(key=lambda a: a.timestamp, reverse=True)
            
            return alerts[:limit]
    
    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        with self.lock:
            unacknowledged = len([a for a in self.alerts.values() if not a.acknowledged])
            
            return {
                "total_alerts": self.stats["total_alerts"],
                "unacknowledged": unacknowledged,
                "notifications_sent": self.stats["notifications_sent"],
                "by_severity": dict(self.stats["alerts_by_severity"]),
                "by_source": dict(self.stats["alerts_by_source"])
            }
    
    def shutdown(self) -> None:
        """Shutdown alert manager"""
        logger.info("Shutting down alert manager...")
        self.running = False
        if self.worker.is_alive():
            self.worker.join(timeout=5)
        logger.info("Alert manager stopped")
