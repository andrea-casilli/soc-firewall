"""
Settings Management Module
Centralized configuration management for SOC Firewall
"""

import os
import json
import yaml
import threading
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FirewallConfig:
    """Firewall core configuration"""
    interface: str = "eth0"
    promiscuous_mode: bool = False
    buffer_size: int = 65536
    snapshot_length: int = 0
    num_workers: int = 4
    queue_size: int = 10000
    block_external_ping: bool = True
    enable_stateful: bool = True
    max_connections: int = 100000
    connection_timeout: int = 300
    enable_nat: bool = False
    enable_logging: bool = True
    default_action: str = "allow"  # allow, drop, reject
    internal_networks: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    ])


@dataclass
class DetectionConfig:
    """Intrusion detection configuration"""
    enable_ids: bool = True
    enable_anomaly: bool = True
    enable_threat_intel: bool = True
    signature_dir: str = "config/signatures"
    threat_feeds: List[Dict[str, Any]] = field(default_factory=list)
    
    # Thresholds
    port_scan_threshold: int = 50
    syn_flood_threshold: int = 100
    dos_threshold: int = 1000
    bruteforce_threshold: int = 10
    icmp_flood_threshold: int = 50
    
    # Machine learning (if enabled)
    enable_ml: bool = False
    model_path: Optional[str] = None
    training_interval: int = 86400  # 24 hours
    
    # Protocol analysis
    check_protocol_anomalies: bool = True
    check_payload: bool = True
    max_payload_size: int = 65535


@dataclass
class ResponseConfig:
    """Automated response configuration"""
    enable_auto_response: bool = True
    enable_quarantine: bool = True
    quarantine_default_duration: int = 3600  # 1 hour
    enable_alerting: bool = True
    enable_notifications: bool = True
    
    # Alert channels
    alert_channels: List[str] = field(default_factory=lambda: ["log"])
    
    # Email configuration
    smtp_server: Optional[str] = None
    smtp_port: int = 25
    email_from: Optional[str] = None
    email_to: List[str] = field(default_factory=list)
    
    # Slack configuration
    slack_webhook: Optional[str] = None
    slack_channel: str = "#alerts"
    
    # Webhook configuration
    webhook_url: Optional[str] = None
    webhook_headers: Dict[str, str] = field(default_factory=dict)
    
    # Playbook directory
    playbook_dir: str = "config/playbooks"


@dataclass
class APIConfig:
    """API configuration"""
    enable_rest_api: bool = True
    rest_host: str = "127.0.0.1"
    rest_port: int = 5000
    rest_debug: bool = False
    
    enable_websocket: bool = True
    websocket_host: str = "127.0.0.1"
    websocket_port: int = 8765
    
    # Authentication
    enable_auth: bool = True
    token_expiry: int = 86400  # 24 hours
    api_tokens: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # CORS
    enable_cors: bool = True
    allowed_origins: List[str] = field(default_factory=lambda: ["*"])
    
    # Rate limiting
    enable_rate_limit: bool = True
    rate_limit: int = 100  # requests per minute


@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_dir: str = "logs"
    log_level: str = "info"  # debug, info, warning, error, critical
    log_format: str = "json"  # json, text
    max_log_size: int = 10485760  # 10MB
    backup_count: int = 5
    console_output: bool = True
    enable_audit: bool = True
    audit_log_size: int = 10485760  # 10MB
    audit_backup_count: int = 10


@dataclass
class Settings:
    """Complete SOC Firewall settings"""
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    # System settings
    instance_id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    config_version: str = "1.0.0"
    environment: str = "production"  # development, staging, production
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            "firewall": asdict(self.firewall),
            "detection": asdict(self.detection),
            "response": asdict(self.response),
            "api": asdict(self.api),
            "logging": asdict(self.logging),
            "instance_id": self.instance_id,
            "config_version": self.config_version,
            "environment": self.environment
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Settings':
        """Create settings from dictionary"""
        settings = cls()
        
        if "firewall" in data:
            settings.firewall = FirewallConfig(**data["firewall"])
        if "detection" in data:
            settings.detection = DetectionConfig(**data["detection"])
        if "response" in data:
            settings.response = ResponseConfig(**data["response"])
        if "api" in data:
            settings.api = APIConfig(**data["api"])
        if "logging" in data:
            settings.logging = LoggingConfig(**data["logging"])
        
        settings.instance_id = data.get("instance_id", settings.instance_id)
        settings.config_version = data.get("config_version", settings.config_version)
        settings.environment = data.get("environment", settings.environment)
        
        return settings


class ConfigManager:
    """
    Configuration manager for SOC Firewall
    
    Features:
    - Load/save configuration from multiple formats (YAML, JSON)
    - Hot reload support
    - Configuration validation
    - Environment variable override
    - Thread-safe access
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.settings = Settings()
        self.lock = threading.RLock()
        self.watchers = []
        self.last_loaded = None
        self.watch_enabled = False
        
        # Load configuration if path provided
        if config_path:
            self.load(config_path)
        
        # Apply environment variable overrides
        self._apply_env_overrides()
        
        logger.info(f"Config manager initialized (version: {self.settings.config_version})")
    
    def load(self, config_path: str) -> bool:
        """
        Load configuration from file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if loaded successfully
        """
        try:
            path = Path(config_path)
            if not path.exists():
                logger.error(f"Configuration file not found: {config_path}")
                return False
            
            # Load based on file extension
            if path.suffix in ['.yaml', '.yml']:
                with open(path, 'r') as f:
                    data = yaml.safe_load(f)
            elif path.suffix == '.json':
                with open(path, 'r') as f:
                    data = json.load(f)
            else:
                logger.error(f"Unsupported config format: {path.suffix}")
                return False
            
            # Update settings
            with self.lock:
                self.settings = Settings.from_dict(data)
                self.config_path = config_path
                self.last_loaded = datetime.now()
            
            logger.info(f"Configuration loaded from {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def save(self, config_path: Optional[str] = None) -> bool:
        """
        Save configuration to file
        
        Args:
            config_path: Path to save to (defaults to current path)
            
        Returns:
            True if saved successfully
        """
        save_path = config_path or self.config_path
        if not save_path:
            logger.error("No save path specified")
            return False
        
        try:
            path = Path(save_path)
            data = self.settings.to_dict()
            
            # Save based on file extension
            if path.suffix in ['.yaml', '.yml']:
                with open(path, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False)
            elif path.suffix == '.json':
                with open(path, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                logger.error(f"Unsupported config format: {path.suffix}")
                return False
            
            logger.info(f"Configuration saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def _apply_env_overrides(self) -> None:
        """Override settings with environment variables"""
        # Firewall overrides
        if os.getenv("SOC_FW_INTERFACE"):
            self.settings.firewall.interface = os.getenv("SOC_FW_INTERFACE")
        
        if os.getenv("SOC_FW_WORKERS"):
            self.settings.firewall.num_workers = int(os.getenv("SOC_FW_WORKERS"))
        
        if os.getenv("SOC_FW_MAX_CONNECTIONS"):
            self.settings.firewall.max_connections = int(os.getenv("SOC_FW_MAX_CONNECTIONS"))
        
        # Detection overrides
        if os.getenv("SOC_DETECTION_ENABLE"):
            self.settings.detection.enable_ids = os.getenv("SOC_DETECTION_ENABLE").lower() == "true"
        
        # API overrides
        if os.getenv("SOC_API_ENABLE"):
            self.settings.api.enable_rest_api = os.getenv("SOC_API_ENABLE").lower() == "true"
        
        if os.getenv("SOC_API_PORT"):
            self.settings.api.rest_port = int(os.getenv("SOC_API_PORT"))
        
        # Logging overrides
        if os.getenv("SOC_LOG_LEVEL"):
            self.settings.logging.log_level = os.getenv("SOC_LOG_LEVEL")
        
        if os.getenv("SOC_LOG_DIR"):
            self.settings.logging.log_dir = os.getenv("SOC_LOG_DIR")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot notation key
        
        Args:
            key: Dot notation key (e.g., "firewall.interface")
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        parts = key.split('.')
        current = self.settings
        
        try:
            for part in parts:
                if hasattr(current, part):
                    current = getattr(current, part)
                elif isinstance(current, dict):
                    current = current[part]
                else:
                    return default
            return current
        except (AttributeError, KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """
        Set configuration value by dot notation key
        
        Args:
            key: Dot notation key
            value: Value to set
            
        Returns:
            True if set successfully
        """
        parts = key.split('.')
        current = self.settings
        
        try:
            for part in parts[:-1]:
                if hasattr(current, part):
                    current = getattr(current, part)
                elif isinstance(current, dict):
                    current = current[part]
                else:
                    return False
            
            last_part = parts[-1]
            if hasattr(current, last_part):
                setattr(current, last_part, value)
            elif isinstance(current, dict):
                current[last_part] = value
            else:
                return False
            
            # Notify watchers
            self._notify_watchers(key, value)
            
            return True
            
        except (AttributeError, KeyError, TypeError):
            return False
    
    def watch(self, callback) -> None:
        """
        Add configuration change watcher
        
        Args:
            callback: Function to call on changes
        """
        with self.lock:
            self.watchers.append(callback)
    
    def _notify_watchers(self, key: str, value: Any) -> None:
        """Notify watchers of configuration change"""
        for watcher in self.watchers:
            try:
                watcher(key, value)
            except Exception as e:
                logger.error(f"Error in config watcher: {e}")
    
    def enable_watch(self, interval: int = 5) -> None:
        """
        Enable configuration file watching for hot reload
        
        Args:
            interval: Check interval in seconds
        """
        if self.watch_enabled:
            return
        
        self.watch_enabled = True
        self.watch_thread = threading.Thread(
            target=self._watch_loop,
            args=(interval,),
            daemon=True,
            name="ConfigWatcher"
        )
        self.watch_thread.start()
        logger.info(f"Config file watching enabled (interval: {interval}s)")
    
    def _watch_loop(self, interval: int) -> None:
        """Watch for configuration file changes"""
        if not self.config_path:
            return
        
        last_mtime = Path(self.config_path).stat().st_mtime
        
        while self.watch_enabled:
            time.sleep(interval)
            
            try:
                current_mtime = Path(self.config_path).stat().st_mtime
                if current_mtime != last_mtime:
                    logger.info("Configuration file changed, reloading...")
                    old_settings = self.settings
                    if self.load(self.config_path):
                        self._notify_reload(old_settings, self.settings)
                    last_mtime = current_mtime
            except Exception as e:
                logger.error(f"Error watching config file: {e}")
    
    def _notify_reload(self, old: Settings, new: Settings) -> None:
        """Notify watchers of configuration reload"""
        for watcher in self.watchers:
            try:
                watcher("__reload__", {"old": old.to_dict(), "new": new.to_dict()})
            except Exception as e:
                logger.error(f"Error in config reload watcher: {e}")
    
    def disable_watch(self) -> None:
        """Disable configuration file watching"""
        self.watch_enabled = False
        if hasattr(self, 'watch_thread'):
            self.watch_thread.join(timeout=2)
        logger.info("Config file watching disabled")
    
    def validate(self) -> List[str]:
        """
        Validate current configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        from src.config.validators import validate_config
        result = validate_config(self.settings.to_dict())
        return result.errors
    
    def reset(self) -> None:
        """Reset to default configuration"""
        with self.lock:
            self.settings = Settings()
        logger.info("Configuration reset to defaults")


# Global config manager instance
_config_manager = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """Get or create global config manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


def load_config(config_path: str) -> Settings:
    """
    Load configuration from file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Settings object
    """
    manager = ConfigManager(config_path)
    return manager.settings
