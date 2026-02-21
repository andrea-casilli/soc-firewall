import ipaddress
import re
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigValidationError(Exception):
    """Configuration validation error"""
    pass


@dataclass
class ValidationResult:
    """Result of configuration validation"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def add_error(self, error: str) -> None:
        """Add error message"""
        self.errors.append(error)
        self.valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add warning message"""
        self.warnings.append(warning)
    
    def merge(self, other: 'ValidationResult') -> None:
        """Merge another validation result"""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        self.valid = self.valid and other.valid


def validate_ip(ip: str) -> bool:
    """
    Validate IP address
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number
        
    Returns:
        True if valid
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_subnet(subnet: str) -> bool:
    """
    Validate subnet in CIDR notation
    
    Args:
        subnet: Subnet string (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid
    """
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def validate_interface(interface: str) -> bool:
    """
    Validate network interface name
    
    Args:
        interface: Interface name
        
    Returns:
        True if valid format
    """
    # Basic interface name validation
    pattern = r'^[a-zA-Z0-9_\.\-]+$'
    return bool(re.match(pattern, interface))


def validate_log_level(level: str) -> bool:
    """
    Validate log level
    
    Args:
        level: Log level string
        
    Returns:
        True if valid
    """
    valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
    return level.lower() in valid_levels


def validate_protocol(protocol: str) -> bool:
    """
    Validate protocol name
    
    Args:
        protocol: Protocol name
        
    Returns:
        True if valid
    """
    valid_protocols = ['tcp', 'udp', 'icmp', 'all']
    return protocol.lower() in valid_protocols


def validate_action(action: str) -> bool:
    """
    Validate firewall action
    
    Args:
        action: Action name
        
    Returns:
        True if valid
    """
    valid_actions = ['allow', 'drop', 'reject', 'log', 'alert']
    return action.lower() in valid_actions


def validate_threshold(value: Union[int, float], name: str, 
                       min_val: Optional[Union[int, float]] = None,
                       max_val: Optional[Union[int, float]] = None) -> List[str]:
    """
    Validate threshold value
    
    Args:
        value: Value to validate
        name: Parameter name
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        
    Returns:
        List of error messages
    """
    errors = []
    
    if not isinstance(value, (int, float)):
        errors.append(f"{name} must be a number")
        return errors
    
    if min_val is not None and value < min_val:
        errors.append(f"{name} must be >= {min_val}")
    
    if max_val is not None and value > max_val:
        errors.append(f"{name} must be <= {max_val}")
    
    return errors


def validate_firewall_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate firewall configuration
    
    Args:
        config: Firewall configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Interface validation
    interface = config.get('interface', 'eth0')
    if not validate_interface(interface):
        result.add_error(f"Invalid interface name: {interface}")
    
    # Number of workers
    num_workers = config.get('num_workers', 4)
    worker_errors = validate_threshold(num_workers, 'num_workers', min_val=1, max_val=32)
    for error in worker_errors:
        result.add_error(error)
    
    # Queue size
    queue_size = config.get('queue_size', 10000)
    queue_errors = validate_threshold(queue_size, 'queue_size', min_val=100, max_val=1000000)
    for error in queue_errors:
        result.add_error(error)
    
    # Max connections
    max_connections = config.get('max_connections', 100000)
    conn_errors = validate_threshold(max_connections, 'max_connections', min_val=100, max_val=10000000)
    for error in conn_errors:
        result.add_error(error)
    
    # Connection timeout
    timeout = config.get('connection_timeout', 300)
    timeout_errors = validate_threshold(timeout, 'connection_timeout', min_val=10, max_val=86400)
    for error in timeout_errors:
        result.add_error(error)
    
    # Default action
    default_action = config.get('default_action', 'allow')
    if not validate_action(default_action):
        result.add_error(f"Invalid default action: {default_action}")
    
    # Internal networks
    internal_networks = config.get('internal_networks', [])
    for network in internal_networks:
        if not validate_subnet(network):
            result.add_warning(f"Invalid internal network: {network}")
    
    return result


def validate_detection_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate detection configuration
    
    Args:
        config: Detection configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Thresholds
    thresholds = [
        ('port_scan_threshold', 50, 1, 1000),
        ('syn_flood_threshold', 100, 1, 10000),
        ('dos_threshold', 1000, 10, 100000),
        ('bruteforce_threshold', 10, 1, 1000),
        ('icmp_flood_threshold', 50, 1, 5000)
    ]
    
    for name, default, min_val, max_val in thresholds:
        value = config.get(name, default)
        errors = validate_threshold(value, name, min_val, max_val)
        for error in errors:
            result.add_error(error)
    
    # Signature directory
    sig_dir = config.get('signature_dir', 'config/signatures')
    if not isinstance(sig_dir, str):
        result.add_error("signature_dir must be a string")
    
    # Threat feeds
    threat_feeds = config.get('threat_feeds', [])
    if not isinstance(threat_feeds, list):
        result.add_error("threat_feeds must be a list")
    else:
        for i, feed in enumerate(threat_feeds):
            if not isinstance(feed, dict):
                result.add_error(f"Threat feed {i} must be a dictionary")
                continue
            
            if 'name' not in feed:
                result.add_error(f"Threat feed {i} missing 'name'")
            if 'url' not in feed:
                result.add_error(f"Threat feed {i} missing 'url'")
    
    return result


def validate_response_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate response configuration
    
    Args:
        config: Response configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Quarantine duration
    duration = config.get('quarantine_default_duration', 3600)
    duration_errors = validate_threshold(duration, 'quarantine_default_duration', 
                                         min_val=60, max_val=2592000)  # 1 min to 30 days
    for error in duration_errors:
        result.add_error(error)
    
    # Alert channels
    channels = config.get('alert_channels', ['log'])
    if not isinstance(channels, list):
        result.add_error("alert_channels must be a list")
    else:
        valid_channels = ['log', 'email', 'slack', 'webhook', 'syslog']
        for channel in channels:
            if channel not in valid_channels:
                result.add_warning(f"Unknown alert channel: {channel}")
    
    # Email configuration
    if 'smtp_server' in config and config['smtp_server']:
        smtp_port = config.get('smtp_port', 25)
        port_errors = validate_threshold(smtp_port, 'smtp_port', min_val=1, max_val=65535)
        for error in port_errors:
            result.add_error(error)
    
    # Webhook configuration
    if 'webhook_url' in config and config['webhook_url']:
        webhook_url = config['webhook_url']
        if not webhook_url.startswith(('http://', 'https://')):
            result.add_error(f"Invalid webhook URL: {webhook_url}")
    
    return result


def validate_api_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate API configuration
    
    Args:
        config: API configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # REST API ports
    rest_port = config.get('rest_port', 5000)
    port_errors = validate_threshold(rest_port, 'rest_port', min_val=1, max_val=65535)
    for error in port_errors:
        result.add_error(error)
    
    # WebSocket ports
    ws_port = config.get('websocket_port', 8765)
    port_errors = validate_threshold(ws_port, 'websocket_port', min_val=1, max_val=65535)
    for error in port_errors:
        result.add_error(error)
    
    # Token expiry
    token_expiry = config.get('token_expiry', 86400)
    expiry_errors = validate_threshold(token_expiry, 'token_expiry', min_val=60, max_val=31536000)
    for error in expiry_errors:
        result.add_error(error)
    
    # Rate limit
    rate_limit = config.get('rate_limit', 100)
    rate_errors = validate_threshold(rate_limit, 'rate_limit', min_val=1, max_val=10000)
    for error in rate_errors:
        result.add_error(error)
    
    # API tokens
    api_tokens = config.get('api_tokens', {})
    if not isinstance(api_tokens, dict):
        result.add_error("api_tokens must be a dictionary")
    else:
        for token, token_data in api_tokens.items():
            if not isinstance(token_data, dict):
                result.add_error(f"Token {token} data must be a dictionary")
                continue
            
            if 'permissions' not in token_data:
                result.add_error(f"Token {token} missing 'permissions'")
            if 'expiry' not in token_data:
                result.add_error(f"Token {token} missing 'expiry'")
    
    # CORS origins
    origins = config.get('allowed_origins', ['*'])
    if not isinstance(origins, list):
        result.add_error("allowed_origins must be a list")
    
    return result


def validate_logging_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate logging configuration
    
    Args:
        config: Logging configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Log level
    log_level = config.get('log_level', 'info')
    if not validate_log_level(log_level):
        result.add_error(f"Invalid log level: {log_level}")
    
    # Log format
    log_format = config.get('log_format', 'json')
    if log_format not in ['json', 'text']:
        result.add_error(f"Invalid log format: {log_format}")
    
    # Log size
    max_log_size = config.get('max_log_size', 10485760)
    size_errors = validate_threshold(max_log_size, 'max_log_size', min_val=1024, max_val=1073741824)
    for error in size_errors:
        result.add_error(error)
    
    # Backup count
    backup_count = config.get('backup_count', 5)
    count_errors = validate_threshold(backup_count, 'backup_count', min_val=0, max_val=100)
    for error in count_errors:
        result.add_error(error)
    
    return result


def validate_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate complete configuration
    
    Args:
        config: Complete configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Validate each section
    sections = [
        ('firewall', validate_firewall_config),
        ('detection', validate_detection_config),
        ('response', validate_response_config),
        ('api', validate_api_config),
        ('logging', validate_logging_config)
    ]
    
    for section_name, validator in sections:
        section_config = config.get(section_name, {})
        section_result = validator(section_config)
        result.merge(section_result)
    
    # Environment validation
    environment = config.get('environment', 'production')
    if environment not in ['development', 'staging', 'production']:
        result.add_warning(f"Unknown environment: {environment}")
    
    # Config version
    config_version = config.get('config_version', '1.0.0')
    version_pattern = r'^\d+\.\d+\.\d+$'
    if not re.match(version_pattern, config_version):
        result.add_warning(f"Invalid config version format: {config_version}")
    
    if not result.valid:
        logger.error(f"Configuration validation failed: {result.errors}")
    
    return result


def validate_rule(rule: Dict[str, Any]) -> ValidationResult:
    """
    Validate a single firewall rule
    
    Args:
        rule: Rule dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Required fields
    required_fields = ['name', 'action', 'conditions']
    for field in required_fields:
        if field not in rule:
            result.add_error(f"Rule missing required field: {field}")
    
    if not result.valid:
        return result
    
    # Action validation
    action = rule.get('action', '').upper()
    if action not in ['ALLOW', 'DROP', 'REJECT', 'LOG', 'ALERT']:
        result.add_error(f"Invalid action: {action}")
    
    # Priority validation
    priority = rule.get('priority', 100)
    if not isinstance(priority, int) or priority < 0 or priority > 1000:
        result.add_error(f"Invalid priority: {priority}")
    
    # Conditions validation
    conditions = rule.get('conditions', [])
    if not isinstance(conditions, list):
        result.add_error("conditions must be a list")
    else:
        for i, condition in enumerate(conditions):
            if not isinstance(condition, dict):
                result.add_error(f"Condition {i} must be a dictionary")
                continue
            
            if 'field' not in condition:
                result.add_error(f"Condition {i} missing 'field'")
            if 'operator' not in condition:
                result.add_error(f"Condition {i} missing 'operator'")
            if 'value' not in condition:
                result.add_error(f"Condition {i} missing 'value'")
            
            # Validate operator
            operator = condition.get('operator')
            valid_operators = ['eq', 'ne', 'gt', 'lt', 'in', 'contains', 'matches', 'cidr']
            if operator not in valid_operators:
                result.add_error(f"Invalid operator: {operator}")
    
    return result


def validate_alert_config(alert_config: Dict[str, Any]) -> ValidationResult:
    """
    Validate alert configuration
    
    Args:
        alert_config: Alert configuration dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Severity mapping
    severity_map = alert_config.get('severity_mapping', {})
    valid_severities = ['info', 'low', 'medium', 'high', 'critical']
    
    for key, severity in severity_map.items():
        if severity not in valid_severities:
            result.add_warning(f"Invalid severity mapping: {key} -> {severity}")
    
    # Throttling
    throttle = alert_config.get('throttle_seconds', 0)
    if throttle < 0:
        result.add_error("throttle_seconds must be >= 0")
    
    return result


def validate_thresholds(thresholds: Dict[str, Any]) -> ValidationResult:
    """
    Validate threshold configuration
    
    Args:
        thresholds: Thresholds dictionary
        
    Returns:
        Validation result
    """
    result = ValidationResult(valid=True)
    
    # Define expected thresholds with min/max
    expected_thresholds = {
        'port_scan': (1, 10000),
        'syn_flood': (1, 100000),
        'dos': (10, 1000000),
        'bruteforce': (1, 1000),
        'icmp_flood': (1, 10000),
        'connection_rate': (1, 100000),
        'packet_rate': (1, 1000000)
    }
    
    for name, (min_val, max_val) in expected_thresholds.items():
        if name in thresholds:
            value = thresholds[name]
            errors = validate_threshold(value, name, min_val, max_val)
            for error in errors:
                result.add_error(error)
    
    return result
