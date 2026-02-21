import os
import sys
import logging
import logging.handlers
import json
import time
import traceback
from typing import Dict, Optional, Any
from datetime import datetime
from pathlib import Path
from pythonjsonlogger import jsonlogger

# Log levels mapping
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

# Default log format
DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
JSON_FORMAT = '%(timestamp)s %(level)s %(name)s %(module)s %(lineno)d %(message)s'


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging"""
    
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['level'] = record.levelname
        log_record['module'] = record.module
        log_record['line'] = record.lineno
        
        if hasattr(record, 'component'):
            log_record['component'] = record.component
        
        if hasattr(record, 'src_ip'):
            log_record['src_ip'] = record.src_ip
        
        if hasattr(record, 'dst_ip'):
            log_record['dst_ip'] = record.dst_ip
        
        if hasattr(record, 'protocol'):
            log_record['protocol'] = record.protocol


class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter for adding contextual information
    """
    
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})
    
    def process(self, msg, kwargs):
        # Add extra context to log records
        kwargs['extra'] = kwargs.get('extra', {})
        kwargs['extra'].update(self.extra)
        return msg, kwargs
    
    def with_fields(self, **fields):
        """Create a new adapter with additional fields"""
        new_extra = self.extra.copy()
        new_extra.update(fields)
        return LoggerAdapter(self.logger, new_extra)


def setup_logging(
    log_dir: str = "logs",
    log_level: str = "info",
    json_format: bool = False,
    max_bytes: int = 10485760,  # 10MB
    backup_count: int = 5,
    console_output: bool = True
) -> None:
    """
    Setup logging configuration
    
    Args:
        log_dir: Directory for log files
        log_level: Log level (debug, info, warning, error, critical)
        json_format: Use JSON format
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        console_output: Output to console
    """
    # Create log directory
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    # Get log level
    level = LOG_LEVELS.get(log_level.lower(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Create formatters
    if json_format:
        formatter = CustomJsonFormatter(JSON_FORMAT)
    else:
        formatter = logging.Formatter(DEFAULT_FORMAT)
    
    # File handler with rotation
    log_file = log_path / "soc_firewall.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    root_logger.addHandler(file_handler)
    
    # Error file handler (only errors and above)
    error_file = log_path / "error.log"
    error_handler = logging.handlers.RotatingFileHandler(
        error_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)
    
    # Create component loggers
    components = [
        'core', 'detection', 'response', 'api', 'utils',
        'packet_engine', 'ids_engine', 'alert_manager'
    ]
    
    for component in components:
        logger = logging.getLogger(f'soc.{component}')
        logger.setLevel(level)
    
    # Log startup
    root_logger.info(f"Logging initialized - Level: {log_level}, JSON: {json_format}")


def get_logger(name: str, component: Optional[str] = None) -> LoggerAdapter:
    """
    Get a logger instance with component context
    
    Args:
        name: Logger name
        component: Component name for context
        
    Returns:
        LoggerAdapter instance
    """
    if component:
        logger_name = f"soc.{component}.{name}"
    else:
        logger_name = f"soc.{name}"
    
    logger = logging.getLogger(logger_name)
    
    # Add component to extra context
    extra = {'component': component or name}
    
    return LoggerAdapter(logger, extra)


class AuditLogger:
    """
    Specialized logger for audit events
    Writes to separate audit log file
    """
    
    def __init__(self, log_dir: str = "logs"):
        """
        Initialize audit logger
        
        Args:
            log_dir: Directory for audit logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create audit logger
        self.logger = logging.getLogger('soc.audit')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        
        # File handler
        audit_file = self.log_dir / "audit.log"
        handler = logging.handlers.RotatingFileHandler(
            audit_file,
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        
        # JSON formatter
        formatter = CustomJsonFormatter(JSON_FORMAT)
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def log(self, event_type: str, user: str, action: str, resource: str,
            result: str, details: Optional[Dict] = None, ip: Optional[str] = None) -> None:
        """
        Log an audit event
        
        Args:
            event_type: Type of event
            user: User performing action
            action: Action performed
            resource: Resource affected
            result: Result (success/failure)
            details: Additional details
            ip: IP address
        """
        extra = {
            'event_type': event_type,
            'user': user,
            'action': action,
            'resource': resource,
            'result': result,
            'ip': ip,
            'details': details or {}
        }
        
        self.logger.info(f"Audit: {action} on {resource}", extra=extra)


# Global audit logger instance
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get or create audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
