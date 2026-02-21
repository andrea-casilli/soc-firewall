import json
import time
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime
from functools import wraps
import hmac
import hashlib

from flask import Flask, request, jsonify, g, abort
from flask_cors import CORS

from src.core.packet_engine import PacketProcessor
from src.core.filter_rules import FilterRules, Rule, RuleAction
from src.core.connection_tracker import ConnectionTracker
from src.detection.ids_engine import IDSEngine
from src.detection.threat_intel import ThreatIntelligence
from src.detection.anomaly_detector import AnomalyDetector
from src.response.incident_handler import IncidentHandler
from src.response.alert_manager import AlertManager, AlertSeverity
from src.response.quarantine import QuarantineManager, QuarantineReason
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Create Flask application
app = Flask(__name__)
CORS(app)

# API version
API_VERSION = "v1"

# Authentication tokens (in production, use proper auth system)
API_TOKENS = {}  # token: {permissions, expiry}

# Global references to components
components = {}


def require_auth(f):
    """Decorator for API authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            abort(401, description="Missing or invalid authorization header")
        
        token = auth_header.split(' ')[1]
        
        if token not in API_TOKENS:
            abort(401, description="Invalid API token")
        
        token_data = API_TOKENS[token]
        if token_data.get('expiry', 0) < time.time():
            abort(401, description="Token expired")
        
        g.token_data = token_data
        return f(*args, **kwargs)
    return decorated


def require_permission(permission: str):
    """Decorator for permission checking"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            permissions = g.token_data.get('permissions', [])
            if permission not in permissions and 'admin' not in permissions:
                abort(403, description=f"Missing required permission: {permission}")
            return f(*args, **kwargs)
        return decorated
    return decorator


class RestAPI:
    """
    RESTful API for firewall management
    
    Features:
    - Firewall status and statistics
    - Rule management (CRUD)
    - Alert retrieval and management
    - Incident management
    - Quarantine management
    - Connection tracking
    - Configuration management
    """
    
    def __init__(
        self,
        packet_processor: Optional[PacketProcessor] = None,
        filter_rules: Optional[FilterRules] = None,
        connection_tracker: Optional[ConnectionTracker] = None,
        ids_engine: Optional[IDSEngine] = None,
        threat_intel: Optional[ThreatIntelligence] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
        incident_handler: Optional[IncidentHandler] = None,
        alert_manager: Optional[AlertManager] = None,
        quarantine_manager: Optional[QuarantineManager] = None,
        host: str = "127.0.0.1",
        port: int = 5000,
        debug: bool = False,
        api_tokens: Optional[Dict[str, Dict]] = None
    ):
        """
        Initialize REST API
        
        Args:
            packet_processor: Packet processor instance
            filter_rules: Filter rules instance
            connection_tracker: Connection tracker instance
            ids_engine: IDS engine instance
            threat_intel: Threat intelligence instance
            anomaly_detector: Anomaly detector instance
            incident_handler: Incident handler instance
            alert_manager: Alert manager instance
            quarantine_manager: Quarantine manager instance
            host: Host to bind to
            port: Port to listen on
            debug: Debug mode
            api_tokens: API tokens for authentication
        """
        self.host = host
        self.port = port
        self.debug = debug
        self.server_thread = None
        self.running = False
        
        # Store component references globally for route access
        global components
        components = {
            'packet_processor': packet_processor,
            'filter_rules': filter_rules,
            'connection_tracker': connection_tracker,
            'ids_engine': ids_engine,
            'threat_intel': threat_intel,
            'anomaly_detector': anomaly_detector,
            'incident_handler': incident_handler,
            'alert_manager': alert_manager,
            'quarantine_manager': quarantine_manager
        }
        
        # Initialize API tokens
        global API_TOKENS
        API_TOKENS = api_tokens or self._generate_default_tokens()
        
        # Register routes
        self._register_routes()
        
        logger.info(f"REST API initialized on {host}:{port}")
    
    def _generate_default_tokens(self) -> Dict[str, Dict]:
        """Generate default API tokens"""
        # In production, load from secure configuration
        return {
            "soc_admin_token_2024": {
                "permissions": ["admin", "read", "write", "configure"],
                "expiry": time.time() + 31536000,  # 1 year
                "user": "admin"
            },
            "soc_readonly_token_2024": {
                "permissions": ["read"],
                "expiry": time.time() + 31536000,
                "user": "readonly"
            }
        }
    
    def _register_routes(self) -> None:
        """Register all API routes"""
        
        # System endpoints
        @app.route(f'/api/{API_VERSION}/status', methods=['GET'])
        @require_auth
        def get_status():
            """Get firewall status"""
            return jsonify({
                'status': 'running' if components.get('packet_processor') and components['packet_processor'].running else 'stopped',
                'timestamp': time.time(),
                'version': '1.0.0',
                'uptime': time.time() - components.get('packet_processor', {}).stats.get('start_time', time.time()) if components.get('packet_processor') else 0
            })
        
        @app.route(f'/api/{API_VERSION}/stats', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_statistics():
            """Get all statistics"""
            stats = {}
            
            if components.get('packet_processor'):
                stats['packet_engine'] = components['packet_processor'].stats
            
            if components.get('connection_tracker'):
                stats['connections'] = components['connection_tracker'].get_statistics()
            
            if components.get('ids_engine'):
                stats['ids'] = components['ids_engine'].get_statistics()
            
            if components.get('alert_manager'):
                stats['alerts'] = components['alert_manager'].get_statistics()
            
            if components.get('incident_handler'):
                stats['incidents'] = components['incident_handler'].get_statistics()
            
            if components.get('quarantine_manager'):
                stats['quarantine'] = components['quarantine_manager'].get_statistics()
            
            return jsonify(stats)
        
        # Control endpoints
        @app.route(f'/api/{API_VERSION}/start', methods=['POST'])
        @require_auth
        @require_permission('admin')
        def start_firewall():
            """Start the firewall"""
            if components.get('packet_processor') and not components['packet_processor'].running:
                thread = threading.Thread(target=components['packet_processor'].start, daemon=True)
                thread.start()
                return jsonify({'status': 'started', 'message': 'Firewall started'})
            return jsonify({'status': 'already_running', 'message': 'Firewall already running'})
        
        @app.route(f'/api/{API_VERSION}/stop', methods=['POST'])
        @require_auth
        @require_permission('admin')
        def stop_firewall():
            """Stop the firewall"""
            if components.get('packet_processor') and components['packet_processor'].running:
                components['packet_processor'].stop()
                return jsonify({'status': 'stopped', 'message': 'Firewall stopped'})
            return jsonify({'status': 'already_stopped', 'message': 'Firewall already stopped'})
        
        # Rule management endpoints
        @app.route(f'/api/{API_VERSION}/rules', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_rules():
            """Get all filter rules"""
            if not components.get('filter_rules'):
                return jsonify({'rules': []})
            
            rules = components['filter_rules'].get_rules()
            return jsonify({'rules': rules, 'count': len(rules)})
        
        @app.route(f'/api/{API_VERSION}/rules/<rule_name>', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_rule(rule_name: str):
            """Get specific rule"""
            if not components.get('filter_rules'):
                abort(404, description="Rule not found")
            
            rules = components['filter_rules'].get_rules()
            rule = next((r for r in rules if r['name'] == rule_name), None)
            
            if not rule:
                abort(404, description="Rule not found")
            
            return jsonify(rule)
        
        @app.route(f'/api/{API_VERSION}/rules', methods=['POST'])
        @require_auth
        @require_permission('write')
        def create_rule():
            """Create a new rule"""
            data = request.get_json()
            
            if not data:
                abort(400, description="Invalid request data")
            
            required_fields = ['name', 'action', 'conditions']
            for field in required_fields:
                if field not in data:
                    abort(400, description=f"Missing required field: {field}")
            
            # Create rule object
            rule = Rule(
                name=data['name'],
                action=RuleAction(data['action'].upper()),
                priority=data.get('priority', 100),
                enabled=data.get('enabled', True),
                description=data.get('description', '')
            )
            
            # Add conditions
            for cond_data in data.get('conditions', []):
                from src.core.filter_rules import RuleCondition
                condition = RuleCondition(
                    field=cond_data['field'],
                    operator=cond_data['operator'],
                    value=cond_data['value']
                )
                rule.conditions.append(condition)
            
            # Add to rules engine
            if components.get('filter_rules'):
                components['filter_rules'].add_rule(rule)
                return jsonify({'status': 'created', 'rule': rule.name}), 201
            
            abort(500, description="Rules engine not available")
        
        @app.route(f'/api/{API_VERSION}/rules/<rule_name>', methods=['PUT'])
        @require_auth
        @require_permission('write')
        def update_rule(rule_name: str):
            """Update an existing rule"""
            data = request.get_json()
            
            if not components.get('filter_rules'):
                abort(500, description="Rules engine not available")
            
            # Remove existing rule
            components['filter_rules'].remove_rule(rule_name)
            
            # Create updated rule
            rule = Rule(
                name=data.get('name', rule_name),
                action=RuleAction(data.get('action', 'ALLOW').upper()),
                priority=data.get('priority', 100),
                enabled=data.get('enabled', True),
                description=data.get('description', '')
            )
            
            for cond_data in data.get('conditions', []):
                from src.core.filter_rules import RuleCondition
                condition = RuleCondition(
                    field=cond_data['field'],
                    operator=cond_data['operator'],
                    value=cond_data['value']
                )
                rule.conditions.append(condition)
            
            components['filter_rules'].add_rule(rule)
            return jsonify({'status': 'updated', 'rule': rule.name})
        
        @app.route(f'/api/{API_VERSION}/rules/<rule_name>', methods=['DELETE'])
        @require_auth
        @require_permission('write')
        def delete_rule(rule_name: str):
            """Delete a rule"""
            if not components.get('filter_rules'):
                abort(500, description="Rules engine not available")
            
            if components['filter_rules'].remove_rule(rule_name):
                return jsonify({'status': 'deleted', 'rule': rule_name})
            
            abort(404, description="Rule not found")
        
        # Alert management endpoints
        @app.route(f'/api/{API_VERSION}/alerts', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_alerts():
            """Get alerts"""
            if not components.get('alert_manager'):
                return jsonify({'alerts': []})
            
            # Parse query parameters
            severity = request.args.get('severity')
            source = request.args.get('source')
            limit = int(request.args.get('limit', 100))
            unacknowledged = request.args.get('unacknowledged', 'false').lower() == 'true'
            
            from src.response.alert_manager import AlertSeverity
            
            severity_enum = None
            if severity:
                try:
                    severity_enum = AlertSeverity(severity)
                except ValueError:
                    abort(400, description=f"Invalid severity: {severity}")
            
            alerts = components['alert_manager'].get_alerts(
                severity=severity_enum,
                source=source,
                limit=limit,
                unacknowledged_only=unacknowledged
            )
            
            return jsonify({
                'alerts': [a.to_dict() for a in alerts],
                'count': len(alerts)
            })
        
        @app.route(f'/api/{API_VERSION}/alerts/<alert_id>/acknowledge', methods=['POST'])
        @require_auth
        @require_permission('write')
        def acknowledge_alert(alert_id: str):
            """Acknowledge an alert"""
            if not components.get('alert_manager'):
                abort(500, description="Alert manager not available")
            
            data = request.get_json() or {}
            user = data.get('user', 'api_user')
            
            if components['alert_manager'].acknowledge_alert(alert_id, user):
                return jsonify({'status': 'acknowledged', 'alert_id': alert_id})
            
            abort(404, description="Alert not found")
        
        # Incident management endpoints
        @app.route(f'/api/{API_VERSION}/incidents', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_incidents():
            """Get incidents"""
            if not components.get('incident_handler'):
                return jsonify({'incidents': []})
            
            status = request.args.get('status')
            severity = request.args.get('severity')
            limit = int(request.args.get('limit', 100))
            
            from src.response.incident_handler import IncidentStatus, IncidentSeverity
            
            status_enum = None
            if status:
                try:
                    status_enum = IncidentStatus(status)
                except ValueError:
                    abort(400, description=f"Invalid status: {status}")
            
            severity_enum = None
            if severity:
                try:
                    severity_enum = IncidentSeverity(severity)
                except ValueError:
                    abort(400, description=f"Invalid severity: {severity}")
            
            incidents = components['incident_handler'].get_incidents(
                status=status_enum,
                severity=severity_enum,
                limit=limit
            )
            
            return jsonify({
                'incidents': [i.to_dict() for i in incidents],
                'count': len(incidents)
            })
        
        @app.route(f'/api/{API_VERSION}/incidents/<incident_id>', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_incident(incident_id: str):
            """Get specific incident"""
            if not components.get('incident_handler'):
                abort(500, description="Incident handler not available")
            
            incident = components['incident_handler'].get_incident(incident_id)
            
            if not incident:
                abort(404, description="Incident not found")
            
            return jsonify(incident.to_dict())
        
        @app.route(f'/api/{API_VERSION}/incidents/<incident_id>/status', methods=['PUT'])
        @require_auth
        @require_permission('write')
        def update_incident_status(incident_id: str):
            """Update incident status"""
            data = request.get_json()
            
            if not data or 'status' not in data:
                abort(400, description="Missing status field")
            
            if not components.get('incident_handler'):
                abort(500, description="Incident handler not available")
            
            from src.response.incident_handler import IncidentStatus
            
            try:
                status = IncidentStatus(data['status'])
            except ValueError:
                abort(400, description=f"Invalid status: {data['status']}")
            
            notes = data.get('notes')
            
            if components['incident_handler'].update_incident_status(incident_id, status, notes):
                return jsonify({'status': 'updated', 'incident_id': incident_id})
            
            abort(404, description="Incident not found")
        
        @app.route(f'/api/{API_VERSION}/incidents/<incident_id>/notes', methods=['POST'])
        @require_auth
        @require_permission('write')
        def add_incident_note(incident_id: str):
            """Add note to incident"""
            data = request.get_json()
            
            if not data or 'note' not in data:
                abort(400, description="Missing note field")
            
            if not components.get('incident_handler'):
                abort(500, description="Incident handler not available")
            
            author = data.get('author', 'api_user')
            
            if components['incident_handler'].add_incident_note(incident_id, data['note'], author):
                return jsonify({'status': 'added', 'incident_id': incident_id})
            
            abort(404, description="Incident not found")
        
        # Quarantine management endpoints
        @app.route(f'/api/{API_VERSION}/quarantine', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_quarantine():
            """Get active quarantines"""
            if not components.get('quarantine_manager'):
                return jsonify({'quarantines': []})
            
            quarantines = components['quarantine_manager'].get_active_quarantines()
            
            return jsonify({
                'quarantines': [q.to_dict() for q in quarantines],
                'count': len(quarantines)
            })
        
        @app.route(f'/api/{API_VERSION}/quarantine/ip', methods=['POST'])
        @require_auth
        @require_permission('write')
        def quarantine_ip():
            """Quarantine an IP address"""
            data = request.get_json()
            
            if not data or 'ip' not in data:
                abort(400, description="Missing ip field")
            
            if not components.get('quarantine_manager'):
                abort(500, description="Quarantine manager not available")
            
            reason_str = data.get('reason', 'manual')
            try:
                reason = QuarantineReason(reason_str)
            except ValueError:
                abort(400, description=f"Invalid reason: {reason_str}")
            
            duration = data.get('duration')
            description = data.get('description', '')
            source = data.get('source', 'api')
            
            try:
                entry = components['quarantine_manager'].quarantine_ip(
                    ip=data['ip'],
                    reason=reason,
                    source=source,
                    duration=duration,
                    description=description,
                    created_by=data.get('created_by', 'api_user')
                )
                
                return jsonify({
                    'status': 'quarantined',
                    'entry': entry.to_dict()
                }), 201
                
            except ValueError as e:
                abort(400, description=str(e))
        
        @app.route(f'/api/{API_VERSION}/quarantine/subnet', methods=['POST'])
        @require_auth
        @require_permission('write')
        def quarantine_subnet():
            """Quarantine a subnet"""
            data = request.get_json()
            
            if not data or 'subnet' not in data:
                abort(400, description="Missing subnet field")
            
            if not components.get('quarantine_manager'):
                abort(500, description="Quarantine manager not available")
            
            reason_str = data.get('reason', 'manual')
            try:
                reason = QuarantineReason(reason_str)
            except ValueError:
                abort(400, description=f"Invalid reason: {reason_str}")
            
            duration = data.get('duration')
            description = data.get('description', '')
            source = data.get('source', 'api')
            
            try:
                entry = components['quarantine_manager'].quarantine_subnet(
                    subnet=data['subnet'],
                    reason=reason,
                    source=source,
                    duration=duration,
                    description=description,
                    created_by=data.get('created_by', 'api_user')
                )
                
                return jsonify({
                    'status': 'quarantined',
                    'entry': entry.to_dict()
                }), 201
                
            except ValueError as e:
                abort(400, description=str(e))
        
        @app.route(f'/api/{API_VERSION}/quarantine/<entry_id>/release', methods=['POST'])
        @require_auth
        @require_permission('write')
        def release_quarantine(entry_id: str):
            """Release a quarantine entry"""
            if not components.get('quarantine_manager'):
                abort(500, description="Quarantine manager not available")
            
            if components['quarantine_manager'].release_quarantine(entry_id):
                return jsonify({'status': 'released', 'entry_id': entry_id})
            
            abort(404, description="Quarantine entry not found")
        
        @app.route(f'/api/{API_VERSION}/quarantine/check/<ip>', methods=['GET'])
        @require_auth
        @require_permission('read')
        def check_quarantine(ip: str):
            """Check if IP is quarantined"""
            if not components.get('quarantine_manager'):
                return jsonify({'quarantined': False})
            
            is_quarantined = components['quarantine_manager'].is_quarantined(ip)
            info = components['quarantine_manager'].get_quarantine_info(ip)
            
            return jsonify({
                'ip': ip,
                'quarantined': is_quarantined,
                'info': info.to_dict() if info else None
            })
        
        # Connection tracking endpoints
        @app.route(f'/api/{API_VERSION}/connections', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_connections():
            """Get connection tracking information"""
            if not components.get('connection_tracker'):
                return jsonify({'connections': []})
            
            ip_filter = request.args.get('ip')
            
            if ip_filter:
                connections = components['connection_tracker'].get_connections_by_ip(ip_filter)
                connections_data = [c.to_dict() for c in connections]
            else:
                # Return just statistics, not all connections (could be many)
                stats = components['connection_tracker'].get_statistics()
                return jsonify({'statistics': stats})
            
            return jsonify({
                'connections': connections_data,
                'count': len(connections_data)
            })
        
        @app.route(f'/api/{API_VERSION}/connections/<ip>', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_connections_for_ip(ip: str):
            """Get connections for specific IP"""
            if not components.get('connection_tracker'):
                return jsonify({'connections': []})
            
            connections = components['connection_tracker'].get_connections_by_ip(ip)
            
            return jsonify({
                'ip': ip,
                'connections': [c.to_dict() for c in connections],
                'count': len(connections)
            })
        
        # Threat intelligence endpoints
        @app.route(f'/api/{API_VERSION}/threat-intel/check/<ip>', methods=['GET'])
        @require_auth
        @require_permission('read')
        def check_threat_intel(ip: str):
            """Check IP against threat intelligence"""
            if not components.get('threat_intel'):
                return jsonify({'threat': None})
            
            threat = components['threat_intel'].check_ip(ip)
            
            return jsonify({
                'ip': ip,
                'threat': threat.to_dict() if threat else None
            })
        
        # Configuration endpoints
        @app.route(f'/api/{API_VERSION}/config', methods=['GET'])
        @require_auth
        @require_permission('read')
        def get_config():
            """Get current configuration"""
            config = {
                'api_version': API_VERSION,
                'components': {}
            }
            
            for name, component in components.items():
                if component:
                    if hasattr(component, 'get_config'):
                        config['components'][name] = component.get_config()
                    else:
                        config['components'][name] = {'available': True}
            
            return jsonify(config)
        
        # Error handlers
        @app.errorhandler(400)
        def bad_request(e):
            return jsonify({'error': 'bad_request', 'message': str(e.description)}), 400
        
        @app.errorhandler(401)
        def unauthorized(e):
            return jsonify({'error': 'unauthorized', 'message': str(e.description)}), 401
        
        @app.errorhandler(403)
        def forbidden(e):
            return jsonify({'error': 'forbidden', 'message': str(e.description)}), 403
        
        @app.errorhandler(404)
        def not_found(e):
            return jsonify({'error': 'not_found', 'message': str(e.description)}), 404
        
        @app.errorhandler(500)
        def internal_error(e):
            logger.error(f"Internal server error: {e}")
            return jsonify({'error': 'internal_server_error', 'message': 'An internal error occurred'}), 5
    
    def start(self) -> None:
        """Start the REST API server"""
        self.running = True
        self.server_thread = threading.Thread(
            target=self._run_server,
            daemon=True,
            name="REST-API"
        )
        self.server_thread.start()
        logger.info(f"REST API server started on http://{self.host}:{self.port}")
    
    def _run_server(self) -> None:
        """Run the Flask server"""
        app.run(host=self.host, port=self.port, debug=self.debug, threaded=True)
    
    def stop(self) -> None:
        """Stop the REST API server"""
        self.running = False
        # Flask doesn't have a clean shutdown method in dev server
        logger.info("REST API server stopped")
    
    def add_token(self, token: str, permissions: List[str], expiry: float, user: str) -> None:
        """Add an API token"""
        global API_TOKENS
        API_TOKENS[token] = {
            'permissions': permissions,
            'expiry': expiry,
            'user': user
        }
    
    def revoke_token(self, token: str) -> bool:
        """Revoke an API token"""
        global API_TOKENS
        if token in API_TOKENS:
            del API_TOKENS[token]
            return True
        return False
