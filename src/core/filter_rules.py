import yaml
import re
import os
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field
import ipaddress

from src.utils.logger import get_logger

logger = get_logger(__name__)

class RuleAction(Enum):
    """Actions for firewall rules"""
    ALLOW = "ALLOW"
    DROP = "DROP"
    REJECT = "REJECT"
    LOG = "LOG"
    ALERT = "ALERT"

@dataclass
class RuleCondition:
    """Condition for rule matching"""
    field: str
    operator: str  # eq, ne, in, contains, matches
    value: Any
    
    def matches(self, packet_data: Dict) -> bool:
        """
        Check if condition matches packet data
        
        Args:
            packet_data: Packet metadata dictionary
            
        Returns:
            True if condition matches
        """
        if self.field not in packet_data:
            return False
        
        packet_value = packet_data[self.field]
        
        if self.operator == "eq":
            return packet_value == self.value
        elif self.operator == "ne":
            return packet_value != self.value
        elif self.operator == "in":
            return packet_value in self.value
        elif self.operator == "contains":
            return self.value in str(packet_value)
        elif self.operator == "matches":
            return bool(re.search(self.value, str(packet_value)))
        elif self.operator == "gt":
            return packet_value > self.value
        elif self.operator == "lt":
            return packet_value < self.value
        elif self.operator == "cidr":
            try:
                ip = ipaddress.IPv4Address(packet_value)
                network = ipaddress.IPv4Network(self.value)
                return ip in network
            except:
                return False
        
        return False

@dataclass
class Rule:
    """Firewall rule definition"""
    name: str
    action: RuleAction
    conditions: List[RuleCondition] = field(default_factory=list)
    priority: int = 100
    enabled: bool = True
    description: str = ""
    
    def matches(self, packet_data: Dict) -> bool:
        """
        Check if packet matches all rule conditions
        
        Args:
            packet_data: Packet metadata dictionary
            
        Returns:
            True if all conditions match
        """
        if not self.enabled:
            return False
        
        for condition in self.conditions:
            if not condition.matches(packet_data):
                return False
        
        return True

class FilterRules:
    """
    Manages firewall filtering rules
    Loads rules from configuration and applies them to packets
    """
    
    def __init__(self, rules_file: str = "config/rules/filter_rules.yaml"):
        """
        Initialize filter rules manager
        
        Args:
            rules_file: Path to rules configuration file
        """
        self.rules_file = rules_file
        self.rules: List[Rule] = []
        self.default_action = RuleAction.ALLOW
        
        self.load_rules()
    
    def load_rules(self) -> None:
        """Load rules from configuration file"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    data = yaml.safe_load(f)
                    
                if data and 'rules' in data:
                    for rule_data in data['rules']:
                        rule = self._parse_rule(rule_data)
                        if rule:
                            self.rules.append(rule)
                    
                    # Sort by priority
                    self.rules.sort(key=lambda r: r.priority)
                    
                    logger.info(f"Loaded {len(self.rules)} filter rules")
            else:
                self._create_default_rules()
                
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            self._create_default_rules()
    
    def _parse_rule(self, data: Dict) -> Optional[Rule]:
        """
        Parse rule from dictionary
        
        Args:
            data: Rule dictionary
            
        Returns:
            Rule object or None if invalid
        """
        try:
            name = data.get('name', 'unnamed')
            action = RuleAction(data.get('action', 'ALLOW'))
            priority = data.get('priority', 100)
            enabled = data.get('enabled', True)
            description = data.get('description', '')
            
            conditions = []
            for cond_data in data.get('conditions', []):
                condition = RuleCondition(
                    field=cond_data['field'],
                    operator=cond_data['operator'],
                    value=cond_data['value']
                )
                conditions.append(condition)
            
            return Rule(
                name=name,
                action=action,
                conditions=conditions,
                priority=priority,
                enabled=enabled,
                description=description
            )
            
        except Exception as e:
            logger.error(f"Error parsing rule: {e}")
            return None
    
    def _create_default_rules(self) -> None:
        """Create default filter rules"""
        default_rules = [
            {
                'name': 'block_external_ping',
                'action': 'DROP',
                'priority': 10,
                'conditions': [
                    {'field': 'protocol', 'operator': 'eq', 'value': 'ICMP'},
                    {'field': 'flags', 'operator': 'contains', 'value': 'type=8'},
                    {'field': 'src_ip', 'operator': 'cidr', 'value': '0.0.0.0/0'}
                ],
                'description': 'Block external ping requests'
            },
            {
                'name': 'allow_internal_ping',
                'action': 'ALLOW',
                'priority': 20,
                'conditions': [
                    {'field': 'protocol', 'operator': 'eq', 'value': 'ICMP'},
                    {'field': 'flags', 'operator': 'contains', 'value': 'type=8'},
                    {'field': 'src_ip', 'operator': 'cidr', 'value': '192.168.0.0/16'}
                ],
                'description': 'Allow internal ping requests'
            },
            {
                'name': 'block_ssh_external',
                'action': 'DROP',
                'priority': 30,
                'conditions': [
                    {'field': 'protocol', 'operator': 'eq', 'value': 'TCP'},
                    {'field': 'dst_port', 'operator': 'eq', 'value': 22},
                    {'field': 'src_ip', 'operator': 'cidr', 'value': '0.0.0.0/0'},
                    {'field': 'src_ip', 'operator': 'cidr', 'value': '!192.168.0.0/16'}
                ],
                'description': 'Block SSH from external networks'
            },
            {
                'name': 'allow_web_traffic',
                'action': 'ALLOW',
                'priority': 40,
                'conditions': [
                    {'field': 'protocol', 'operator': 'eq', 'value': 'TCP'},
                    {'field': 'dst_port', 'operator': 'in', 'value': [80, 443]}
                ],
                'description': 'Allow HTTP/HTTPS traffic'
            }
        ]
        
        for rule_data in default_rules:
            rule = self._parse_rule(rule_data)
            if rule:
                self.rules.append(rule)
        
        logger.info(f"Created {len(self.rules)} default filter rules")
    
    def check_packet(self, packet_metadata) -> Tuple[RuleAction, Optional[str]]:
        """
        Check packet against all rules
        
        Args:
            packet_metadata: Packet metadata object
            
        Returns:
            Tuple of (action, rule_name)
        """
        packet_data = packet_metadata.to_dict()
        
        for rule in self.rules:
            if rule.matches(packet_data):
                logger.debug(f"Packet matched rule: {rule.name} -> {rule.action.value}")
                return rule.action, rule.name
        
        return self.default_action, None
    
    def add_rule(self, rule: Rule) -> None:
        """
        Add a new rule
        
        Args:
            rule: Rule to add
        """
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        self.save_rules()
        logger.info(f"Added rule: {rule.name}")
    
    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove a rule by name
        
        Args:
            rule_name: Name of rule to remove
            
        Returns:
            True if removed, False if not found
        """
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                del self.rules[i]
                self.save_rules()
                logger.info(f"Removed rule: {rule_name}")
                return True
        return False
    
    def save_rules(self) -> None:
        """Save rules to configuration file"""
        try:
            os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
            
            rules_data = {'rules': []}
            for rule in self.rules:
                rule_dict = {
                    'name': rule.name,
                    'action': rule.action.value,
                    'priority': rule.priority,
                    'enabled': rule.enabled,
                    'description': rule.description,
                    'conditions': [
                        {
                            'field': c.field,
                            'operator': c.operator,
                            'value': c.value
                        }
                        for c in rule.conditions
                    ]
                }
                rules_data['rules'].append(rule_dict)
            
            with open(self.rules_file, 'w') as f:
                yaml.dump(rules_data, f, default_flow_style=False)
            
            logger.info(f"Saved {len(self.rules)} rules to {self.rules_file}")
            
        except Exception as e:
            logger.error(f"Error saving rules: {e}")
    
    def get_rules(self) -> List[Dict]:
        """
        Get all rules as dictionaries
        
        Returns:
            List of rule dictionaries
        """
        return [
            {
                'name': r.name,
                'action': r.action.value,
                'priority': r.priority,
                'enabled': r.enabled,
                'description': r.description,
                'conditions': [
                    {'field': c.field, 'operator': c.operator, 'value': c.value}
                    for c in r.conditions
                ]
            }
            for r in self.rules
        ]
