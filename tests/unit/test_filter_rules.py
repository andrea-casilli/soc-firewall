import pytest
import tempfile
import yaml
from pathlib import Path

from src.core.filter_rules import FilterRules, Rule, RuleAction, RuleCondition


class TestFilterRules:
    """Tests for FilterRules class"""
    
    @pytest.fixture
    def rules_file(self, tmp_path):
        """Create temporary rules file"""
        rules_data = {
            'rules': [
                {
                    'name': 'test_rule_1',
                    'action': 'DROP',
                    'priority': 10,
                    'conditions': [
                        {'field': 'protocol', 'operator': 'eq', 'value': 'ICMP'},
                        {'field': 'src_ip', 'operator': 'cidr', 'value': '0.0.0.0/0'}
                    ]
                },
                {
                    'name': 'test_rule_2',
                    'action': 'ALLOW',
                    'priority': 20,
                    'conditions': [
                        {'field': 'dst_port', 'operator': 'eq', 'value': 80}
                    ]
                }
            ]
        }
        
        file_path = tmp_path / "test_rules.yaml"
        with open(file_path, 'w') as f:
            yaml.dump(rules_data, f)
        
        return file_path
    
    def test_load_rules(self, rules_file):
        """Test loading rules from file"""
        rules = FilterRules(str(rules_file))
        assert len(rules.rules) == 2
        assert rules.rules[0].name == 'test_rule_1'
        assert rules.rules[0].action == RuleAction.DROP
    
    def test_check_packet(self, rules_file):
        """Test checking packet against rules"""
        rules = FilterRules(str(rules_file))
        
        # Create mock packet metadata
        class MockMetadata:
            def to_dict(self):
                return {
                    'protocol': 'ICMP',
                    'src_ip': '8.8.8.8',
                    'dst_ip': '192.168.1.1',
                    'dst_port': 0,
                    'flags': ['type=8']
                }
        
        packet = MockMetadata()
        
        # Should match rule 1
        action, rule_name = rules.check_packet(packet)
        assert action == RuleAction.DROP
        assert rule_name == 'test_rule_1'
    
    def test_add_remove_rule(self, rules_file):
        """Test adding and removing rules"""
        rules = FilterRules(str(rules_file))
        initial_count = len(rules.rules)
        
        # Add rule
        new_rule = Rule(
            name='new_test_rule',
            action=RuleAction.ALLOW,
            conditions=[
                RuleCondition(field='protocol', operator='eq', value='TCP'),
                RuleCondition(field='dst_port', operator='eq', value=443)
            ]
        )
        
        rules.add_rule(new_rule)
        assert len(rules.rules) == initial_count + 1
        
        # Remove rule
        rules.remove_rule('new_test_rule')
        assert len(rules.rules) == initial_count
    
    def test_condition_matching(self):
        """Test rule condition matching"""
        # EQ condition
        cond = RuleCondition(field='protocol', operator='eq', value='TCP')
        assert cond.matches({'protocol': 'TCP'}) == True
        assert cond.matches({'protocol': 'UDP'}) == False
        
        # IN condition
        cond = RuleCondition(field='dst_port', operator='in', value=[80, 443])
        assert cond.matches({'dst_port': 80}) == True
        assert cond.matches({'dst_port': 8080}) == False
        
        # CIDR condition
        cond = RuleCondition(field='src_ip', operator='cidr', value='192.168.1.0/24')
        assert cond.matches({'src_ip': '192.168.1.100'}) == True
        assert cond.matches({'src_ip': '10.0.0.1'}) == False
        
        # GT condition
        cond = RuleCondition(field='packet_size', operator='gt', value=100)
        assert cond.matches({'packet_size': 150}) == True
        assert cond.matches({'packet_size': 50}) == False
