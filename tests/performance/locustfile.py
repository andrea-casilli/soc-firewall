from locust import HttpUser, task, between
import json


class FirewallAPIUser(HttpUser):
    """Simulated API user for load testing"""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Setup before tests"""
        # Authenticate
        self.token = "soc_admin_token_2024"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    @task(1)
    def get_status(self):
        """Get firewall status"""
        self.client.get("/api/v1/status", headers=self.headers)
    
    @task(2)
    def get_statistics(self):
        """Get statistics"""
        self.client.get("/api/v1/stats", headers=self.headers)
    
    @task(1)
    def get_rules(self):
        """Get filter rules"""
        self.client.get("/api/v1/rules", headers=self.headers)
    
    @task(1)
    def get_alerts(self):
        """Get alerts"""
        self.client.get("/api/v1/alerts?limit=10", headers=self.headers)
    
    @task(1)
    def get_incidents(self):
        """Get incidents"""
        self.client.get("/api/v1/incidents?limit=10", headers=self.headers)
    
    @task(1)
    def get_quarantine(self):
        """Get quarantine list"""
        self.client.get("/api/v1/quarantine", headers=self.headers)
    
    @task(1)
    def get_connections(self):
        """Get connection statistics"""
        self.client.get("/api/v1/connections", headers=self.headers)
    
    @task(1)
    def check_ip(self):
        """Check IP threat status"""
        self.client.get("/api/v1/threat-intel/check/8.8.8.8", headers=self.headers)
    
    @task(1)
    def create_rule(self):
        """Create a new rule"""
        rule_data = {
            "name": f"load_test_rule_{self.environment.runner.user_count}",
            "action": "DROP",
            "priority": 100,
            "conditions": [
                {"field": "protocol", "operator": "eq", "value": "ICMP"},
                {"field": "src_ip", "operator": "cidr", "value": "0.0.0.0/0"}
            ]
        }
        
        self.client.post(
            "/api/v1/rules",
            headers=self.headers,
            json=rule_data
        )
    
    @task(1)
    def quarantine_ip(self):
        """Quarantine an IP"""
        quarantine_data = {
            "ip": "192.168.1.100",
            "reason": "suspicious",
            "duration": 300,
            "description": "Load test quarantine"
        }
        
        self.client.post(
            "/api/v1/quarantine/ip",
            headers=self.headers,
            json=quarantine_data
        )
    
    @task(1)
    def acknowledge_alert(self):
        """Acknowledge an alert"""
        # This would need a real alert ID
        pass
