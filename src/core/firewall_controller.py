"""
Firewall Controller Module
Integrates with system firewall (iptables/nftables) for actual packet filtering
"""

import subprocess
import re
from typing import List, Dict, Optional
from enum import Enum
from dataclasses import dataclass

from src.utils.logger import get_logger
from src.utils.network_utils import is_valid_ip, is_valid_port

logger = get_logger(__name__)

class FirewallBackend(Enum):
    """Supported firewall backends"""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    UNKNOWN = "unknown"

@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    chain: str
    protocol: Optional[str]
    source: Optional[str]
    destination: Optional[str]
    sport: Optional[int]
    dport: Optional[int]
    action: str  # ACCEPT, DROP, REJECT
    comment: Optional[str]

class FirewallController:
    """
    Controls system firewall to implement actual packet blocking
    Supports iptables and nftables backends
    """
    
    def __init__(self):
        self.backend = self._detect_backend()
        self.rules: List[FirewallRule] = []
        
        if self.backend == FirewallBackend.UNKNOWN:
            logger.warning("No supported firewall backend found")
        else:
            logger.info(f"Using {self.backend.value} as firewall backend")
    
    def _detect_backend(self) -> FirewallBackend:
        """
        Detect available firewall backend
        
        Returns:
            Detected firewall backend
        """
        try:
            # Check for iptables
            result = subprocess.run(
                ["iptables", "--version"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                return FirewallBackend.IPTABLES
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        try:
            # Check for nftables
            result = subprocess.run(
                ["nft", "--version"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                return FirewallBackend.NFTABLES
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return FirewallBackend.UNKNOWN
    
    def block_external_ping(self) -> bool:
        """
        Add rule to block external ping requests
        
        Returns:
            True if successful, False otherwise
        """
        if self.backend == FirewallBackend.IPTABLES:
            return self._iptables_block_external_ping()
        elif self.backend == FirewallBackend.NFTABLES:
            return self._nftables_block_external_ping()
        else:
            logger.error("No supported firewall backend available")
            return False
    
    def _iptables_block_external_ping(self) -> bool:
        """
        Block external ping using iptables
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Block ICMP echo requests from external sources
            commands = [
                # Rate limit ICMP to prevent flooding
                ["iptables", "-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                 "-m", "limit", "--limit", "1/second", "--limit-burst", "5",
                 "-j", "ACCEPT", "-m", "comment", "--comment", "Rate limit ICMP"],
                
                # Drop all other ICMP echo requests
                ["iptables", "-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                 "-j", "DROP", "-m", "comment", "--comment", "Block external ping"],
                
                # Allow internal ping (adjust network range as needed)
                ["iptables", "-I", "INPUT", "1", "-p", "icmp", "--icmp-type", "echo-request",
                 "-s", "192.168.0.0/16", "-j", "ACCEPT",
                 "-m", "comment", "--comment", "Allow internal ping"]
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    logger.error(f"Failed to execute iptables command: {result.stderr}")
                    return False
            
            logger.info("Successfully added iptables rules to block external ping")
            return True
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing iptables command: {e}")
            return False
    
    def _nftables_block_external_ping(self) -> bool:
        """
        Block external ping using nftables
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create nftables ruleset
            ruleset = """
            table inet filter {
                chain input {
                    type filter hook input priority 0; policy drop;
                    
                    # Allow established connections
                    ct state established,related accept
                    
                    # Allow loopback
                    iifname "lo" accept
                    
                    # Allow internal ping
                    ip saddr 192.168.0.0/16 icmp type echo-request accept
                    
                    # Rate limit ICMP
                    icmp type echo-request limit rate 1/second burst 5 packets accept
                    
                    # Log dropped pings
                    icmp type echo-request log prefix "DROPPED PING: "
                }
            }
            """
            
            # Apply ruleset
            process = subprocess.run(
                ["nft", "-f", "-"],
                input=ruleset,
                capture_output=True,
                text=True,
                check=False
            )
            
            if process.returncode != 0:
                logger.error(f"Failed to apply nftables rules: {process.stderr}")
                return False
            
            logger.info("Successfully added nftables rules to block external ping")
            return True
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing nftables command: {e}")
            return False
    
    def add_port_filter(self, port: int, protocol: str = "tcp", action: str = "DROP") -> bool:
        """
        Add a port filtering rule
        
        Args:
            port: Port number to filter
            protocol: Protocol (tcp/udp)
            action: Action (DROP/REJECT/ACCEPT)
            
        Returns:
            True if successful, False otherwise
        """
        if not is_valid_port(port):
            logger.error(f"Invalid port number: {port}")
            return False
        
        if protocol.lower() not in ["tcp", "udp"]:
            logger.error(f"Invalid protocol: {protocol}")
            return False
        
        if self.backend == FirewallBackend.IPTABLES:
            return self._iptables_add_port_filter(port, protocol, action)
        elif self.backend == FirewallBackend.NFTABLES:
            return self._nftables_add_port_filter(port, protocol, action)
        else:
            logger.error("No supported firewall backend available")
            return False
    
    def _iptables_add_port_filter(self, port: int, protocol: str, action: str) -> bool:
        """
        Add port filter using iptables
        
        Args:
            port: Port number
            protocol: Protocol
            action: Action
            
        Returns:
            True if successful
        """
        try:
            cmd = [
                "iptables", "-A", "INPUT",
                "-p", protocol,
                "--dport", str(port),
                "-j", action.upper(),
                "-m", "comment", "--comment", f"Port filter {port}/{protocol}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                logger.info(f"Added {action} rule for port {port}/{protocol}")
                return True
            else:
                logger.error(f"Failed to add port filter: {result.stderr}")
                return False
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing iptables command: {e}")
            return False
    
    def _nftables_add_port_filter(self, port: int, protocol: str, action: str) -> bool:
        """
        Add port filter using nftables
        
        Args:
            port: Port number
            protocol: Protocol
            action: Action
            
        Returns:
            True if successful
        """
        try:
            rule = f"nft add rule inet filter input {protocol} dport {port} {action.lower()}"
            
            result = subprocess.run(
                rule.split(),
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                logger.info(f"Added {action} rule for port {port}/{protocol}")
                return True
            else:
                logger.error(f"Failed to add port filter: {result.stderr}")
                return False
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error executing nftables command: {e}")
            return False
    
    def list_rules(self) -> List[str]:
        """
        List current firewall rules
        
        Returns:
            List of rule strings
        """
        if self.backend == FirewallBackend.IPTABLES:
            return self._iptables_list_rules()
        elif self.backend == FirewallBackend.NFTABLES:
            return self._nftables_list_rules()
        else:
            return []
    
    def _iptables_list_rules(self) -> List[str]:
        """List iptables rules"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n", "-v"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout.splitlines()
            else:
                logger.error(f"Failed to list iptables rules: {result.stderr}")
                return []
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error listing iptables rules: {e}")
            return []
    
    def _nftables_list_rules(self) -> List[str]:
        """List nftables rules"""
        try:
            result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout.splitlines()
            else:
                logger.error(f"Failed to list nftables rules: {result.stderr}")
                return []
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error listing nftables rules: {e}")
            return []
    
    def flush_rules(self) -> bool:
        """
        Remove all rules added by this controller
        
        Returns:
            True if successful
        """
        if self.backend == FirewallBackend.IPTABLES:
            return self._iptables_flush_rules()
        elif self.backend == FirewallBackend.NFTABLES:
            return self._nftables_flush_rules()
        else:
            return False
    
    def _iptables_flush_rules(self) -> bool:
        """Flush iptables rules"""
        try:
            # Flush INPUT chain
            subprocess.run(
                ["iptables", "-F", "INPUT"],
                capture_output=True,
                check=False
            )
            
            # Set default policies
            subprocess.run(
                ["iptables", "-P", "INPUT", "ACCEPT"],
                capture_output=True,
                check=False
            )
            
            logger.info("Flushed iptables rules")
            return True
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error flushing iptables rules: {e}")
            return False
    
    def _nftables_flush_rules(self) -> bool:
        """Flush nftables rules"""
        try:
            subprocess.run(
                ["nft", "flush", "ruleset"],
                capture_output=True,
                check=False
            )
            
            logger.info("Flushed nftables rules")
            return True
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error flushing nftables rules: {e
