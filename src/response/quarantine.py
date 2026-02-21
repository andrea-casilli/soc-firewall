import time
import json
import threading
import subprocess
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
import ipaddress

from src.utils.logger import get_logger

logger = get_logger(__name__)


class QuarantineReason(Enum):
    """Reasons for quarantine"""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    ATTACK_SOURCE = "attack_source"
    COMPROMISED = "compromised"
    POLICY_VIOLATION = "policy_violation"
    MANUAL = "manual"


class QuarantineAction(Enum):
    """Quarantine actions"""
    BLOCK_IP = "block_ip"
    BLOCK_SUBNET = "block_subnet"
    BLOCK_ALL_TRAFFIC = "block_all_traffic"
    ISOLATE_HOST = "isolate_host"
    SHUTDOWN_HOST = "shutdown_host"


@dataclass
class QuarantineEntry:
    """Quarantine entry"""
    id: str
    target: str  # IP, subnet, hostname
    reason: QuarantineReason
    action: QuarantineAction
    source: str  # manual, automated, incident
    timestamp: float
    expires: Optional[float] = None
    description: str = ""
    created_by: str = "system"
    rules_added: List[str] = field(default_factory=list)
    active: bool = True
    
    def is_expired(self) -> bool:
        """Check if quarantine has expired"""
        if self.expires:
            return time.time() > self.expires
        return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "target": self.target,
            "reason": self.reason.value,
            "action": self.action.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "expires": self.expires,
            "description": self.description,
            "created_by": self.created_by,
            "active": self.active
        }


class QuarantineManager:
    """
    IP and host quarantine management
    
    Features:
    - IP/Subnet blocking
    - Automatic expiration
    - Multiple blocking methods (iptables, hosts file, etc.)
    - Persistent storage
    - Audit logging
    """
    
    def __init__(self, data_dir: str = "data/quarantine"):
        """
        Initialize quarantine manager
        
        Args:
            data_dir: Directory for persistent storage
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.quarantined: Dict[str, QuarantineEntry] = {}
        self.blocked_ips: Set[str] = set()
        self.blocked_subnets: Set[str] = set()
        
        # Statistics
        self.stats = {
            "total_quarantined": 0,
            "active_quarantines": 0,
            "expired_quarantines": 0,
            "by_reason": defaultdict(int)
        }
        
        self.lock = threading.RLock()
        
        # Load existing quarantines
        self._load_quarantines()
        
        # Start cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self.cleanup_thread.start()
        
        logger.info("Quarantine Manager initialized")
    
    def _load_quarantines(self) -> None:
        """Load quarantines from disk"""
        try:
            quarantine_file = self.data_dir / "quarantines.json"
            if quarantine_file.exists():
                with open(quarantine_file, 'r') as f:
                    data = json.load(f)
                
                for q_data in data.get("quarantines", []):
                    entry = QuarantineEntry(
                        id=q_data["id"],
                        target=q_data["target"],
                        reason=QuarantineReason(q_data["reason"]),
                        action=QuarantineAction(q_data["action"]),
                        source=q_data["source"],
                        timestamp=q_data["timestamp"],
                        expires=q_data.get("expires"),
                        description=q_data.get("description", ""),
                        created_by=q_data.get("created_by", "system"),
                        active=q_data.get("active", True)
                    )
                    
                    self.quarantined[entry.id] = entry
                    
                    if entry.active and not entry.is_expired():
                        if entry.action == QuarantineAction.BLOCK_IP:
                            self.blocked_ips.add(entry.target)
                        elif entry.action == QuarantineAction.BLOCK_SUBNET:
                            self.blocked_subnets.add(entry.target)
                        
                        self.stats["active_quarantines"] += 1
                        self.stats["by_reason"][entry.reason.value] += 1
                
                logger.info(f"Loaded {len(self.quarantined)} quarantine entries")
                
        except Exception as e:
            logger.error(f"Error loading quarantines: {e}")
    
    def _save_quarantines(self) -> None:
        """Save quarantines to disk"""
        try:
            quarantine_file = self.data_dir / "quarantines.json"
            
            data = {
                "quarantines": [q.to_dict() for q in self.quarantined.values()],
                "updated_at": time.time()
            }
            
            with open(quarantine_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            logger.error(f"Error saving quarantines: {e}")
    
    def quarantine_ip(
        self,
        ip: str,
        reason: QuarantineReason,
        source: str,
        duration: Optional[int] = None,
        description: str = "",
        created_by: str = "system"
    ) -> QuarantineEntry:
        """
        Quarantine an IP address
        
        Args:
            ip: IP address to quarantine
            reason: Quarantine reason
            source: Quarantine source
            duration: Duration in seconds (None for permanent)
            description: Description
            created_by: Creator
            
        Returns:
            Quarantine entry
        """
        # Validate IP
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IP address: {ip}")
        
        entry_id = f"Q{int(time.time())}-{ip.replace('.', '-')}"
        
        expires = time.time() + duration if duration else None
        
        with self.lock:
            entry = QuarantineEntry(
                id=entry_id,
                target=ip,
                reason=reason,
                action=QuarantineAction.BLOCK_IP,
                source=source,
                timestamp=time.time(),
                expires=expires,
                description=description,
                created_by=created_by
            )
            
            self.quarantined[entry_id] = entry
            self.blocked_ips.add(ip)
            
            # Add firewall rule
            self._add_firewall_rule(ip)
            
            # Update statistics
            self.stats["total_quarantined"] += 1
            self.stats["active_quarantines"] += 1
            self.stats["by_reason"][reason.value] += 1
            
            self._save_quarantines()
            
            logger.warning(f"IP {ip} quarantined: {reason.value} ({duration}s)" if duration else f"IP {ip} quarantined permanently: {reason.value}")
            
            return entry
    
    def quarantine_subnet(
        self,
        subnet: str,
        reason: QuarantineReason,
        source: str,
        duration: Optional[int] = None,
        description: str = "",
        created_by: str = "system"
    ) -> QuarantineEntry:
        """
        Quarantine a subnet
        
        Args:
            subnet: Subnet to quarantine (CIDR notation)
            reason: Quarantine reason
            source: Quarantine source
            duration: Duration in seconds
            description: Description
            created_by: Creator
            
        Returns:
            Quarantine entry
        """
        # Validate subnet
        try:
            ipaddress.IPv4Network(subnet)
        except ValueError:
            raise ValueError(f"Invalid subnet: {subnet}")
        
        entry_id = f"Q{int(time.time())}-subnet-{hash(subnet) % 10000}"
        
        expires = time.time() + duration if duration else None
        
        with self.lock:
            entry = QuarantineEntry(
                id=entry_id,
                target=subnet,
                reason=reason,
                action=QuarantineAction.BLOCK_SUBNET,
                source=source,
                timestamp=time.time(),
                expires=expires,
                description=description,
                created_by=created_by
            )
            
            self.quarantined[entry_id] = entry
            self.blocked_subnets.add(subnet)
            
            # Add firewall rule for subnet
            self._add_firewall_rule(subnet, is_subnet=True)
            
            # Update statistics
            self.stats["total_quarantined"] += 1
            self.stats["active_quarantines"] += 1
            self.stats["by_reason"][reason.value] += 1
            
            self._save_quarantines()
            
            logger.warning(f"Subnet {subnet} quarantined: {reason.value}")
            
            return entry
    
    def _add_firewall_rule(self, target: str, is_subnet: bool = False) -> None:
        """
        Add firewall rule to block target
        
        Args:
            target: IP or subnet
            is_subnet: True if subnet
        """
        try:
            # Try iptables first
            cmd = [
                "iptables",
                "-A", "INPUT",
                "-s", target,
                "-j", "DROP",
                "-m", "comment",
                "--comment", f"Quarantine: {target}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Added iptables rule to block {target}")
            else:
                # Fallback to hosts.deny
                with open("/etc/hosts.deny", "a") as f:
                    f.write(f"ALL: {target}\n")
                logger.info(f"Added hosts.deny entry for {target}")
                
        except Exception as e:
            logger.error(f"Error adding firewall rule: {e}")
    
    def _remove_firewall_rule(self, target: str, is_subnet: bool = False) -> None:
        """
        Remove firewall rule for target
        
        Args:
            target: IP or subnet
            is_subnet: True if subnet
        """
        try:
            # Try iptables first
            cmd = [
                "iptables",
                "-D", "INPUT",
                "-s", target,
                "-j", "DROP"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Removed iptables rule for {target}")
                
        except Exception as e:
            logger.error(f"Error removing firewall rule: {e}")
    
    def release_quarantine(self, entry_id: str) -> bool:
        """
        Release a quarantine entry
        
        Args:
            entry_id: Quarantine entry ID
            
        Returns:
            True if released
        """
        with self.lock:
            if entry_id not in self.quarantined:
                return False
            
            entry = self.quarantined[entry_id]
            
            if not entry.active:
                return False
            
            entry.active = False
            
            # Remove from active sets
            if entry.action == QuarantineAction.BLOCK_IP:
                self.blocked_ips.discard(entry.target)
                self._remove_firewall_rule(entry.target)
            elif entry.action == QuarantineAction.BLOCK_SUBNET:
                self.blocked_subnets.discard(entry.target)
                self._remove_firewall_rule(entry.target, is_subnet=True)
            
            # Update statistics
            self.stats["active_quarantines"] -= 1
            
            self._save_quarantines()
            
            logger.info(f"Quarantine released: {entry.target}")
            return True
    
    def release_by_target(self, target: str) -> bool:
        """
        Release all quarantines for a target
        
        Args:
            target: IP or subnet
            
        Returns:
            True if any released
        """
        released = False
        with self.lock:
            for entry_id, entry in list(self.quarantined.items()):
                if entry.target == target and entry.active:
                    if self.release_quarantine(entry_id):
                        released = True
        return released
    
    def is_quarantined(self, ip: str) -> bool:
        """
        Check if IP is quarantined
        
        Args:
            ip: IP address to check
            
        Returns:
            True if quarantined
        """
        # Check direct IP match
        if ip in self.blocked_ips:
            return True
        
        # Check subnet matches
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for subnet in self.blocked_subnets:
                if ip_obj in ipaddress.IPv4Network(subnet):
                    return True
        except:
            pass
        
        return False
    
    def get_quarantine_info(self, ip: str) -> Optional[QuarantineEntry]:
        """
        Get quarantine information for an IP
        
        Args:
            ip: IP address
            
        Returns:
            Quarantine entry or None
        """
        # Check direct match
        for entry in self.quarantined.values():
            if entry.active and entry.target == ip:
                return entry
        
        # Check subnet matches
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for entry in self.quarantined.values():
                if entry.active and entry.action == QuarantineAction.BLOCK_SUBNET:
                    try:
                        if ip_obj in ipaddress.IPv4Network(entry.target):
                            return entry
                    except:
                        pass
        except:
            pass
        
        return None
    
    def _cleanup_loop(self) -> None:
        """Periodic cleanup of expired quarantines"""
        while self.running:
            time.sleep(60)  # Check every minute
            self._cleanup_expired()
    
    def _cleanup_expired(self) -> int:
        """
        Remove expired quarantine entries
        
        Returns:
            Number of entries removed
        """
        count = 0
        with self.lock:
            for entry_id, entry in list(self.quarantined.items()):
                if entry.active and entry.is_expired():
                    if self.release_quarantine(entry_id):
                        count += 1
                        self.stats["expired_quarantines"] += 1
        
        if count > 0:
            logger.info(f"Cleaned up {count} expired quarantine entries")
        
        return count
    
    def get_active_quarantines(self) -> List[QuarantineEntry]:
        """Get all active quarantines"""
        with self.lock:
            return [e for e in self.quarantined.values() if e.active]
    
    def get_statistics(self) -> Dict:
        """Get quarantine statistics"""
        with self.lock:
            return {
                "total_quarantined": self.stats["total_quarantined"],
                "active_quarantines": self.stats["active_quarantines"],
                "expired_quarantines": self.stats["expired_quarantines"],
                "blocked_ips": len(self.blocked_ips),
                "blocked_subnets": len(self.blocked_subnets),
                "by_reason": dict(self.stats["by_reason"])
            }
    
    def shutdown(self) -> None:
        """Shutdown quarantine manager"""
        logger.info("Shutting down quarantine manager...")
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        
        # Save before exit
        self._save_quarantines()
        logger.info("Quarantine manager stopped")
