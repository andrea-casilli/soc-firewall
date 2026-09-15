import time
import json
import sqlite3
import threading
import requests
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import ipaddress
from collections import defaultdict

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatFeedType(Enum):
    """Types of threat intelligence feeds"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"


class ThreatConfidence(Enum):
    """Confidence levels"""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.95


@dataclass
class ThreatIndicator:
    """Individual threat indicator"""
    value: str
    type: ThreatFeedType
    source: str
    confidence: float
    first_seen: float
    last_seen: float
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    reference: Optional[str] = None
    expires: Optional[float] = None
    
    def is_expired(self) -> bool:
        """Check if indicator has expired"""
        if self.expires:
            return time.time() > self.expires
        return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "value": self.value,
            "type": self.type.value,
            "source": self.source,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
            "description": self.description,
            "reference": self.reference
        }


@dataclass
class ThreatFeed:
    """Threat feed configuration"""
    name: str
    url: str
    type: ThreatFeedType
    format: str  # json, csv, txt, stix
    update_interval: int  # seconds
    enabled: bool = True
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    parser: Optional[str] = None


class ThreatIntelligence:
    """
    Threat intelligence integration module
    Manages threat feeds and provides lookup capabilities
    
    Features:
    - Multiple feed sources
    - Automatic feed updates
    - Persistent storage (SQLite)
    - Confidence scoring
    - Expiration management
    - Fast lookup with indexing
    """
    
    def __init__(self, db_path: str = "data/threat_intel.db"):
        """
        Initialize threat intelligence module
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.feeds: List[ThreatFeed] = []
        self.cache: Dict[str, ThreatIndicator] = {}
        self.cache_lock = threading.RLock()
        
        # In-memory indexes for fast lookup
        self.ip_index: Dict[str, List[ThreatIndicator]] = defaultdict(list)
        self.domain_index: Dict[str, List[ThreatIndicator]] = defaultdict(list)
        self.hash_index: Dict[str, List[ThreatIndicator]] = defaultdict(list)
        
        # Statistics
        self.stats = {
            "total_indicators": 0,
            "feeds_active": 0,
            "last_update": None,
            "updates_performed": 0,
            "lookup_hits": 0,
            "lookup_misses": 0
        }
        
        # Initialize database
        self._init_database()
        
        # Load default feeds
        self._load_default_feeds()
        
        # Start update threads
        self.running = True
        self.update_threads = []
        self._start_update_threads()
        
        # Load cache from database
        self._load_cache()
        
        logger.info(f"Threat Intelligence initialized with {len(self.feeds)} feeds")
    
    def _init_database(self) -> None:
        """Initialize SQLite database"""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            
            # Create tables
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires REAL,
                    tags TEXT,
                    description TEXT,
                    reference TEXT,
                    UNIQUE(value, type, source)
                )
            """)
            
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_value ON indicators(value)
            """)
            
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_type ON indicators(type)
            """)
            
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires ON indicators(expires)
            """)
            
            self.conn.commit()
            logger.debug("Threat intelligence database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def _load_default_feeds(self) -> None:
        """Load default threat feeds"""
        default_feeds = [
            ThreatFeed(
                name="AlienVault OTX",
                url="https://otx.alienvault.com/api/v1/indicators/export",
                type=ThreatFeedType.IP,
                format="json",
                update_interval=3600,  # 1 hour
                headers={"X-OTX-API-KEY": "${OTX_API_KEY}"}
            ),
            ThreatFeed(
                name="AbuseIPDB",
                url="https://api.abuseipdb.com/api/v2/blacklist",
                type=ThreatFeedType.IP,
                format="json",
                update_interval=3600,
                headers={"Key": "${ABUSEIPDB_API_KEY}", "Accept": "application/json"}
            ),
            ThreatFeed(
                name="Firehol Level 1",
                url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                type=ThreatFeedType.IP,
                format="txt",
                update_interval=86400  # 24 hours
            ),
            ThreatFeed(
                name="MalwareDomains",
                url="https://mirror1.malwaredomains.com/files/justdomains",
                type=ThreatFeedType.DOMAIN,
                format="txt",
                update_interval=86400
            ),
            ThreatFeed(
                name="Emerging Threats",
                url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                type=ThreatFeedType.IP,
                format="txt",
                update_interval=3600
            ),
            ThreatFeed(
                name="CINSscore",
                url="https://cinsscore.com/list/ci-badguys.txt",
                type=ThreatFeedType.IP,
                format="txt",
                update_interval=3600
            )
        ]
        
        for feed in default_feeds:
            # Check if API key is configured
            if feed.url and "${" not in feed.url:
                self.add_feed(feed)
    
    def add_feed(self, feed: ThreatFeed) -> None:
        """Register one enabled feed without performing a network request."""
        if not feed.enabled:
            return
        if any(existing.name == feed.name for existing in self.feeds):
            return
        self.feeds.append(feed)
        self.stats["feeds_active"] = len(self.feeds)

    def _start_update_threads(self) -> None:
        """Keep feed registration side-effect free; callers update feeds explicitly."""
        self.update_threads = []

    def _load_cache(self) -> None:
        """Load persisted indicators into the in-memory indexes."""
        rows = self.conn.execute(
            "SELECT value, type, source, confidence, first_seen, last_seen, expires, tags, description, reference FROM indicators"
        ).fetchall()
        for row in rows:
            try:
                indicator = ThreatIndicator(
                    value=row[0],
                    type=ThreatFeedType(row[1]),
                    source=row[2],
                    confidence=row[3],
                    first_seen=row[4],
                    last_seen=row[5],
                    expires=row[6],
                    tags=json.loads(row[7] or "[]"),
                    description=row[8],
                    reference=row[9],
                )
                self._index_indicator(indicator)
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                logger.warning("Skipping invalid threat-intel row: %s", error)
        self.stats["total_indicators"] = len(self.cache)

    def _index_indicator(self, indicator: ThreatIndicator) -> None:
        """Add an indicator to the cache and the index appropriate to its type."""
        key = f"{indicator.type.value}:{indicator.value.lower()}"
        self.cache[key] = indicator
        index = {
            ThreatFeedType.IP: self.ip_index,
            ThreatFeedType.DOMAIN: self.domain_index,
            ThreatFeedType.HASH: self.hash_index,
        }.get(indicator.type)
        if index is not None:
            index[indicator.value.lower()].append(indicator)

    def check_ip(self, ip: str) -> List[ThreatIndicator]:
        """Return active indicators matching a valid IP address."""
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            logger.warning("Invalid IP supplied to threat intelligence: %s", ip)
            return []
        matches = [item for item in self.ip_index.get(normalized, []) if not item.is_expired()]
        self.stats["lookup_hits" if matches else "lookup_misses"] += 1
        return matches

    def close(self) -> None:
        """Release local database resources."""
        self.running = False
        if hasattr(self, "conn"):
            self.conn.close()
