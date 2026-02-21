#!/usr/bin/env python3
import os
import sys
import time
import json
import yaml
import sqlite3
import hashlib
import logging
import requests
import argparse
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import setup_logging, get_logger
from src.detection.threat_intel import ThreatIntelligence, ThreatFeed, ThreatIndicator, ThreatFeedType

logger = get_logger(__name__)


class ThreatIntelUpdater:
    """
    Threat intelligence feed updater
    Downloads and processes threat feeds
    """
    
    def __init__(self, config_path: Optional[str] = None, db_path: str = "data/threat_intel.db"):
        """
        Initialize updater
        
        Args:
            config_path: Path to configuration file
            db_path: Path to threat intel database
        """
        self.config_path = config_path
        self.db_path = db_path
        self.feeds: List[Dict] = []
        self.stats = {
            "total_feeds": 0,
            "successful_updates": 0,
            "failed_updates": 0,
            "total_indicators": 0,
            "new_indicators": 0,
            "start_time": time.time()
        }
        
        # Load configuration
        self.load_config()
        
        # Initialize threat intel
        self.threat_intel = ThreatIntelligence(db_path)
        
        # Setup logging
        setup_logging(log_dir="logs", log_level="info")
    
    def load_config(self) -> None:
        """Load feed configuration"""
        default_config = {
            "feeds": [
                {
                    "name": "AlienVault OTX",
                    "url": "https://otx.alienvault.com/api/v1/indicators/export",
                    "type": "ip",
                    "format": "json",
                    "enabled": False,
                    "update_interval": 3600,
                    "api_key_env": "OTX_API_KEY"
                },
                {
                    "name": "AbuseIPDB",
                    "url": "https://api.abuseipdb.com/api/v2/blacklist",
                    "type": "ip",
                    "format": "json",
                    "enabled": False,
                    "update_interval": 3600,
                    "api_key_env": "ABUSEIPDB_API_KEY"
                },
                {
                    "name": "Firehol Level 1",
                    "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                    "type": "ip",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 86400
                },
                {
                    "name": "Firehol Level 2",
                    "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                    "type": "ip",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 86400
                },
                {
                    "name": "MalwareDomains",
                    "url": "https://mirror1.malwaredomains.com/files/justdomains",
                    "type": "domain",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 86400
                },
                {
                    "name": "Emerging Threats Compromised",
                    "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                    "type": "ip",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 3600
                },
                {
                    "name": "CINSscore",
                    "url": "https://cinsscore.com/list/ci-badguys.txt",
                    "type": "ip",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 3600
                },
                {
                    "name": "Blocklist.de",
                    "url": "https://lists.blocklist.de/lists/all.txt",
                    "type": "ip",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 3600
                },
                {
                    "name": "Spamhaus DROP",
                    "url": "https://www.spamhaus.org/drop/drop.txt",
                    "type": "ip",
                    "format": "txt",
                    "enabled": True,
                    "update_interval": 86400
                },
                {
                    "name": "SSL Blacklist",
                    "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                    "type": "ip",
                    "format": "csv",
                    "enabled": True,
                    "update_interval": 3600
                }
            ],
            "settings": {
                "timeout": 30,
                "max_workers": 5,
                "verify_ssl": True,
                "user_agent": "SOC-Firewall/1.0"
            }
        }
        
        if self.config_path and Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                if self.config_path.endswith('.yaml'):
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
                
                self.feeds = config.get('feeds', default_config['feeds'])
                self.settings = config.get('settings', default_config['settings'])
        else:
            self.feeds = default_config['feeds']
            self.settings = default_config['settings']
        
        self.stats["total_feeds"] = len([f for f in self.feeds if f.get('enabled', True)])
        logger.info(f"Loaded {self.stats['total_feeds']} enabled threat feeds")
    
    def download_feed(self, feed: Dict) -> List[ThreatIndicator]:
        """
        Download and parse a threat feed
        
        Args:
            feed: Feed configuration
            
        Returns:
            List of threat indicators
        """
        indicators = []
        feed_name = feed['name']
        
        try:
            logger.info(f"Downloading feed: {feed_name}")
            
            # Prepare headers
            headers = {
                'User-Agent': self.settings.get('user_agent', 'SOC-Firewall/1.0')
            }
            
            # Add API key if needed
            api_key_env = feed.get('api_key_env')
            if api_key_env:
                api_key = os.getenv(api_key_env)
                if api_key:
                    if 'AbuseIPDB' in feed_name:
                        headers['Key'] = api_key
                    elif 'AlienVault' in feed_name:
                        headers['X-OTX-API-KEY'] = api_key
                    else:
                        headers['Authorization'] = f"Bearer {api_key}"
            
            # Download feed
            response = requests.get(
                feed['url'],
                headers=headers,
                timeout=self.settings.get('timeout', 30),
                verify=self.settings.get('verify_ssl', True)
            )
            response.raise_for_status()
            
            # Parse based on format
            feed_type = ThreatFeedType(feed['type'])
            feed_format = feed.get('format', 'txt')
            
            if feed_format == 'json':
                indicators = self._parse_json_feed(response.json(), feed)
            elif feed_format == 'csv':
                indicators = self._parse_csv_feed(response.text, feed)
            else:  # txt
                indicators = self._parse_txt_feed(response.text, feed)
            
            logger.info(f"Downloaded {len(indicators)} indicators from {feed_name}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading feed {feed_name}: {e}")
            self.stats["failed_updates"] += 1
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {e}")
            self.stats["failed_updates"] += 1
        
        return indicators
    
    def _parse_txt_feed(self, content: str, feed: Dict) -> List[ThreatIndicator]:
        """Parse text format feed"""
        indicators = []
        feed_type = ThreatFeedType(feed['type'])
        current_time = time.time()
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
