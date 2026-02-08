"""
===========================================================
FILE: threat_intel.py
PURPOSE: Check IP reputation, geolocation, threat analysis
SYSTEM: Kali Linux
MEMBER: 3 (Defense System)
===========================================================

WHAT THIS FILE DOES:
--------------------
1. Checks if IP is malicious using AbuseIPDB API
2. Gets IP geolocation (country, city)
3. Maintains local blacklist/whitelist
4. Caches results to avoid API spam
5. Calculates threat score

APIs USED:
----------
- AbuseIPDB (IP reputation)
- ip-api.com (Geolocation - free, no key needed)

===========================================================
"""

# ========================
# IMPORTS
# ========================

import requests
import json
import logging
import time
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple

# ========================
# LOGGING SETUP
# ========================

logging.basicConfig(
    filename='threat_intel_log.txt',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ========================
# CONFIGURATION
# ========================

class ThreatConfig:
    """
    Configuration for threat intelligence.
    Store API keys and settings here.
    """
    
    # AbuseIPDB API Key
    # Get free key: https://www.abuseipdb.com/register
    ABUSEIPDB_API_KEY = "YOUR_API_KEY_HERE"
    
    # Cache settings
    CACHE_DURATION_MINUTES = 30
    
    # Threat thresholds
    THREAT_THRESHOLDS = {
        'low': 25,
        'medium': 50,
        'high': 75,
        'critical': 90
    }
    
    # Request timeout
    REQUEST_TIMEOUT = 10
    
    # Rate limiting (requests per minute)
    RATE_LIMIT = 30


# ========================
# LOCAL THREAT DATABASE
# ========================

class LocalThreatDB:
    """
    Local database of known malicious and safe IPs.
    Works offline without API.
    """
    
    # Known malicious IPs (add more as needed)
    BLACKLIST = {
        '45.33.32.156',      # Scanners
        '185.220.101.1',     # Tor exit node
        '171.25.193.20',     # Tor exit node
        '89.248.167.131',    # Known attacker
        '45.155.205.233',    # Bruteforce
        '194.26.29.1',       # Scanner
        '5.188.210.227',     # Malicious
        '195.54.160.149',    # Botnet
        '192.241.220.183',   # Scanner
        '45.129.56.200',     # Attacker
    }
    
    # Known safe IPs (whitelist)
    WHITELIST = {
        '8.8.8.8',           # Google DNS
        '8.8.4.4',           # Google DNS
        '1.1.1.1',           # Cloudflare DNS
        '1.0.0.1',           # Cloudflare DNS
        '208.67.222.222',    # OpenDNS
        '208.67.220.220',    # OpenDNS
        '9.9.9.9',           # Quad9 DNS
    }
    
    # Known malicious subnets (first 3 octets)
    MALICIOUS_SUBNETS = {
        '45.155.205',
        '185.220.101',
        '171.25.193',
        '89.248.167',
    }
    
    @classmethod
    def check_local(cls, ip_address: str) -> Tuple[str, int]:
        """
        Checks IP against local database.
        
        Args:
            ip_address: IP to check
        
        Returns:
            Tuple of (status, confidence)
            status: 'malicious', 'safe', 'unknown'
            confidence: 0-100
        """
        
        # Check whitelist first
        if ip_address in cls.WHITELIST:
            return ('safe', 100)
        
        # Check blacklist
        if ip_address in cls.BLACKLIST:
            return ('malicious', 100)
        
        # Check malicious subnets
        subnet = '.'.join(ip_address.split('.')[:3])
        if subnet in cls.MALICIOUS_SUBNETS:
            return ('malicious', 80)
        
        # Check if private IP (always safe)
        if cls._is_private_ip(ip_address):
            return ('safe', 100)
        
        return ('unknown', 0)
    
    @staticmethod
    def _is_private_ip(ip_address: str) -> bool:
        """
        Checks if IP is private/local.
        Private IPs are not threats.
        """
        
        parts = ip_address.split('.')
        
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.x.x.x
            if first == 10:
                return True
            
            # 172.16.x.x - 172.31.x.x
            if first == 172 and 16 <= second <= 31:
                return True
            
            # 192.168.x.x
            if first == 192 and second == 168:
                return True
            
            # 127.x.x.x (localhost)
            if first == 127:
                return True
            
            return False
        
        except ValueError:
            return False


# ========================
# CACHE SYSTEM
# ========================

class ThreatCache:
    """
    Caches API results to reduce requests.
    Saves money and improves speed.
    """
    
    def __init__(self):
        self.cache = {}
        self.cache_file = 'threat_cache.json'
        self._load_cache()
    
    def _load_cache(self):
        """Loads cache from file."""
        
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
        except Exception:
            self.cache = {}
    
    def _save_cache(self):
        """Saves cache to file."""
        
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            pass
    
    def get(self, ip_address: str) -> Optional[Dict]:
        """
        Gets cached result for IP.
        Returns None if not cached or expired.
        """
        
        if ip_address not in self.cache:
            return None
        
        entry = self.cache[ip_address]
        cached_time = datetime.fromisoformat(entry['timestamp'])
        expiry = cached_time + timedelta(minutes=ThreatConfig.CACHE_DURATION_MINUTES)
        
        if datetime.now() > expiry:
            del self.cache[ip_address]
            return None
        
        return entry['data']
    
    def set(self, ip_address: str, data: Dict):
        """Stores result in cache."""
        
        self.cache[ip_address] = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self._save_cache()
    
    def clear(self):
        """Clears all cache."""
        
        self.cache = {}
        self._save_cache()


# ========================
# RATE LIMITER
# ========================

class RateLimiter:
    """
    Prevents API rate limit violations.
    Tracks requests per minute.
    """
    
    def __init__(self, max_requests: int = 30):
        self.max_requests = max_requests
        self.requests = []
    
    def can_request(self) -> bool:
        """Checks if we can make a request."""
        
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # Remove old requests
        self.requests = [r for r in self.requests if r > minute_ago]
        
        return len(self.requests) < self.max_requests
    
    def add_request(self):
        """Records a request."""
        
        self.requests.append(datetime.now())
    
    def wait_time(self) -> int:
        """Returns seconds to wait before next request."""
        
        if self.can_request():
            return 0
        
        oldest = min(self.requests)
        wait = 60 - (datetime.now() - oldest).seconds
        
        return max(0, wait)


# ========================
# THREAT INTELLIGENCE CLASS
# ========================

class ThreatIntelligence:
    """
    Main threat intelligence engine.
    Combines multiple sources for comprehensive analysis.
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize threat intelligence.
        
        Args:
            api_key: AbuseIPDB API key (optional)
        """
        
        self.api_key = api_key or ThreatConfig.ABUSEIPDB_API_KEY
        self.cache = ThreatCache()
        self.rate_limiter = RateLimiter(ThreatConfig.RATE_LIMIT)
        self.stats = {
            'total_checks': 0,
            'cache_hits': 0,
            'api_calls': 0,
            'threats_found': 0
        }
        
        logging.info("ThreatIntelligence initialized")
        print("[THREAT-INTEL] ✅ Initialized")
    
    # ========================
    # VALIDATE IP
    # ========================
    
    def _validate_ip(self, ip_address: str) -> bool:
        """Validates IP address format."""
        
        parts = ip_address.split('.')
        
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True
    
    # ========================
    # ABUSEIPDB CHECK
    # ========================
    
    def _check_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """
        Checks IP reputation on AbuseIPDB.
        
        Args:
            ip_address: IP to check
        
        Returns:
            Dict with abuse data or None if failed
        """
        
        # Check if API key is set
        if self.api_key == "YOUR_API_KEY_HERE" or not self.api_key:
            return None
        
        # Check rate limit
        if not self.rate_limiter.can_request():
            wait = self.rate_limiter.wait_time()
            print(f"[THREAT-INTEL] ⏳ Rate limited. Wait {wait}s")
            return None
        
        # API endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'
        
        # Headers with API key
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        # Query parameters
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            # Make request
            self.rate_limiter.add_request()
            self.stats['api_calls'] += 1
            
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=ThreatConfig.REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                return {
                    'source': 'abuseipdb',
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'is_tor': data.get('isTor', False),
                    'is_public': data.get('isPublic', True),
                    'last_reported': data.get('lastReportedAt', None)
                }
            
            elif response.status_code == 429:
                print("[THREAT-INTEL] ⚠️  API rate limit reached")
                logging.warning("AbuseIPDB rate limit reached")
                return None
            
            else:
                logging.error(f"AbuseIPDB error: {response.status_code}")
                return None
        
        except requests.exceptions.Timeout:
            print("[THREAT-INTEL] ⚠️  API timeout")
            return None
        
        except requests.exceptions.RequestException as e:
            logging.error(f"AbuseIPDB request failed: {e}")
            return None
    
    # ========================
    # GEOLOCATION CHECK
    # ========================
    
    def _get_geolocation(self, ip_address: str) -> Optional[Dict]:
        """
        Gets IP geolocation data.
        Uses free ip-api.com service.
        
        Args:
            ip_address: IP to locate
        
        Returns:
            Dict with location data
        """
        
        # Skip private IPs
        if LocalThreatDB._is_private_ip(ip_address):
            return {
                'country': 'Local Network',
                'country_code': 'LO',
                'city': 'Private',
                'region': 'Internal',
                'lat': 0,
                'lon': 0,
                'isp': 'Local',
                'org': 'Private Network'
            }
        
        url = f'http://ip-api.com/json/{ip_address}'
        
        try:
            response = requests.get(
                url,
                timeout=ThreatConfig.REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown')
                    }
            
            return None
        
        except Exception:
            return None
    
    # ========================
    # CALCULATE THREAT LEVEL
    # ========================
    
    def _calculate_threat_level(self, score: int) -> str:
        """
        Converts numeric score to threat level.
        
        Args:
            score: 0-100 abuse score
        
        Returns:
            'low', 'medium', 'high', or 'critical'
        """
        
        thresholds = ThreatConfig.THREAT_THRESHOLDS
        
        if score >= thresholds['critical']:
            return 'critical'
        elif score >= thresholds['high']:
            return 'high'
        elif score >= thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    # ========================
    # MAIN CHECK METHOD
    # ========================
    
    def check_ip(self, ip_address: str, use_cache: bool = True) -> Dict:
        """
        Comprehensive IP threat analysis.
        
        Args:
            ip_address: IP to analyze
            use_cache: Whether to use cached results
        
        Returns:
            Complete threat report
        """
        
        self.stats['total_checks'] += 1
        
        # Step 1: Validate IP
        if not self._validate_ip(ip_address):
            return {
                'ip': ip_address,
                'valid': False,
                'error': 'Invalid IP format'
            }
        
        # Step 2: Check cache
        if use_cache:
            cached = self.cache.get(ip_address)
            if cached:
                self.stats['cache_hits'] += 1
                cached['from_cache'] = True
                return cached
        
        # Step 3: Check local database first
        local_status, local_confidence = LocalThreatDB.check_local(ip_address)
        
        # Step 4: Build initial result
        result = {
            'ip': ip_address,
            'valid': True,
            'timestamp': datetime.now().isoformat(),
            'from_cache': False,
            'local_status': local_status,
            'local_confidence': local_confidence,
            'abuse_score': 0,
            'threat_level': 'low',
            'is_malicious': False,
            'is_tor': False,
            'total_reports': 0,
            'geolocation': None,
            'recommendation': 'allow'
        }
        
        # Step 5: If local says malicious, trust it
        if local_status == 'malicious':
            result['abuse_score'] = local_confidence
            result['threat_level'] = 'high' if local_confidence < 100 else 'critical'
            result['is_malicious'] = True
            result['recommendation'] = 'block'
            self.stats['threats_found'] += 1
        
        # Step 6: If local says safe, trust it
        elif local_status == 'safe':
            result['abuse_score'] = 0
            result['threat_level'] = 'low'
            result['recommendation'] = 'allow'
        
        # Step 7: Unknown - check AbuseIPDB
        else:
            abuse_data = self._check_abuseipdb(ip_address)
            
            if abuse_data:
                result['abuse_score'] = abuse_data['abuse_score']
                result['total_reports'] = abuse_data['total_reports']
                result['is_tor'] = abuse_data['is_tor']
                result['isp'] = abuse_data.get('isp', 'Unknown')
                result['domain'] = abuse_data.get('domain', 'Unknown')
                
                # Calculate threat level
                result['threat_level'] = self._calculate_threat_level(abuse_data['abuse_score'])
                
                # Determine if malicious
                if abuse_data['abuse_score'] >= ThreatConfig.THREAT_THRESHOLDS['high']:
                    result['is_malicious'] = True
                    result['recommendation'] = 'block'
                    self.stats['threats_found'] += 1
                elif abuse_data['abuse_score'] >= ThreatConfig.THREAT_THRESHOLDS['medium']:
                    result['recommendation'] = 'monitor'
                else:
                    result['recommendation'] = 'allow'
        
        # Step 8: Get geolocation
        geo = self._get_geolocation(ip_address)
        if geo:
            result['geolocation'] = geo
            result['country'] = geo['country']
            result['country_code'] = geo['country_code']
            result['city'] = geo['city']
        
        # Step 9: Cache result
        self.cache.set(ip_address, result)
        
        # Step 10: Log
        logging.info(f"Checked {ip_address}: {result['threat_level']} ({result['abuse_score']})")
        
        return result
    
    # ========================
    # QUICK CHECK (FOR GAME)
    # ========================
    
    def quick_check(self, ip_address: str) -> Tuple[str, str, int]:
        """
        Fast check for game integration.
        Returns only essential data.
        
        Args:
            ip_address: IP to check
        
        Returns:
            Tuple of (threat_level, country, abuse_score)
        """
        
        result = self.check_ip(ip_address)
        
        return (
            result.get('threat_level', 'low'),
            result.get('country', 'Unknown'),
            result.get('abuse_score', 0)
        )
    
    # ========================
    # BATCH CHECK
    # ========================
    
    def check_multiple(self, ip_list: list) -> list:
        """
        Checks multiple IPs.
        
        Args:
            ip_list: List of IPs
        
        Returns:
            List of results
        """
        
        results = []
        
        for ip in ip_list:
            result = self.check_ip(ip)
            results.append(result)
            time.sleep(0.5)  # Avoid rate limiting
        
        return results
    
    # ========================
    # GET STATS
    # ========================
    
    def get_stats(self) -> Dict:
        """Returns intelligence statistics."""
        
        return {
            **self.stats,
            'cache_size': len(self.cache.cache),
            'timestamp': datetime.now().isoformat()
        }
    
    # ========================
    # CLEAR CACHE
    # ========================
    
    def clear_cache(self):
        """Clears threat cache."""
        
        self.cache.clear()
        print("[THREAT-INTEL] ✅ Cache cleared")


# ========================
# PRETTY PRINT RESULT
# ========================

def print_threat_report(result: Dict):
    """
    Prints formatted threat report.
    Used for testing and demo.
    """
    
    if not result.get('valid'):
        print(f"[ERROR] {result.get('error', 'Invalid IP')}")
        return
    
    # Threat level colors (terminal)
    level = result.get('threat_level', 'low')
    level_icons = {
        'low': '🟢',
        'medium': '🟡',
        'high': '🟠',
        'critical': '🔴'
    }
    
    icon = level_icons.get(level, '⚪')
    
    print()
    print("=" * 50)
    print(f"  THREAT INTELLIGENCE REPORT")
    print("=" * 50)
    print(f"  IP Address    : {result['ip']}")
    print(f"  Threat Level  : {icon} {level.upper()}")
    print(f"  Abuse Score   : {result['abuse_score']}/100")
    print(f"  Is Malicious  : {'YES ⚠️' if result['is_malicious'] else 'NO'}")
    print(f"  Is Tor Exit   : {'YES' if result.get('is_tor') else 'NO'}")
    print(f"  Total Reports : {result.get('total_reports', 0)}")
    print("-" * 50)
    
    geo = result.get('geolocation')
    if geo:
        print(f"  Country       : {geo['country']} ({geo['country_code']})")
        print(f"  City          : {geo['city']}")
        print(f"  ISP           : {geo.get('isp', 'Unknown')}")
        print(f"  Coordinates   : {geo['lat']}, {geo['lon']}")
    
    print("-" * 50)
    print(f"  Recommendation: {result['recommendation'].upper()}")
    print(f"  From Cache    : {'Yes' if result.get('from_cache') else 'No'}")
    print("=" * 50)
    print()


# ========================
# STANDALONE TEST MODE
# ========================

if __name__ == "__main__":
    
    print("=" * 50)
    print("    THREAT INTELLIGENCE — TEST MODE")
    print("=" * 50)
    print()
    
    # Check if API key is set
    if ThreatConfig.ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
        print("[WARNING] AbuseIPDB API key not set!")
        print("[INFO] Get free key: https://www.abuseipdb.com/register")
        print("[INFO] Using local database + geolocation only")
        print()
    
    # Create intelligence instance
    intel = ThreatIntelligence()
    print()
    
    # Menu
    while True:
        print("-" * 30)
        print("1. Check single IP")
        print("2. Check multiple IPs")
        print("3. Quick check (game mode)")
        print("4. Show stats")
        print("5. Clear cache")
        print("6. Test known malicious IP")
        print("7. Test known safe IP")
        print("8. Exit")
        print("-" * 30)
        
        choice = input("Choice: ").strip()
        
        if choice == '1':
            ip = input("Enter IP: ").strip()
            result = intel.check_ip(ip)
            print_threat_report(result)
        
        elif choice == '2':
            ips = input("Enter IPs (comma separated): ").strip()
            ip_list = [ip.strip() for ip in ips.split(',')]
            results = intel.check_multiple(ip_list)
            for r in results:
                print_threat_report(r)
        
        elif choice == '3':
            ip = input("Enter IP: ").strip()
            level, country, score = intel.quick_check(ip)
            print(f"\n  {ip}: {level.upper()} | {country} | Score: {score}\n")
        
        elif choice == '4':
            stats = intel.get_stats()
            print(f"\n  Total Checks : {stats['total_checks']}")
            print(f"  Cache Hits   : {stats['cache_hits']}")
            print(f"  API Calls    : {stats['api_calls']}")
            print(f"  Threats Found: {stats['threats_found']}")
            print(f"  Cache Size   : {stats['cache_size']}\n")
        
        elif choice == '5':
            intel.clear_cache()
        
        elif choice == '6':
            # Test with known malicious IP from local database
            result = intel.check_ip('45.33.32.156')
            print_threat_report(result)
        
        elif choice == '7':
            # Test with known safe IP
            result = intel.check_ip('8.8.8.8')
            print_threat_report(result)
        
        elif choice == '8':
            print("[THREAT-INTEL] Exiting...")
            break
        
        else:
            print("Invalid choice")
