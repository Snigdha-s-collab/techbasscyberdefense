"""
===========================================================
FILE: attack_simulator.py
PURPOSE: Simulate various cyber attacks for game visualization
SYSTEM: Kali Linux
MEMBER: 3 (Defense System)
===========================================================

WHAT THIS FILE DOES:
--------------------
1. Simulates different attack types (DDoS, SYN Flood, Port Scan, etc.)
2. Generates fake packet data for visualization
3. Feeds packets to shared queue for game UI
4. Controls attack intensity and duration
5. Provides realistic attack patterns

ATTACK TYPES SUPPORTED:
-----------------------
- DDoS (Distributed Denial of Service)
- SYN Flood
- Port Scan
- Brute Force
- Ping Flood
- Slowloris
- DNS Amplification

INTEGRATION:
------------
- Packets go to: packet_queue (read by Packet Capture module)
- Defense triggered: firewall.py + threat_intel.py
- Visualization: Game UI reads queue and spawns sprites

===========================================================
"""

# ========================
# IMPORTS
# ========================

import random
import string
import threading
import time
import logging
from queue import Queue
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum

# ========================
# LOGGING SETUP
# ========================

logging.basicConfig(
    filename='attack_simulator_log.txt',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ========================
# ENUMS
# ========================

class AttackType(Enum):
    """Supported attack types."""
    DDOS = "ddos"
    SYN_FLOOD = "syn_flood"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    PING_FLOOD = "ping_flood"
    SLOWLORIS = "slowloris"
    DNS_AMPLIFICATION = "dns_amplification"


class Protocol(Enum):
    """Network protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    DNS = "DNS"
    SSH = "SSH"
    FTP = "FTP"


class Severity(Enum):
    """Attack severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# ========================
# CONFIGURATION
# ========================

class AttackConfig:
    """Configuration for attack simulation."""
    
    # Default target (local network simulation)
    DEFAULT_TARGET = "192.168.1.100"
    
    # Packets per second by intensity
    INTENSITY_PPS = {
        'low': 5,
        'medium': 15,
        'high': 30,
        'extreme': 50
    }
    
    # Common attack ports
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    
    # Malicious IP ranges (simulated)
    MALICIOUS_IP_RANGES = [
        "45.33.32.",
        "185.220.101.",
        "171.25.193.",
        "89.248.167.",
        "45.155.205.",
        "194.26.29.",
        "5.188.210.",
        "195.54.160.",
        "192.241.220.",
        "45.129.56.",
        "103.251.167.",
        "91.240.118.",
        "185.156.73.",
        "45.95.169.",
        "194.165.16."
    ]
    
    # Botnet simulation (multiple sources)
    BOTNET_SIZE = {
        'small': 10,
        'medium': 50,
        'large': 100
    }

# ========================
# PACKET DATA CLASS
# ========================

@dataclass
class SimulatedPacket:
    """
    Represents a simulated network packet.
    This is what gets sent to the packet queue.
    """
    
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    size: int
    flags: str
    attack_type: str
    is_malicious: bool
    severity: str
    payload_preview: str
    
    def to_dict(self) -> Dict:
        """Converts packet to dictionary."""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.source_ip,
            'dst_ip': self.destination_ip,
            'src_port': self.source_port,
            'dst_port': self.destination_port,
            'protocol': self.protocol,
            'size': self.size,
            'flags': self.flags,
            'attack_type': self.attack_type,
            'is_malicious': self.is_malicious,
            'severity': self.severity,
            'payload': self.payload_preview
        }

# ========================
# IP GENERATOR
# ========================

class IPGenerator:
    """Generates realistic IP addresses for simulation."""
    
    @staticmethod
    def random_malicious_ip() -> str:
        """Generates a random malicious IP."""
        prefix = random.choice(AttackConfig.MALICIOUS_IP_RANGES)
        return f"{prefix}{random.randint(1, 254)}"
    
    @staticmethod
    def random_botnet_ips(count: int) -> List[str]:
        """Generates multiple botnet IPs."""
        ips = set()
        while len(ips) < count:
            ips.add(IPGenerator.random_malicious_ip())
        return list(ips)
    
    @staticmethod
    def random_internal_ip() -> str:
        """Generates random internal IP."""
        return f"192.168.1.{random.randint(1, 254)}"
    
    @staticmethod
    def random_public_ip() -> str:
        """Generates random public IP."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# ========================
# PAYLOAD GENERATOR
# ========================

class PayloadGenerator:
    """Generates realistic attack payloads."""
    
    @staticmethod
    def random_string(length: int = 16) -> str:
        """Generates random string."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def http_flood_payload() -> str:
        """HTTP flood request."""
        paths = ['/login', '/admin', '/api/users', '/search', '/wp-admin', '/phpmyadmin']
        return f"GET {random.choice(paths)} HTTP/1.1"
    
    @staticmethod
    def sql_injection_payload() -> str:
        """SQL injection attempt."""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM passwords--",
            "admin'--",
            "1; DELETE FROM users"
        ]
        return random.choice(payloads)
    
    @staticmethod
    def brute_force_payload() -> str:
        """Brute force login attempt."""
        usernames = ['admin', 'root', 'user', 'administrator', 'test']
        passwords = ['123456', 'password', 'admin', 'root', 'qwerty']
        return f"USER:{random.choice(usernames)} PASS:{random.choice(passwords)}"
    
    @staticmethod
    def dns_query_payload() -> str:
        """DNS amplification query."""
        domains = ['google.com', 'facebook.com', 'example.com', 'target.com']
        return f"DNS_QUERY:ANY {random.choice(domains)}"
    
    @staticmethod
    def syn_payload() -> str:
        """SYN flood payload."""
        return f"SYN SEQ={random.randint(1000000, 9999999)}"
    
    @staticmethod
    def icmp_payload() -> str:
        """ICMP ping payload."""
        return f"ICMP_ECHO ID={random.randint(1, 65535)} SEQ={random.randint(1, 1000)}"

# ========================
# ATTACK SIMULATOR CLASS
# ========================

class AttackSimulator:
    """
    Main attack simulation engine.
    Generates simulated cyber attacks for game visualization.
    """
    
    def __init__(self, packet_queue: Queue = None):
        """
        Initialize attack simulator.
        
        Args:
            packet_queue: Shared queue for packets (creates new if None)
        """
        
        # Packet queue (shared with other modules)
        self.packet_queue = packet_queue or Queue()
        
        # Active attacks tracking
        self.active_attacks: Dict[str, dict] = {}
        
        # Control flags
        self.running = False
        self.attack_threads: List[threading.Thread] = []
        
        # Statistics
        self.stats = {
            'total_packets_generated': 0,
            'attacks_launched': 0,
            'attacks_stopped': 0,
            'start_time': None
        }
        
        # Botnet IPs (pre-generated for realism)
        self.botnet_ips = IPGenerator.random_botnet_ips(AttackConfig.BOTNET_SIZE['medium'])
        
        logging.info("AttackSimulator initialized")
        print("[ATTACK-SIM] ✅ Initialized")
    
    # ========================
    # TIMESTAMP
    # ========================
    
    def _get_timestamp(self) -> str:
        """Returns current timestamp."""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # ========================
    # GENERATE ATTACK ID
    # ========================
    
    def _generate_attack_id(self) -> str:
        """Generates unique attack ID."""
        return f"ATK-{random.randint(10000, 99999)}"
    
    # ========================
    # CREATE PACKET
    # ========================
    
    def _create_packet(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str,
        attack_type: str,
        severity: str,
        flags: str = "",
        payload: str = ""
    ) -> SimulatedPacket:
        """Creates a simulated packet."""
        
        return SimulatedPacket(
            timestamp=self._get_timestamp(),
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            size=random.randint(64, 1500),
            flags=flags,
            attack_type=attack_type,
            is_malicious=True,
            severity=severity,
            payload_preview=payload[:50] if payload else ""
        )
    
    # ========================
    # SEND PACKET TO QUEUE
    # ========================
    
    def _send_packet(self, packet: SimulatedPacket):
        """Sends packet to shared queue."""
        
        self.packet_queue.put(packet.to_dict())
        self.stats['total_packets_generated'] += 1
    
    # ========================
    # DDoS ATTACK
    # ========================
    
    def _ddos_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates Distributed Denial of Service attack.
        Multiple source IPs flooding target.
        """
        
        pps = AttackConfig.INTENSITY_PPS.get(intensity, 10)
        delay = 1.0 / pps
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            source_ip = random.choice(self.botnet_ips)
            
            packet = self._create_packet(
                source_ip=source_ip,
                destination_ip=target,
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([80, 443, 8080]),
                protocol=Protocol.HTTP.value,
                attack_type=AttackType.DDOS.value,
                severity=Severity.CRITICAL.value,
                flags="PSH,ACK",
                payload=PayloadGenerator.http_flood_payload()
            )
            
            self._send_packet(packet)
            time.sleep(delay)
    
    # ========================
    # SYN FLOOD ATTACK
    # ========================
    
    def _syn_flood_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates SYN Flood attack.
        TCP SYN packets without completing handshake.
        """
        
        pps = AttackConfig.INTENSITY_PPS.get(intensity, 10)
        delay = 1.0 / pps
        source_ip = IPGenerator.random_malicious_ip()
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            packet = self._create_packet(
                source_ip=source_ip,
                destination_ip=target,
                source_port=random.randint(1024, 65535),
                destination_port=random.choice(AttackConfig.COMMON_PORTS),
                protocol=Protocol.TCP.value,
                attack_type=AttackType.SYN_FLOOD.value,
                severity=Severity.HIGH.value,
                flags="SYN",
                payload=PayloadGenerator.syn_payload()
            )
            
            self._send_packet(packet)
            time.sleep(delay)
    
    # ========================
    # PORT SCAN ATTACK
    # ========================
    
    def _port_scan_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates Port Scanning attack.
        Sequential port probing.
        """
        
        pps = AttackConfig.INTENSITY_PPS.get(intensity, 10)
        delay = 1.0 / pps
        source_ip = IPGenerator.random_malicious_ip()
        current_port = 1
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            packet = self._create_packet(
                source_ip=source_ip,
                destination_ip=target,
                source_port=random.randint(49152, 65535),
                destination_port=current_port,
                protocol=Protocol.TCP.value,
                attack_type=AttackType.PORT_SCAN.value,
                severity=Severity.MEDIUM.value,
                flags="SYN",
                payload=f"SCAN_PORT:{current_port}"
            )
            
            self._send_packet(packet)
            
            current_port += 1
            if current_port > 1024:
                current_port = 1
            
            time.sleep(delay)
    
    # ========================
    # BRUTE FORCE ATTACK
    # ========================
    
    def _brute_force_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates Brute Force login attack.
        Multiple authentication attempts.
        """
        
        pps = AttackConfig.INTENSITY_PPS.get(intensity, 10)
        delay = 1.0 / pps
        source_ip = IPGenerator.random_malicious_ip()
        target_ports = [22, 21, 3389, 23]
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            port = random.choice(target_ports)
            protocol = Protocol.SSH.value if port == 22 else Protocol.FTP.value
            
            packet = self._create_packet(
                source_ip=source_ip,
                destination_ip=target,
                source_port=random.randint(49152, 65535),
                destination_port=port,
                protocol=protocol,
                attack_type=AttackType.BRUTE_FORCE.value,
                severity=Severity.HIGH.value,
                flags="PSH,ACK",
                payload=PayloadGenerator.brute_force_payload()
            )
            
            self._send_packet(packet)
            time.sleep(delay)
    
    # ========================
    # PING FLOOD ATTACK
    # ========================
    
    def _ping_flood_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates ICMP Ping Flood attack.
        Overwhelming ICMP echo requests.
        """
        
        pps = AttackConfig.INTENSITY_PPS.get(intensity, 10)
        delay = 1.0 / pps
        source_ip = IPGenerator.random_malicious_ip()
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            packet = self._create_packet(
                source_ip=source_ip,
                destination_ip=target,
                source_port=0,
                destination_port=0,
                protocol=Protocol.ICMP.value,
                attack_type=AttackType.PING_FLOOD.value,
                severity=Severity.MEDIUM.value,
                flags="ECHO_REQUEST",
                payload=PayloadGenerator.icmp_payload()
            )
            
            self._send_packet(packet)
            time.sleep(delay)
    
    # ========================
    # SLOWLORIS ATTACK
    # ========================
    
    def _slowloris_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates Slowloris attack.
        Slow, persistent HTTP connections.
        """
        
        delay = 2.0
        source_ips = IPGenerator.random_botnet_ips(20)
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            packet = self._create_packet(
                source_ip=random.choice(source_ips),
                destination_ip=target,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol=Protocol.HTTP.value,
                attack_type=AttackType.SLOWLORIS.value,
                severity=Severity.HIGH.value,
                flags="PSH",
                payload="X-Custom-Header: keep-alive-chunk"
            )
            
            self._send_packet(packet)
            time.sleep(delay)
    
    # ========================
    # DNS AMPLIFICATION ATTACK
    # ========================
    
    def _dns_amplification_attack(self, attack_id: str, target: str, intensity: str):
        """
        Simulates DNS Amplification attack.
        Spoofed DNS queries causing amplified responses.
        """
        
        pps = AttackConfig.INTENSITY_PPS.get(intensity, 10)
        delay = 1.0 / pps
        dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
        
        while self.active_attacks.get(attack_id, {}).get('running', False):
            
            packet = self._create_packet(
                source_ip=target,
                destination_ip=random.choice(dns_servers),
                source_port=random.randint(49152, 65535),
                destination_port=53,
                protocol=Protocol.DNS.value,
                attack_type=AttackType.DNS_AMPLIFICATION.value,
                severity=Severity.CRITICAL.value,
                flags="QUERY",
                payload=PayloadGenerator.dns_query_payload()
            )
            
            self._send_packet(packet)
            time.sleep(delay)
    
    # ========================
    # START ATTACK
    # ========================
    
    def start_attack(
        self,
        attack_type: str,
        target: str = None,
        intensity: str = "medium",
        duration: int = None
    ) -> str:
        """
        Starts a simulated attack.
        
        Args:
            attack_type: Type of attack (ddos, syn_flood, port_scan, etc.)
            target: Target IP address
            intensity: Attack intensity (low, medium, high, extreme)
            duration: Duration in seconds (None = until stopped)
        
        Returns:
            Attack ID for tracking
        """
        
        target = target or AttackConfig.DEFAULT_TARGET
        attack_id = self._generate_attack_id()
        
        # Attack method mapping
        attack_methods = {
            'ddos': self._ddos_attack,
            'syn_flood': self._syn_flood_attack,
            'port_scan': self._port_scan_attack,
            'brute_force': self._brute_force_attack,
            'ping_flood': self._ping_flood_attack,
            'slowloris': self._slowloris_attack,
            'dns_amplification': self._dns_amplification_attack
        }
        
        attack_method = attack_methods.get(attack_type.lower())
        
        if not attack_method:
            print(f"[ATTACK-SIM] ❌ Unknown attack type: {attack_type}")
            return None
        
        # Register attack
        self.active_attacks[attack_id] = {
            'type': attack_type,
            'target': target,
            'intensity': intensity,
            'running': True,
            'start_time': datetime.now().isoformat(),
            'packets_sent': 0
        }
        
        # Start attack thread
        thread = threading.Thread(
            target=attack_method,
            args=(attack_id, target, intensity),
            daemon=True
        )
        thread.start()
        self.attack_threads.append(thread)
        
        # Auto-stop if duration specified
        if duration:
            threading.Timer(duration, lambda: self.stop_attack(attack_id)).start()
        
        self.stats['attacks_launched'] += 1
        self.stats['start_time'] = datetime.now().isoformat()
        
        logging.info(f"Attack started: {attack_id} | Type: {attack_type} | Target: {target}")
        print(f"[ATTACK-SIM] 🚀 Attack started: {attack_id}")
        print(f"             Type: {attack_type.upper()}")
        print(f"             Target: {target}")
        print(f"             Intensity: {intensity}")
        
        return attack_id
    
    # ========================
    # STOP ATTACK
    # ========================
    
    def stop_attack(self, attack_id: str) -> bool:
        """
        Stops a specific attack.
        
        Args:
            attack_id: ID of attack to stop
        
        Returns:
            True if stopped successfully
        """
        
        if attack_id not in self.active_attacks:
            print(f"[ATTACK-SIM] ⚠️ Attack not found: {attack_id}")
            return False
        
        self.active_attacks[attack_id]['running'] = False
        self.stats['attacks_stopped'] += 1
        
        logging.info(f"Attack stopped: {attack_id}")
        print(f"[ATTACK-SIM] 🛑 Attack stopped: {attack_id}")
        
        return True
    
    # ========================
    # STOP ALL ATTACKS
    # ========================
    
    def stop_all_attacks(self) -> int:
        """
        Stops all active attacks.
        
        Returns:
            Number of attacks stopped
        """
        
        count = 0
        
        for attack_id in list(self.active_attacks.keys()):
            if self.active_attacks[attack_id]['running']:
                self.stop_attack(attack_id)
                count += 1
        
        print(f"[ATTACK-SIM] 🛑 All attacks stopped ({count} total)")
        
        return count
    
    # ========================
    # GET ACTIVE ATTACKS
    # ========================
    
    def get_active_attacks(self) -> List[Dict]:
        """Returns list of currently active attacks."""
        
        active = []
        
        for attack_id, info in self.active_attacks.items():
            if info['running']:
                active.append({
                    'id': attack_id,
                    'type': info['type'],
                    'target': info['target'],
                    'intensity': info['intensity'],
                    'start_time': info['start_time']
                })
        
        return active
    
    # ========================
    # GET ATTACK STATUS
    # ========================
    
    def get_attack_status(self, attack_id: str) -> Optional[Dict]:
        """Returns status of specific attack."""
        
        if attack_id not in self.active_attacks:
            return None
        
        info = self.active_attacks[attack_id]
        
        return {
            'id': attack_id,
            'type': info['type'],
            'target': info['target'],
            'intensity': info['intensity'],
            'running': info['running'],
            'start_time': info['start_time']
        }
    
    # ========================
    # GET PACKET QUEUE
    # ========================
    
    def get_packet_queue(self) -> Queue:
        """Returns the shared packet queue."""
        
        return self.packet_queue
    
    # ========================
    # GET STATISTICS
    # ========================
    
    def get_statistics(self) -> Dict:
        """Returns simulator statistics."""
        
        return {
            'total_packets_generated': self.stats['total_packets_generated'],
            'attacks_launched': self.stats['attacks_launched'],
            'attacks_stopped': self.stats['attacks_stopped'],
            'active_attacks': len([a for a in self.active_attacks.values() if a['running']]),
            'queue_size': self.packet_queue.qsize(),
            'botnet_size': len(self.botnet_ips),
            'timestamp': datetime.now().isoformat()
        }
    
    # ========================
    # REGENERATE BOTNET
    # ========================
    
    def regenerate_botnet(self, size: str = 'medium'):
        """Regenerates botnet IPs for fresh attack sources."""
        
        count = AttackConfig.BOTNET_SIZE.get(size, 50)
        self.botnet_ips = IPGenerator.random_botnet_ips(count)
        
        print(f"[ATTACK-SIM] 🔄 Botnet regenerated: {len(self.botnet_ips)} IPs")
    
    # ========================
    # QUICK ATTACK (FOR DEMO)
    # ========================
    
    def quick_attack(self, attack_type: str, duration: int = 10) -> str:
        """
        Launches quick attack for demo purposes.
        
        Args:
            attack_type: Type of attack
            duration: Duration in seconds
        
        Returns:
            Attack ID
        """
        
        return self.start_attack(
            attack_type=attack_type,
            intensity='high',
            duration=duration
        )
    
    # ========================
    # SCENARIO: MULTI-VECTOR
    # ========================
    
    def launch_multi_vector_attack(self, target: str = None, duration: int = 30) -> List[str]:
        """
        Launches coordinated multi-vector attack.
        Combines multiple attack types simultaneously.
        
        Args:
            target: Target IP
            duration: Duration in seconds
        
        Returns:
            List of attack IDs
        """
        
        target = target or AttackConfig.DEFAULT_TARGET
        attack_ids = []
        
        attacks = ['ddos', 'syn_flood', 'port_scan']
        
        print(f"[ATTACK-SIM] ⚔️ Launching MULTI-VECTOR attack on {target}")
        
        for attack_type in attacks:
            attack_id = self.start_attack(
                attack_type=attack_type,
                target=target,
                intensity='high',
                duration=duration
            )
            if attack_id:
                attack_ids.append(attack_id)
            time.sleep(0.5)
        
        return attack_ids
    
    # ========================
    # GENERATE NORMAL TRAFFIC
    # ========================
    
    def generate_normal_traffic(self, duration: int = 10, pps: int = 5):
        """
        Generates normal (non-malicious) traffic for contrast.
        
        Args:
            duration: Duration in seconds
            pps: Packets per second
        """
        
        print(f"[ATTACK-SIM] 🔵 Generating normal traffic for {duration}s")
        
        delay = 1.0 / pps
        end_time = time.time() + duration
        
        while time.time() < end_time:
            
            packet = SimulatedPacket(
                timestamp=self._get_timestamp(),
                source_ip=IPGenerator.random_internal_ip(),
                destination_ip=IPGenerator.random_public_ip(),
                source_port=random.randint(49152, 65535),
                destination_port=random.choice([80, 443]),
                protocol=Protocol.HTTP.value,
                size=random.randint(64, 1500),
                flags="ACK",
                attack_type="normal",
                is_malicious=False,
                severity="none",
                payload_preview="Normal HTTP traffic"
            )
            
            self.packet_queue.put(packet.to_dict())
            self.stats['total_packets_generated'] += 1
            
            time.sleep(delay)
        
        print("[ATTACK-SIM] 🔵 Normal traffic generation complete")


# ========================
# STANDALONE TEST MODE
# ========================

if __name__ == "__main__":
    
    print("=" * 60)
    print("    ATTACK SIMULATOR — CYBER DEFENSE GAME")
    print("=" * 60)
    print()
    print("⚠️  SIMULATION ONLY — No real attacks performed")
    print()
    
    # Create simulator
    simulator = AttackSimulator()
    print()
    
    # Menu
    while True:
        print("-" * 40)
        print("ATTACKS:")
        print("  1. DDoS Attack")
        print("  2. SYN Flood")
        print("  3. Port Scan")
        print("  4. Brute Force")
        print("  5. Ping Flood")
        print("  6. Slowloris")
        print("  7. DNS Amplification")
        print("  8. Multi-Vector Attack")
        print()
        print("CONTROL:")
        print("  9.  Stop specific attack")
        print("  10. Stop all attacks")
        print("  11. View active attacks")
        print("  12. View statistics")
        print("  13. Generate normal traffic")
        print("  14. View packet queue")
        print("  15. Regenerate botnet")
        print("  0.  Exit")
        print("-" * 40)
        
        choice = input("Choice: ").strip()
        
        # Attack commands
        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            attack_types = {
                '1': 'ddos',
                '2': 'syn_flood',
                '3': 'port_scan',
                '4': 'brute_force',
                '5': 'ping_flood',
                '6': 'slowloris',
                '7': 'dns_amplification'
            }
            
            target = input("Target IP (Enter for default): ").strip()
            target = target or AttackConfig.DEFAULT_TARGET
            
            intensity = input("Intensity (low/medium/high/extreme): ").strip()
            intensity = intensity or 'medium'
            
            duration = input("Duration seconds (Enter for unlimited): ").strip()
            duration = int(duration) if duration else None
            
            simulator.start_attack(
                attack_type=attack_types[choice],
                target=target,
                intensity=intensity,
                duration=duration
            )
        
        elif choice == '8':
            duration = input("Duration seconds (default 30): ").strip()
            duration = int(duration) if duration else 30
            simulator.launch_multi_vector_attack(duration=duration)
        
        elif choice == '9':
            attack_id = input("Attack ID to stop: ").strip()
            simulator.stop_attack(attack_id)
        
        elif choice == '10':
            simulator.stop_all_attacks()
        
        elif choice == '11':
            active = simulator.get_active_attacks()
            print(f"\nActive Attacks ({len(active)}):")
            if active:
                for a in active:
                    print(f"  🔴 {a['id']} | {a['type']} → {a['target']}")
            else:
                print("  None")
            print()
        
        elif choice == '12':
            stats = simulator.get_statistics()
            print(f"\n📊 Statistics:")
            print(f"  Total Packets    : {stats['total_packets_generated']}")
            print(f"  Attacks Launched : {stats['attacks_launched']}")
            print(f"  Attacks Stopped  : {stats['attacks_stopped']}")
            print(f"  Active Attacks   : {stats['active_attacks']}")
            print(f"  Queue Size       : {stats['queue_size']}")
            print(f"  Botnet Size      : {stats['botnet_size']}")
            print()
        
        elif choice == '13':
            duration = input("Duration seconds (default 10): ").strip()
            duration = int(duration) if duration else 10
            threading.Thread(
                target=simulator.generate_normal_traffic,
                args=(duration,),
                daemon=True
            ).start()
        
        elif choice == '14':
            queue = simulator.get_packet_queue()
            print(f"\nQueue Size: {queue.qsize()}")
            if not queue.empty():
                print("Latest packet preview:")
                pkt = queue.queue[0] if queue.queue else None
                if pkt:
                    print(f"  {pkt['src_ip']} → {pkt['dst_ip']} | {pkt['attack_type']}")
            print()
        
        elif choice == '15':
            size = input("Botnet size (small/medium/large): ").strip()
            size = size or 'medium'
            simulator.regenerate_botnet(size)
        
        elif choice == '0':
            simulator.stop_all_attacks()
            print("[ATTACK-SIM] Exiting...")
            break
        
        else:
            print("Invalid choice")
