"""
===========================================================
FILE: firewall.py
PURPOSE: Control iptables firewall — block and unblock IPs
SYSTEM: Kali Linux
MEMBER: 3 (Defense System)
===========================================================
"""

# ========================
# IMPORTS
# ========================

import subprocess
import logging
from datetime import datetime
from typing import Optional

# ========================
# LOGGING SETUP
# ========================

logging.basicConfig(
    filename='firewall_log.txt',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ========================
# FIREWALL CONTROLLER CLASS
# ========================

class FirewallController:
    """
    Controls iptables firewall on Kali Linux.
    Blocks and unblocks IP addresses in real-time.
    """
    
    def __init__(self):
        """
        Initialize firewall controller.
        Checks for root privileges.
        """
        
        # Store blocked IPs (set = no duplicates, fast lookup)
        self.blocked_ips = set()
        
        # Check if running as root
        self._check_root()
        
        # Log startup
        logging.info("FirewallController initialized")
        print("[FIREWALL] ✅ Initialized")
    
    # ========================
    # ROOT CHECK
    # ========================
    
    def _check_root(self) -> bool:
        """
        Verifies script is running with root privileges.
        iptables requires root access.
        """
        
        import os
        
        if os.geteuid() != 0:
            print("[FIREWALL] ⚠️  WARNING: Not running as root!")
            print("[FIREWALL] Run with: sudo python3 firewall.py")
            logging.warning("Not running as root")
            return False
        
        return True
    
    # ========================
    # VALIDATE IP ADDRESS
    # ========================
    
    def _validate_ip(self, ip_address: str) -> bool:
        """
        Validates IP address format.
        
        Args:
            ip_address: IP to validate
        
        Returns:
            True if valid, False if invalid
        """
        
        parts = ip_address.split('.')
        
        # Must have 4 parts
        if len(parts) != 4:
            return False
        
        # Each part must be 0-255
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True
    
    # ========================
    # EXECUTE IPTABLES COMMAND
    # ========================
    
    def _run_iptables(self, args: list) -> tuple:
        """
        Executes iptables command.
        
        Args:
            args: List of iptables arguments
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        
        command = ['iptables'] + args
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return (True, "Success")
            else:
                return (False, result.stderr.strip())
        
        except subprocess.TimeoutExpired:
            return (False, "Command timed out")
        
        except PermissionError:
            return (False, "Permission denied - run as root")
        
        except FileNotFoundError:
            return (False, "iptables not found")
        
        except Exception as e:
            return (False, str(e))
    
    # ========================
    # BLOCK IP
    # ========================
    
    def block_ip(self, ip_address: str) -> bool:
        """
        Blocks an IP address using iptables.
        
        Args:
            ip_address: The IP to block
        
        Returns:
            True if blocked successfully
        """
        
        # Step 1: Validate IP
        if not self._validate_ip(ip_address):
            print(f"[FIREWALL] ❌ Invalid IP: {ip_address}")
            logging.error(f"Invalid IP format: {ip_address}")
            return False
        
        # Step 2: Check if already blocked
        if ip_address in self.blocked_ips:
            print(f"[FIREWALL] ⚠️  Already blocked: {ip_address}")
            return True
        
        # Step 3: Block incoming traffic from IP
        # -A INPUT: Append to INPUT chain
        # -s: Source IP
        # -j DROP: Drop the packet
        success, message = self._run_iptables([
            '-A', 'INPUT',
            '-s', ip_address,
            '-j', 'DROP'
        ])
        
        if not success:
            print(f"[FIREWALL] ❌ Block failed: {message}")
            logging.error(f"Block failed for {ip_address}: {message}")
            return False
        
        # Step 4: Block outgoing traffic to IP
        # -A OUTPUT: Append to OUTPUT chain
        # -d: Destination IP
        success_out, message_out = self._run_iptables([
            '-A', 'OUTPUT',
            '-d', ip_address,
            '-j', 'DROP'
        ])
        
        if not success_out:
            print(f"[FIREWALL] ⚠️  Outbound block failed: {message_out}")
            logging.warning(f"Outbound block failed for {ip_address}")
        
        # Step 5: Add to blocked set
        self.blocked_ips.add(ip_address)
        
        # Step 6: Log and confirm
        logging.info(f"BLOCKED: {ip_address}")
        print(f"[FIREWALL] 🛡️  BLOCKED: {ip_address}")
        
        return True
    
    # ========================
    # UNBLOCK IP
    # ========================
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Removes firewall block on an IP address.
        
        Args:
            ip_address: The IP to unblock
        
        Returns:
            True if unblocked successfully
        """
        
        # Step 1: Validate IP
        if not self._validate_ip(ip_address):
            print(f"[FIREWALL] ❌ Invalid IP: {ip_address}")
            return False
        
        # Step 2: Check if actually blocked
        if ip_address not in self.blocked_ips:
            print(f"[FIREWALL] ⚠️  Not in blocked list: {ip_address}")
            return True
        
        # Step 3: Remove INPUT rule
        # -D: Delete rule
        success, message = self._run_iptables([
            '-D', 'INPUT',
            '-s', ip_address,
            '-j', 'DROP'
        ])
        
        # Step 4: Remove OUTPUT rule
        self._run_iptables([
            '-D', 'OUTPUT',
            '-d', ip_address,
            '-j', 'DROP'
        ])
        
        # Step 5: Remove from blocked set
        self.blocked_ips.discard(ip_address)
        
        # Step 6: Log and confirm
        logging.info(f"UNBLOCKED: {ip_address}")
        print(f"[FIREWALL] ✅ UNBLOCKED: {ip_address}")
        
        return True
    
    # ========================
    # BLOCK MULTIPLE IPs
    # ========================
    
    def block_multiple(self, ip_list: list) -> dict:
        """
        Blocks multiple IPs at once.
        
        Args:
            ip_list: List of IPs to block
        
        Returns:
            Dict with success and failure counts
        """
        
        results = {'success': 0, 'failed': 0, 'failed_ips': []}
        
        for ip in ip_list:
            if self.block_ip(ip):
                results['success'] += 1
            else:
                results['failed'] += 1
                results['failed_ips'].append(ip)
        
        print(f"[FIREWALL] Blocked {results['success']}/{len(ip_list)} IPs")
        logging.info(f"Bulk block: {results['success']} success, {results['failed']} failed")
        
        return results
    
    # ========================
    # AUTO DEFENSE MODE
    # ========================
    
    def auto_defense(self, ip_address: str, threat_level: str) -> bool:
        """
        Automatically blocks based on threat level.
        Called by game when threat detected.
        
        Args:
            ip_address: The suspicious IP
            threat_level: 'low', 'medium', 'high', 'critical'
        
        Returns:
            True if action taken
        """
        
        # Define actions for each threat level
        actions = {
            'low': False,       # Monitor only
            'medium': False,    # Alert only
            'high': True,       # Block
            'critical': True    # Block immediately
        }
        
        should_block = actions.get(threat_level, False)
        
        if should_block:
            logging.info(f"AUTO-DEFENSE triggered for {ip_address} ({threat_level})")
            print(f"[AUTO-DEFENSE] 🚨 {threat_level.upper()} threat: {ip_address}")
            return self.block_ip(ip_address)
        
        else:
            print(f"[AUTO-DEFENSE] 👁️  Monitoring: {ip_address} ({threat_level})")
            logging.info(f"Monitoring {ip_address} ({threat_level})")
            return False
    
    # ========================
    # GET BLOCKED IPs
    # ========================
    
    def get_blocked_ips(self) -> list:
        """
        Returns list of all blocked IPs.
        Used by UI to display blocked list.
        """
        
        return list(self.blocked_ips)
    
    # ========================
    # GET STATUS
    # ========================
    
    def get_status(self) -> dict:
        """
        Returns current firewall status.
        Used by UI for stats display.
        """
        
        return {
            'active': True,
            'total_blocked': len(self.blocked_ips),
            'blocked_ips': list(self.blocked_ips),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    # ========================
    # CLEAR ALL BLOCKS
    # ========================
    
    def clear_all_blocks(self) -> bool:
        """
        Removes all firewall blocks created by this program.
        Used for demo reset.
        """
        
        print("[FIREWALL] 🔄 Clearing all blocks...")
        
        # Copy set to avoid modification during iteration
        ips_to_clear = list(self.blocked_ips)
        
        for ip in ips_to_clear:
            self.unblock_ip(ip)
        
        logging.info("All blocks cleared")
        print("[FIREWALL] ✅ All blocks cleared")
        
        return True
    
    # ========================
    # FLUSH ALL RULES (DANGER)
    # ========================
    
    def flush_all_rules(self) -> bool:
        """
        Flushes ALL iptables rules.
        ⚠️ USE WITH CAUTION - removes all firewall rules.
        """
        
        print("[FIREWALL] ⚠️  Flushing ALL iptables rules...")
        
        # Flush INPUT chain
        self._run_iptables(['-F', 'INPUT'])
        
        # Flush OUTPUT chain
        self._run_iptables(['-F', 'OUTPUT'])
        
        # Clear blocked set
        self.blocked_ips.clear()
        
        logging.warning("All iptables rules flushed")
        print("[FIREWALL] ✅ All rules flushed")
        
        return True
    
    # ========================
    # SHOW CURRENT RULES
    # ========================
    
    def show_rules(self) -> str:
        """
        Shows current iptables rules.
        Useful for debugging.
        """
        
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n', '--line-numbers'],
                capture_output=True,
                text=True
            )
            return result.stdout
        
        except Exception as e:
            return f"Error: {e}"


# ========================
# STANDALONE TEST MODE
# ========================

if __name__ == "__main__":
    
    print("=" * 50)
    print("    FIREWALL CONTROLLER — KALI LINUX")
    print("=" * 50)
    print()
    
    # Create controller
    fw = FirewallController()
    print()
    
    # Menu
    while True:
        print("-" * 30)
        print("1. Block IP")
        print("2. Unblock IP")
        print("3. Show blocked IPs")
        print("4. Show iptables rules")
        print("5. Clear all blocks")
        print("6. Test auto-defense")
        print("7. Exit")
        print("-" * 30)
        
        choice = input("Choice: ").strip()
        
        if choice == '1':
            ip = input("IP to block: ").strip()
            fw.block_ip(ip)
        
        elif choice == '2':
            ip = input("IP to unblock: ").strip()
            fw.unblock_ip(ip)
        
        elif choice == '3':
            status = fw.get_status()
            print(f"\nBlocked IPs ({status['total_blocked']}):")
            if status['blocked_ips']:
                for ip in status['blocked_ips']:
                    print(f"  🛡️  {ip}")
            else:
                print("  None")
            print()
        
        elif choice == '4':
            print("\nCurrent iptables rules:")
            print(fw.show_rules())
        
        elif choice == '5':
            confirm = input("Clear all? (y/n): ").strip().lower()
            if confirm == 'y':
                fw.clear_all_blocks()
        
        elif choice == '6':
            ip = input("Test IP: ").strip()
            level = input("Threat level (low/medium/high/critical): ").strip()
            fw.auto_defense(ip, level)
        
        elif choice == '7':
            print("[FIREWALL] Exiting...")
            break
        
        else:
            print("Invalid choice")
