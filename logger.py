"""
===========================================================
FILE: logger.py
PURPOSE: Save all game events with timestamps
SYSTEM: Kali Linux
MEMBER: 4 (Logging & Reports)
===========================================================

WHAT THIS FILE DOES:
--------------------
1. Records all game events with timestamps
2. Saves logs to files in logs/ folder
3. Supports different event types (ATTACK, BLOCK, INFO, etc.)
4. Provides methods for other modules to log events
5. Maintains session-based logging

INTEGRATION:
------------
- Used by: main.py, firewall.py, threat_intel.py, attack_simulator.py
- Feeds data to: report_generator.py

===========================================================
"""

# ========================
# IMPORTS
# ========================

import os
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum

# ========================
# EVENT TYPES
# ========================

class EventType(Enum):
    """Types of events that can be logged."""
    
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    ATTACK = "ATTACK"
    BLOCK = "BLOCK"
    UNBLOCK = "UNBLOCK"
    HEALTH = "HEALTH"
    DEFENSE = "DEFENSE"
    PACKET = "PACKET"
    GAME = "GAME"
    SYSTEM = "SYSTEM"

# ========================
# CONFIGURATION
# ========================

class LoggerConfig:
    """Configuration for logger."""
    
    LOG_FOLDER = "logs"
    FILENAME_PREFIX = "game_session"
    DATE_FORMAT = "%Y-%m-%d"
    TIME_FORMAT = "%H:%M:%S"
    DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    MAX_MEMORY_EVENTS = 1000

# ========================
# EVENT CLASS
# ========================

class Event:
    """Represents a single logged event."""
    
    def __init__(self, event_type: str, message: str, details: Dict = None):
        """
        Create a new event.
        
        Args:
            event_type: Type of event (ATTACK, BLOCK, etc.)
            message: Event message
            details: Additional details dictionary
        """
        
        self.timestamp = datetime.now().strftime(LoggerConfig.DATETIME_FORMAT)
        self.event_type = event_type
        self.message = message
        self.details = details or {}
    
    def to_string(self) -> str:
        """Convert event to log string."""
        
        return f"[{self.timestamp}] {self.event_type:8} | {self.message}"
    
    def to_dict(self) -> Dict:
        """Convert event to dictionary."""
        
        return {
            'timestamp': self.timestamp,
            'type': self.event_type,
            'message': self.message,
            'details': self.details
        }

# ========================
# GAME LOGGER CLASS
# ========================

class GameLogger:
    """
    Main logger for the cyber defense game.
    Records all events with timestamps.
    """
    
    def __init__(self, log_folder: str = None):
        """
        Initialize the game logger.
        
        Args:
            log_folder: Folder to save log files
        """
        
        self.log_folder = log_folder or LoggerConfig.LOG_FOLDER
        self.session_id = self._generate_session_id()
        self.log_file = None
        self.events = []
        self.event_counts = {}
        self.start_time = datetime.now()
        
        self._create_folder()
        self._create_log_file()
        
        self.log_info("Logger initialized")
        self.log_info(f"Session ID: {self.session_id}")
        
        print(f"[LOGGER] ✅ Initialized")
        print(f"[LOGGER] 📁 Log file: {self.log_file}")
    
    # ========================
    # SETUP METHODS
    # ========================
    
    def _generate_session_id(self) -> str:
        """Generates unique session ID."""
        
        return f"SESSION-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    def _create_folder(self):
        """Creates log folder if it doesn't exist."""
        
        try:
            if not os.path.exists(self.log_folder):
                os.makedirs(self.log_folder)
        except Exception as e:
            print(f"[LOGGER] ⚠️ Could not create folder: {e}")
    
    def _create_log_file(self):
        """Creates new log file for this session."""
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{LoggerConfig.FILENAME_PREFIX}_{timestamp}.log"
        self.log_file = os.path.join(self.log_folder, filename)
        
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("  CYBER DEFENSE GAME - SESSION LOG\n")
                f.write("=" * 60 + "\n")
                f.write(f"  Session ID: {self.session_id}\n")
                f.write(f"  Started: {datetime.now().strftime(LoggerConfig.DATETIME_FORMAT)}\n")
                f.write("=" * 60 + "\n\n")
        except Exception as e:
            print(f"[LOGGER] ⚠️ Could not create log file: {e}")
    
    # ========================
    # CORE LOG METHOD
    # ========================
    
    def log(self, event_type: str, message: str, details: Dict = None):
        """
        Log an event.
        
        Args:
            event_type: Type of event
            message: Event message
            details: Additional details
        """
        
        event = Event(event_type, message, details)
        
        # Store in memory
        self.events.append(event)
        
        # Limit memory usage
        if len(self.events) > LoggerConfig.MAX_MEMORY_EVENTS:
            self.events = self.events[-LoggerConfig.MAX_MEMORY_EVENTS:]
        
        # Count events
        if event_type not in self.event_counts:
            self.event_counts[event_type] = 0
        self.event_counts[event_type] += 1
        
        # Write to file
        self._write_to_file(event)
    
    def _write_to_file(self, event: Event):
        """Writes event to log file."""
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(event.to_string() + "\n")
        except Exception:
            pass
    
    # ========================
    # CONVENIENCE LOG METHODS
    # ========================
    
    def log_info(self, message: str, details: Dict = None):
        """Log INFO event."""
        self.log(EventType.INFO.value, message, details)
    
    def log_warning(self, message: str, details: Dict = None):
        """Log WARNING event."""
        self.log(EventType.WARNING.value, message, details)
    
    def log_error(self, message: str, details: Dict = None):
        """Log ERROR event."""
        self.log(EventType.ERROR.value, message, details)
    
    def log_attack(self, attack_type: str, source_ip: str, details: Dict = None):
        """Log ATTACK event."""
        message = f"{attack_type} detected from {source_ip}"
        self.log(EventType.ATTACK.value, message, details)
    
    def log_block(self, ip_address: str, reason: str = "", details: Dict = None):
        """Log BLOCK event."""
        message = f"Blocked IP {ip_address}"
        if reason:
            message += f" ({reason})"
        self.log(EventType.BLOCK.value, message, details)
    
    def log_unblock(self, ip_address: str, details: Dict = None):
        """Log UNBLOCK event."""
        message = f"Unblocked IP {ip_address}"
        self.log(EventType.UNBLOCK.value, message, details)
    
    def log_health(self, current_health: int, change: int = 0, details: Dict = None):
        """Log HEALTH event."""
        if change < 0:
            message = f"Health dropped to {current_health} ({change})"
        elif change > 0:
            message = f"Health restored to {current_health} (+{change})"
        else:
            message = f"Health: {current_health}"
        self.log(EventType.HEALTH.value, message, details)
    
    def log_defense(self, action: str, details: Dict = None):
        """Log DEFENSE event."""
        self.log(EventType.DEFENSE.value, action, details)
    
    def log_packet(self, source_ip: str, dest_ip: str, protocol: str, details: Dict = None):
        """Log PACKET event."""
        message = f"{source_ip} -> {dest_ip} [{protocol}]"
        self.log(EventType.PACKET.value, message, details)
    
    def log_game(self, action: str, details: Dict = None):
        """Log GAME event."""
        self.log(EventType.GAME.value, action, details)
    
    def log_system(self, message: str, details: Dict = None):
        """Log SYSTEM event."""
        self.log(EventType.SYSTEM.value, message, details)
    
    # ========================
    # GET EVENTS
    # ========================
    
    def get_events(self, event_type: str = None, limit: int = None) -> List[Dict]:
        """
        Get logged events.
        
        Args:
            event_type: Filter by event type (optional)
            limit: Maximum events to return (optional)
        
        Returns:
            List of event dictionaries
        """
        
        events = self.events
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if limit:
            events = events[-limit:]
        
        return [e.to_dict() for e in events]
    
    def get_recent_events(self, count: int = 20) -> List[Dict]:
        """Get most recent events."""
        
        return [e.to_dict() for e in self.events[-count:]]
    
    def get_attacks(self) -> List[Dict]:
        """Get all attack events."""
        
        return self.get_events(EventType.ATTACK.value)
    
    def get_blocks(self) -> List[Dict]:
        """Get all block events."""
        
        return self.get_events(EventType.BLOCK.value)
    
    # ========================
    # STATISTICS
    # ========================
    
    def get_statistics(self) -> Dict:
        """Get logging statistics."""
        
        duration = datetime.now() - self.start_time
        duration_seconds = int(duration.total_seconds())
        
        if duration_seconds < 60:
            duration_str = f"{duration_seconds} seconds"
        else:
            minutes = duration_seconds // 60
            seconds = duration_seconds % 60
            duration_str = f"{minutes}m {seconds}s"
        
        return {
            'session_id': self.session_id,
            'start_time': self.start_time.strftime(LoggerConfig.DATETIME_FORMAT),
            'duration': duration_str,
            'total_events': len(self.events),
            'event_counts': self.event_counts.copy(),
            'log_file': self.log_file
        }
    
    def get_summary(self) -> Dict:
        """Get session summary for report generation."""
        
        stats = self.get_statistics()
        
        return {
            'session_id': self.session_id,
            'start_time': self.start_time.strftime(LoggerConfig.DATETIME_FORMAT),
            'end_time': datetime.now().strftime(LoggerConfig.DATETIME_FORMAT),
            'duration': stats['duration'],
            'total_events': len(self.events),
            'attacks_detected': self.event_counts.get(EventType.ATTACK.value, 0),
            'ips_blocked': self.event_counts.get(EventType.BLOCK.value, 0),
            'events': self.get_recent_events(50)
        }
    
    # ========================
    # FILE OPERATIONS
    # ========================
    
    def read_log_file(self) -> str:
        """Reads current log file content."""
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"Error reading log file: {e}"
    
    def list_log_files(self) -> List[str]:
        """Lists all log files."""
        
        logs = []
        
        try:
            if os.path.exists(self.log_folder):
                for file in os.listdir(self.log_folder):
                    if file.endswith('.log'):
                        logs.append(file)
        except Exception:
            pass
        
        return sorted(logs, reverse=True)
    
    def delete_old_logs(self, keep_last: int = 10) -> int:
        """Deletes old log files."""
        
        logs = self.list_log_files()
        deleted = 0
        
        if len(logs) > keep_last:
            for log in logs[keep_last:]:
                try:
                    filepath = os.path.join(self.log_folder, log)
                    os.remove(filepath)
                    deleted += 1
                except Exception:
                    pass
        
        if deleted > 0:
            self.log_info(f"Deleted {deleted} old log files")
        
        return deleted
    
    # ========================
    # SESSION MANAGEMENT
    # ========================
    
    def end_session(self):
        """Ends the logging session."""
        
        self.log_info("Session ended")
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write("\n" + "=" * 60 + "\n")
                f.write("  SESSION ENDED\n")
                f.write(f"  End Time: {datetime.now().strftime(LoggerConfig.DATETIME_FORMAT)}\n")
                f.write(f"  Total Events: {len(self.events)}\n")
                f.write("=" * 60 + "\n")
        except Exception:
            pass
        
        print(f"[LOGGER] ✅ Session ended")
    
    def clear_memory(self):
        """Clears events from memory (file remains)."""
        
        self.events = []
        self.event_counts = {}
        self.log_info("Memory cleared")

# ========================
# GLOBAL LOGGER INSTANCE
# ========================

_global_logger = None

def get_logger() -> GameLogger:
    """Gets or creates global logger instance."""
    
    global _global_logger
    
    if _global_logger is None:
        _global_logger = GameLogger()
    
    return _global_logger

def log_event(event_type: str, message: str, details: Dict = None):
    """Quick function to log events using global logger."""
    
    logger = get_logger()
    logger.log(event_type, message, details)

# ========================
# STANDALONE TEST MODE
# ========================

if __name__ == "__main__":
    
    print("=" * 60)
    print("    GAME LOGGER — TEST MODE")
    print("=" * 60)
    print()
    
    logger = GameLogger()
    print()
    
    while True:
        print("-" * 40)
        print("1. Log INFO event")
        print("2. Log ATTACK event")
        print("3. Log BLOCK event")
        print("4. Log HEALTH event")
        print("5. Log DEFENSE event")
        print("6. View recent events")
        print("7. View statistics")
        print("8. View log file")
        print("9. List all log files")
        print("10. Run demo (multiple events)")
        print("11. End session and exit")
        print("-" * 40)
        
        choice = input("Choice: ").strip()
        
        if choice == '1':
            message = input("Message: ").strip()
            logger.log_info(message or "Test info message")
            print("✅ Logged\n")
        
        elif choice == '2':
            attack = input("Attack type (default DDoS): ").strip()
            ip = input("Source IP (default 45.33.32.156): ").strip()
            logger.log_attack(
                attack or "DDoS",
                ip or "45.33.32.156"
            )
            print("✅ Logged\n")
        
        elif choice == '3':
            ip = input("IP to block (default 45.33.32.156): ").strip()
            reason = input("Reason (default threat): ").strip()
            logger.log_block(
                ip or "45.33.32.156",
                reason or "threat"
            )
            print("✅ Logged\n")
        
        elif choice == '4':
            health = input("Current health (default 85): ").strip()
            change = input("Change amount (default -15): ").strip()
            logger.log_health(
                int(health) if health else 85,
                int(change) if change else -15
            )
            print("✅ Logged\n")
        
        elif choice == '5':
            action = input("Defense action (default Auto-defense activated): ").strip()
            logger.log_defense(action or "Auto-defense activated")
            print("✅ Logged\n")
        
        elif choice == '6':
            events = logger.get_recent_events(10)
            print(f"\n📋 Recent Events ({len(events)}):")
            for event in events:
                print(f"  [{event['timestamp']}] {event['type']}: {event['message']}")
            print()
        
        elif choice == '7':
            stats = logger.get_statistics()
            print(f"\n📊 Statistics:")
            print(f"  Session ID: {stats['session_id']}")
            print(f"  Started: {stats['start_time']}")
            print(f"  Duration: {stats['duration']}")
            print(f"  Total Events: {stats['total_events']}")
            print(f"  Event Counts:")
            for event_type, count in stats['event_counts'].items():
                print(f"    - {event_type}: {count}")
            print()
        
        elif choice == '8':
            print(f"\n📄 Log File Content:\n")
            print(logger.read_log_file())
        
        elif choice == '9':
            logs = logger.list_log_files()
            print(f"\n📁 Log Files ({len(logs)}):")
            for log in logs:
                print(f"  • {log}")
            print()
        
        elif choice == '10':
            print("\n🎮 Running demo...\n")
            
            logger.log_game("Game started")
            logger.log_info("Player ready")
            
            logger.log_attack("DDoS", "45.33.32.156")
            logger.log_attack("SYN Flood", "185.220.101.45")
            logger.log_attack("Port Scan", "171.25.193.20")
            
            logger.log_health(100, 0)
            logger.log_health(85, -15)
            logger.log_health(70, -15)
            
            logger.log_block("45.33.32.156", "DDoS attack")
            logger.log_block("185.220.101.45", "SYN Flood")
            
            logger.log_defense("Auto-defense activated")
            logger.log_defense("Firewall rules updated")
            
            logger.log_block("171.25.193.20", "Auto-blocked")
            
            logger.log_health(75, 5)
            logger.log_info("Attack wave ended")
            logger.log_game("Wave 1 complete")
            
            print("✅ Demo complete - 15 events logged\n")
        
        elif choice == '11':
            logger.end_session()
            print("Exiting...")
            break
        
        else:
            print("Invalid choice\n")
