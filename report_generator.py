"""
===========================================================
FILE: report_generator.py
PURPOSE: Generate TXT and PDF summary reports for game events
SYSTEM: Kali Linux
MEMBER: 4 (Logging & Reports)
===========================================================

WHAT THIS FILE DOES:
--------------------
1. Collects game statistics and events
2. Generates formatted TXT reports
3. Generates PDF reports
4. Creates summary of attacks, blocks, and defense actions
5. Saves reports with timestamps in reports/ folder

INTEGRATION:
------------
- Receives data from: logger.py, main.py
- Called at: End of game session

===========================================================
"""

# ========================
# IMPORTS
# ========================

import os
from datetime import datetime
from typing import Dict, List

# PDF library (optional)
try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ========================
# CONFIGURATION
# ========================

class ReportConfig:
    """Configuration for report generation."""
    
    REPORT_FOLDER = "reports"
    FILENAME_PREFIX = "cyber_defense_report"
    REPORT_TITLE = "Cyber Defense Simulation - Game Report"
    TEAM_NAME = "CSI Cyber Defenders"

# ========================
# REPORT DATA CLASS
# ========================

class ReportData:
    """Holds all data for report generation."""
    
    def __init__(self):
        """Initialize empty report data."""
        
        self.session_id = ""
        self.start_time = ""
        self.end_time = ""
        self.duration = ""
        
        self.total_packets = 0
        self.safe_packets = 0
        self.threat_packets = 0
        
        self.total_blocked = 0
        self.auto_blocked = 0
        self.manual_blocked = 0
        
        self.attacks_detected = 0
        self.attack_types = {}
        
        self.initial_health = 100
        self.final_health = 100
        self.damage_taken = 0
        
        self.blocked_ips = []
        self.events = []
        self.top_attackers = []

# ========================
# REPORT GENERATOR CLASS
# ========================

class ReportGenerator:
    """Generates TXT and PDF reports for game sessions."""
    
    def __init__(self, report_folder: str = None):
        """
        Initialize report generator.
        
        Args:
            report_folder: Folder to save reports
        """
        
        self.report_folder = report_folder or ReportConfig.REPORT_FOLDER
        self._create_folder()
        
        print("[REPORT] ✅ Report Generator initialized")
    
    # ========================
    # CREATE FOLDER
    # ========================
    
    def _create_folder(self):
        """Creates report folder if it doesn't exist."""
        
        try:
            if not os.path.exists(self.report_folder):
                os.makedirs(self.report_folder)
                print(f"[REPORT] 📁 Created folder: {self.report_folder}")
        except Exception as e:
            print(f"[REPORT] ⚠️ Could not create folder: {e}")
    
    # ========================
    # GENERATE FILENAME
    # ========================
    
    def _generate_filename(self, extension: str) -> str:
        """Generates unique filename with timestamp."""
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{ReportConfig.FILENAME_PREFIX}_{timestamp}.{extension}"
        
        return os.path.join(self.report_folder, filename)
    
    # ========================
    # GENERATE TXT REPORT
    # ========================
    
    def generate_txt_report(self, data: ReportData) -> str:
        """
        Generates a TXT format report.
        
        Args:
            data: ReportData object with game statistics
        
        Returns:
            Path to generated report file
        """
        
        filepath = self._generate_filename("txt")
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                
                # Header
                f.write("=" * 60 + "\n")
                f.write(f"  {ReportConfig.REPORT_TITLE}\n")
                f.write("=" * 60 + "\n\n")
                
                # Team info
                f.write(f"Team: {ReportConfig.TEAM_NAME}\n")
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Session info
                f.write("-" * 60 + "\n")
                f.write("  SESSION INFORMATION\n")
                f.write("-" * 60 + "\n")
                f.write(f"  Session ID    : {data.session_id}\n")
                f.write(f"  Start Time    : {data.start_time}\n")
                f.write(f"  End Time      : {data.end_time}\n")
                f.write(f"  Duration      : {data.duration}\n\n")
                
                # Packet statistics
                f.write("-" * 60 + "\n")
                f.write("  PACKET STATISTICS\n")
                f.write("-" * 60 + "\n")
                f.write(f"  Total Packets   : {data.total_packets}\n")
                f.write(f"  Safe Packets    : {data.safe_packets}\n")
                f.write(f"  Threat Packets  : {data.threat_packets}\n")
                
                if data.total_packets > 0:
                    threat_percent = (data.threat_packets / data.total_packets) * 100
                    f.write(f"  Threat Rate     : {threat_percent:.1f}%\n")
                f.write("\n")
                
                # Defense statistics
                f.write("-" * 60 + "\n")
                f.write("  DEFENSE STATISTICS\n")
                f.write("-" * 60 + "\n")
                f.write(f"  Total Blocked   : {data.total_blocked}\n")
                f.write(f"  Auto Blocked    : {data.auto_blocked}\n")
                f.write(f"  Manual Blocked  : {data.manual_blocked}\n\n")
                
                # Attack statistics
                f.write("-" * 60 + "\n")
                f.write("  ATTACK STATISTICS\n")
                f.write("-" * 60 + "\n")
                f.write(f"  Attacks Detected: {data.attacks_detected}\n\n")
                
                if data.attack_types:
                    f.write("  Attack Types:\n")
                    for attack_type, count in data.attack_types.items():
                        f.write(f"    - {attack_type}: {count}\n")
                    f.write("\n")
                
                # Health statistics
                f.write("-" * 60 + "\n")
                f.write("  HEALTH STATISTICS\n")
                f.write("-" * 60 + "\n")
                f.write(f"  Initial Health  : {data.initial_health}\n")
                f.write(f"  Final Health    : {data.final_health}\n")
                f.write(f"  Damage Taken    : {data.damage_taken}\n")
                
                if data.final_health > 0:
                    f.write("  Result          : SURVIVED ✓\n\n")
                else:
                    f.write("  Result          : DEFEATED ✗\n\n")
                
                # Blocked IPs
                if data.blocked_ips:
                    f.write("-" * 60 + "\n")
                    f.write("  BLOCKED IP ADDRESSES\n")
                    f.write("-" * 60 + "\n")
                    for ip in data.blocked_ips:
                        f.write(f"  • {ip}\n")
                    f.write("\n")
                
                # Top attackers
                if data.top_attackers:
                    f.write("-" * 60 + "\n")
                    f.write("  TOP ATTACKERS\n")
                    f.write("-" * 60 + "\n")
                    for i, attacker in enumerate(data.top_attackers[:5], 1):
                        ip = attacker.get('ip', 'Unknown')
                        count = attacker.get('count', 0)
                        f.write(f"  {i}. {ip} ({count} packets)\n")
                    f.write("\n")
                
                # Recent events
                if data.events:
                    f.write("-" * 60 + "\n")
                    f.write("  RECENT EVENTS (Last 20)\n")
                    f.write("-" * 60 + "\n")
                    for event in data.events[-20:]:
                        timestamp = event.get('timestamp', '')
                        event_type = event.get('type', '')
                        message = event.get('message', '')
                        f.write(f"  [{timestamp}] {event_type}: {message}\n")
                    f.write("\n")
                
                # Footer
                f.write("=" * 60 + "\n")
                f.write("  END OF REPORT\n")
                f.write("=" * 60 + "\n")
            
            print(f"[REPORT] 📄 TXT Report saved: {filepath}")
            return filepath
        
        except PermissionError:
            print(f"[REPORT] ❌ Permission denied: {filepath}")
            return ""
        
        except Exception as e:
            print(f"[REPORT] ❌ Error generating TXT report: {e}")
            return ""
    
    # ========================
    # GENERATE PDF REPORT
    # ========================
    
    def generate_pdf_report(self, data: ReportData) -> str:
        """
        Generates a PDF format report.
        
        Args:
            data: ReportData object with game statistics
        
        Returns:
            Path to generated report file
        """
        
        if not PDF_AVAILABLE:
            print("[REPORT] ⚠️ PDF library not installed")
            print("[REPORT] Install with: pip install fpdf")
            print("[REPORT] Generating TXT report instead...")
            return self.generate_txt_report(data)
        
        filepath = self._generate_filename("pdf")
        
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, ReportConfig.REPORT_TITLE, ln=True, align='C')
            pdf.ln(5)
            
            # Team and date
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Team: {ReportConfig.TEAM_NAME}", ln=True)
            pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.ln(5)
            
            # Session info
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "SESSION INFORMATION", ln=True)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Session ID: {data.session_id}", ln=True)
            pdf.cell(0, 6, f"Start Time: {data.start_time}", ln=True)
            pdf.cell(0, 6, f"End Time: {data.end_time}", ln=True)
            pdf.cell(0, 6, f"Duration: {data.duration}", ln=True)
            pdf.ln(5)
            
            # Packet stats
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "PACKET STATISTICS", ln=True)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Total Packets: {data.total_packets}", ln=True)
            pdf.cell(0, 6, f"Safe Packets: {data.safe_packets}", ln=True)
            pdf.cell(0, 6, f"Threat Packets: {data.threat_packets}", ln=True)
            pdf.ln(5)
            
            # Defense stats
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "DEFENSE STATISTICS", ln=True)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Total Blocked: {data.total_blocked}", ln=True)
            pdf.cell(0, 6, f"Auto Blocked: {data.auto_blocked}", ln=True)
            pdf.cell(0, 6, f"Manual Blocked: {data.manual_blocked}", ln=True)
            pdf.ln(5)
            
            # Attack stats
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "ATTACK STATISTICS", ln=True)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Attacks Detected: {data.attacks_detected}", ln=True)
            
            if data.attack_types:
                for attack_type, count in data.attack_types.items():
                    pdf.cell(0, 6, f"  - {attack_type}: {count}", ln=True)
            pdf.ln(5)
            
            # Health stats
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "HEALTH STATISTICS", ln=True)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Initial Health: {data.initial_health}", ln=True)
            pdf.cell(0, 6, f"Final Health: {data.final_health}", ln=True)
            pdf.cell(0, 6, f"Damage Taken: {data.damage_taken}", ln=True)
            
            result = "SURVIVED" if data.final_health > 0 else "DEFEATED"
            pdf.cell(0, 6, f"Result: {result}", ln=True)
            pdf.ln(5)
            
            # Blocked IPs
            if data.blocked_ips:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, "BLOCKED IP ADDRESSES", ln=True)
                pdf.set_font('Arial', '', 10)
                for ip in data.blocked_ips[:15]:
                    pdf.cell(0, 6, f"  - {ip}", ln=True)
            
            pdf.output(filepath)
            
            print(f"[REPORT] 📄 PDF Report saved: {filepath}")
            return filepath
        
        except Exception as e:
            print(f"[REPORT] ❌ Error generating PDF report: {e}")
            print("[REPORT] Generating TXT report instead...")
            return self.generate_txt_report(data)
    
    # ========================
    # GENERATE BOTH REPORTS
    # ========================
    
    def generate_all_reports(self, data: ReportData) -> Dict[str, str]:
        """Generates both TXT and PDF reports."""
        
        results = {}
        results['txt'] = self.generate_txt_report(data)
        results['pdf'] = self.generate_pdf_report(data)
        
        return results
    
    # ========================
    # QUICK REPORT
    # ========================
    
    def quick_report(self, total_packets: int, threats: int, blocked: int, health: int) -> str:
        """Generates a quick simple report."""
        
        data = ReportData()
        data.session_id = f"SESSION-{datetime.now().strftime('%H%M%S')}"
        data.start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data.end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data.duration = "Quick Report"
        data.total_packets = total_packets
        data.safe_packets = total_packets - threats
        data.threat_packets = threats
        data.total_blocked = blocked
        data.final_health = health
        data.damage_taken = 100 - health
        
        return self.generate_txt_report(data)
    
    # ========================
    # LIST REPORTS
    # ========================
    
    def list_reports(self) -> List[str]:
        """Lists all generated reports."""
        
        reports = []
        
        try:
            if os.path.exists(self.report_folder):
                for file in os.listdir(self.report_folder):
                    if file.endswith('.txt') or file.endswith('.pdf'):
                        reports.append(file)
        except Exception:
            pass
        
        return sorted(reports, reverse=True)
    
    # ========================
    # DELETE OLD REPORTS
    # ========================
    
    def delete_old_reports(self, keep_last: int = 10) -> int:
        """Deletes old reports, keeping only recent ones."""
        
        reports = self.list_reports()
        deleted = 0
        
        if len(reports) > keep_last:
            for report in reports[keep_last:]:
                try:
                    filepath = os.path.join(self.report_folder, report)
                    os.remove(filepath)
                    deleted += 1
                except Exception:
                    pass
        
        if deleted > 0:
            print(f"[REPORT] 🗑️ Deleted {deleted} old reports")
        
        return deleted
    
    # ========================
    # GET STATUS
    # ========================
    
    def get_status(self) -> Dict:
        """Returns report generator status."""
        
        return {
            'report_folder': self.report_folder,
            'pdf_available': PDF_AVAILABLE,
            'total_reports': len(self.list_reports())
        }

# ========================
# SAMPLE DATA FUNCTION
# ========================

def create_sample_data() -> ReportData:
    """Creates sample data for testing."""
    
    data = ReportData()
    
    data.session_id = f"TEST-{datetime.now().strftime('%H%M%S')}"
    data.start_time = "2025-01-15 10:00:00"
    data.end_time = "2025-01-15 10:15:00"
    data.duration = "15 minutes"
    
    data.total_packets = 1500
    data.safe_packets = 1200
    data.threat_packets = 300
    
    data.total_blocked = 25
    data.auto_blocked = 20
    data.manual_blocked = 5
    
    data.attacks_detected = 45
    data.attack_types = {
        'DDoS': 15,
        'SYN Flood': 12,
        'Port Scan': 10,
        'Brute Force': 8
    }
    
    data.initial_health = 100
    data.final_health = 65
    data.damage_taken = 35
    
    data.blocked_ips = [
        "45.33.32.156",
        "185.220.101.45",
        "171.25.193.20",
        "89.248.167.131",
        "45.155.205.233"
    ]
    
    data.top_attackers = [
        {'ip': '45.33.32.156', 'count': 150},
        {'ip': '185.220.101.45', 'count': 85},
        {'ip': '171.25.193.20', 'count': 45}
    ]
    
    data.events = [
        {'timestamp': '10:01:23', 'type': 'ATTACK', 'message': 'DDoS detected from 45.33.32.156'},
        {'timestamp': '10:01:25', 'type': 'BLOCK', 'message': 'Blocked IP 45.33.32.156'},
        {'timestamp': '10:05:12', 'type': 'ATTACK', 'message': 'SYN Flood from 185.220.101.45'},
        {'timestamp': '10:05:14', 'type': 'BLOCK', 'message': 'Blocked IP 185.220.101.45'},
        {'timestamp': '10:10:00', 'type': 'INFO', 'message': 'Auto-defense activated'}
    ]
    
    return data

# ========================
# STANDALONE TEST MODE
# ========================

if __name__ == "__main__":
    
    print("=" * 60)
    print("    REPORT GENERATOR — TEST MODE")
    print("=" * 60)
    print()
    
    if PDF_AVAILABLE:
        print("[INFO] ✅ PDF generation available")
    else:
        print("[INFO] ⚠️ PDF not available (install: pip install fpdf)")
    print()
    
    generator = ReportGenerator()
    print()
    
    while True:
        print("-" * 40)
        print("1. Generate TXT Report")
        print("2. Generate PDF Report")
        print("3. Generate Both Reports")
        print("4. Quick Report")
        print("5. List All Reports")
        print("6. Delete Old Reports")
        print("7. Show Status")
        print("8. Exit")
        print("-" * 40)
        
        choice = input("Choice: ").strip()
        
        if choice == '1':
            data = create_sample_data()
            generator.generate_txt_report(data)
        
        elif choice == '2':
            data = create_sample_data()
            generator.generate_pdf_report(data)
        
        elif choice == '3':
            data = create_sample_data()
            generator.generate_all_reports(data)
        
        elif choice == '4':
            print()
            packets = input("Total packets (default 100): ").strip()
            threats = input("Threats detected (default 20): ").strip()
            blocked = input("IPs blocked (default 5): ").strip()
            health = input("Final health (default 75): ").strip()
            
            generator.quick_report(
                int(packets) if packets else 100,
                int(threats) if threats else 20,
                int(blocked) if blocked else 5,
                int(health) if health else 75
            )
        
        elif choice == '5':
            reports = generator.list_reports()
            print(f"\n📁 Reports ({len(reports)}):")
            if reports:
                for report in reports:
                    print(f"  • {report}")
            else:
                print("  No reports found")
            print()
        
        elif choice == '6':
            generator.delete_old_reports(5)
        
        elif choice == '7':
            status = generator.get_status()
            print(f"\n📊 Status:")
            print(f"  Folder: {status['report_folder']}")
            print(f"  PDF Available: {status['pdf_available']}")
            print(f"  Total Reports: {status['total_reports']}\n")
        
        elif choice == '8':
            print("[REPORT] Exiting...")
            break
        
        else:
            print("Invalid choice")
