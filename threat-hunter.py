import re
import sys
import os
import requests
import json
import getpass
from datetime import datetime
from collections import defaultdict

# ==========================================
# CONFIGURATION & SIGNATURES
# ==========================================
SEVERITY = {
    "HIGH": ["SQL Injection", "Web Shell", "XSS", "Path Traversal", "Brute Force", "Log Tampering"],
    "MEDIUM": ["User Enumeration", "Admin Scanning", "Brute Force (Web)"],
    "LOW": ["Vulnerability Scan", "Single Failure"]
}

# WEB ATTACK PATTERNS
WEB_ATTACK_SIGNATURES = {
    "SQL Injection": [r"UNION SELECT", r"' OR '1'='1", r"substring\(", r"load_file", r"--"],
    "XSS": [r"<script>", r"alert\(", r"%3Cscript%3E"],
    "Path Traversal": [r"\.\./", r"%2e%2e/", r"/etc/passwd", r"boot\.ini"],
    "Web Shell": [r"shell\.php", r"reverse_shell", r"cmd\.php", r"upload\.php"],
    "Admin Scanning": [r"wp-admin", r"wp-login", r"/admin/", r"phpmyadmin"]
}

# THRESHOLDS
BRUTE_FORCE_THRESHOLD = 5
TIME_GAP_THRESHOLD = 3600

# ==========================================
# HELPER: SAVE TO FILE
# ==========================================
def save_to_file(content):
    """Asks user to save the report to a text file."""
    choice = input("\n[?] Save this report to 'threat_reports.txt'? (y/N): ").strip().lower()
    if choice == 'y':
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("threat_reports.txt", "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"REPORT TIMESTAMP: {timestamp}\n")
                f.write(f"{'='*60}\n")
                f.write(content)
                f.write(f"\n{'='*60}\n\n")
            print(f"[+] Report saved to threat_reports.txt")
        except Exception as e:
            print(f"[!] Error saving file: {e}")

# ==========================================
# CLASS: UNIVERSAL LOG ANALYZER
# ==========================================
class LogAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.suspicious_events = []
        # General stats
        self.ip_activity = defaultdict(lambda: {
            'fails': 0, 'success': 0, 'users': set(), 
            'web_401': 0, 'web_404': 0, 'web_200': 0
        })

    def parse_logs(self):
        print(f"\n[*] Parsing file: {self.file_path}...")
        
        # PATTERNS
        ssh_pattern = re.compile(r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}) \S+ (\S+): (.*)')
        web_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)')
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        try:
            with open(self.file_path, 'r', encoding="utf-8", errors='ignore') as f:
                for line in f:
                    # --- TRY WEB LOG FORMAT FIRST ---
                    web_match = web_pattern.search(line)
                    if web_match:
                        self._process_web_line(web_match)
                        continue

                    # --- TRY SSH LOG FORMAT SECOND ---
                    ssh_match = ssh_pattern.match(line)
                    if ssh_match:
                        self._process_ssh_line(ssh_match, ip_pattern)
                        continue

        except FileNotFoundError:
            print(f"[!] Error: File '{self.file_path}' not found.")
            return False
        return True

    def _process_web_line(self, match):
        """Handle Apache/Nginx Logs"""
        ip, timestamp, request, status, size = match.groups()
        status = int(status)

        # 1. Check Signatures (SQLi, XSS, etc.)
        for attack_type, patterns in WEB_ATTACK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    # Severity check: Web Shells with 200 OK are Critical
                    severity = "HIGH"
                    if attack_type == "Web Shell" and status == 200:
                         description = f"SUCCESSFUL SHELL ACCESS: {request[:40]}..."
                    else:
                         description = f"Attempted {attack_type}"
                    
                    self.register_event(ip, attack_type, severity, description)
                    break # Stop checking other patterns for this line

        # 2. Track Stats
        if status == 401: self.ip_activity[ip]['web_401'] += 1
        elif status == 404: self.ip_activity[ip]['web_404'] += 1

    def _process_ssh_line(self, match, ip_pattern):
        """Handle Linux System Logs"""
        timestamp_str, process, message = match.groups()
        
        # Extract IP
        ip_match = ip_pattern.search(message)
        if ip_match:
            ip = ip_match.group(1)
            
            if "Failed password" in message or "authentication failure" in message:
                self.ip_activity[ip]['fails'] += 1
            elif "Accepted password" in message:
                if self.ip_activity[ip]['fails'] > 2:
                    self.register_event(ip, "Success After Failure", "HIGH", f"Login success after {self.ip_activity[ip]['fails']} fails")
                self.ip_activity[ip]['fails'] = 0

    def analyze_behavior(self):
        print("[*] Running heuristic analysis...")
        for ip, data in self.ip_activity.items():
            # SSH Brute Force
            if data['fails'] >= BRUTE_FORCE_THRESHOLD:
                self.register_event(ip, "Brute Force (SSH)", "HIGH", f"{data['fails']} failed system logins")
            
            # Web Brute Force
            if data['web_401'] >= 5:
                self.register_event(ip, "Brute Force (Web)", "MEDIUM", f"{data['web_401']} failed web logins")
            
            # Web Scanning
            if data['web_404'] >= 5:
                self.register_event(ip, "Vulnerability Scan", "LOW", f"{data['web_404']} missing pages accessed")

    def register_event(self, target, attack_type, default_severity, description):
        self.suspicious_events.append({
            "Target": target, "Type": attack_type, "Severity": default_severity, "Description": description
        })

    def print_report(self):
        if not self.suspicious_events:
            print("\n[+] No threats detected.")
            return

        # Prepare header
        header = f"\n{'='*90}\n{'UNIFIED THREAT REPORT':^90}\n{'='*90}\n"
        header += f"{'SEVERITY':<10} | {'TYPE':<22} | {'TARGET':<16} | {'DETAILS'}\n"
        header += "-" * 90
        
        print(header)

        # Prepare list for file saving (clean text)
        file_output = [header]
        
        # Sort HIGH -> MEDIUM -> LOW
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_events = sorted(self.suspicious_events, key=lambda x: severity_order.get(x['Severity'], 3))

        for event in sorted_events:
            # Color logic for Terminal
            color = "\033[91m" if event['Severity'] == "HIGH" else "\033[93m" if event['Severity'] == "MEDIUM" else "\033[92m"
            reset = "\033[0m"
            
            # Print to Terminal (With Color)
            print(f"{color}{event['Severity']:<10}{reset} | {event['Type']:<22} | {event['Target']:<16} | {event['Description']}")
            
            # Save to Memory (Without Color)
            file_output.append(f"{event['Severity']:<10} | {event['Type']:<22} | {event['Target']:<16} | {event['Description']}")

        # Trigger Save Prompt
        save_to_file("\n".join(file_output))


# ==========================================
# THREAT INTEL MODULE
# ==========================================
def get_api_key():
    key = os.getenv("ABUSE_IPDB_KEY")
    if not key:
        print("\n[!] API Key not found in environment variables.")
        key = getpass.getpass("[?] Enter your AbuseIPDB API Key (Hidden): ").strip()
    return key

def check_ip_reputation(ip_address, api_key):
    print(f"\n[*] Querying AbuseIPDB for {ip_address}...")
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            
            # Build the report string
            report_lines = []
            report_lines.append(f"{'='*50}")
            report_lines.append(f"REPORT FOR: {ip_address}")
            report_lines.append(f"{'='*50}")
            report_lines.append(f"Total Reports    : {data.get('totalReports', 'N/A')}")
            report_lines.append(f"Confidence Score : {data.get('abuseConfidenceScore', 0)}%")
            report_lines.append(f"ISP              : {data.get('isp', 'Unknown')}")
            report_lines.append(f"Country          : {data.get('countryCode', 'Unknown')}")
            report_lines.append(f"Last Reported    : {data.get('lastReportedAt', 'Never')}")
            
            # Print to screen
            print("\n" + "\n".join(report_lines))
            
            # Trigger Save Prompt
            save_to_file("\n".join(report_lines))
            
        elif response.status_code == 401:
            print("[!] Error: Invalid API Key.")
        else:
            print(f"[!] API Error: {response.status_code}")
    except Exception as e:
        print(f"[!] Connection Error: {e}")

# ==========================================
# MENUS
# ==========================================
def main_menu():
    while True:
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(f"{'='*40}")
        print(f"{'CYBER THREAT HUNTER v7.0':^40}")
        print(f"{'='*40}")
        print("1. Analyze Log File (SSH or Web)")
        print("2. Check IP Reputation (AbuseIPDB)")
        print("3. Exit")
        print("-" * 40)
        
        choice = input("Select Option: ").strip()
        
        if choice == '1':
            while True:
                print("\n--- LOG ANALYSIS MODE ---")
                fpath = input("Enter log file path (or 'b' for back): ").strip()
                if fpath.lower() == 'b': break
                
                analyzer = LogAnalyzer(fpath)
                if analyzer.parse_logs():
                    analyzer.analyze_behavior()
                    analyzer.print_report()
                input("\n[Press Enter to continue...]")

        elif choice == '2':
            while True:
                print("\n--- THREAT INTEL MODE ---")
                ip = input("Enter IP Address (or 'b' for back): ").strip()
                if ip.lower() == 'b': break
                
                key = get_api_key()
                if key: check_ip_reputation(ip, key)
                input("\n[Press Enter to continue...]")

        elif choice == '3':
            print("Exiting...")
            sys.exit()
        else:
            input("[!] Invalid option.")

if __name__ == "__main__":
    main_menu()
