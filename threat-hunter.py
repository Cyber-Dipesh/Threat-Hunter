import re
import sys
import os
import requests
import json
import getpass
from datetime import datetime, timedelta # <--- Added timedelta
from collections import defaultdict

# ==========================================
# CONFIGURATION & SIGNATURES
# ==========================================
SEVERITY = {
    "HIGH": ["SQL Injection", "Web Shell", "XSS", "Path Traversal", "Brute Force", "Log Tampering"],
    "MEDIUM": ["User Enumeration", "Admin Scanning", "Brute Force (Web)"],
    "LOW": ["Vulnerability Scan", "Single Failure"]
}

WEB_ATTACK_SIGNATURES = {
    "SQL Injection": [r"UNION SELECT", r"' OR '1'='1", r"substring\(", r"load_file", r"--"],
    "XSS": [r"<script>", r"alert\(", r"%3Cscript%3E"],
    "Path Traversal": [r"\.\./", r"%2e%2e/", r"/etc/passwd", r"boot\.ini"],
    "Web Shell": [r"shell\.php", r"reverse_shell", r"cmd\.php", r"upload\.php"],
    "Admin Scanning": [r"wp-admin", r"wp-login", r"/admin/", r"phpmyadmin"]
}

# --- UPDATED THRESHOLDS ---
BRUTE_FORCE_THRESHOLD = 5
TIME_GAP_THRESHOLD = 60  # Time window in seconds (1 Minute)

# ==========================================
# HELPER: SAVE TO FILE
# ==========================================
def save_to_file(content):
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
        # UPDATED DATA STRUCTURE
        # 'fail_timestamps' is now a list to store datetime objects of every failure
        self.ip_activity = defaultdict(lambda: {
            'fail_timestamps': [], 
            'success': 0, 
            'web_401': 0, 'web_404': 0
        })

    def parse_logs(self):
        print(f"\n[*] Parsing file: {self.file_path}...")
        
        ssh_pattern = re.compile(r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}) \S+ (\S+): (.*)')
        web_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)')
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        try:
            with open(self.file_path, 'r', encoding="utf-8", errors='ignore') as f:
                for line in f:
                    web_match = web_pattern.search(line)
                    if web_match:
                        self._process_web_line(web_match)
                        continue

                    ssh_match = ssh_pattern.match(line)
                    if ssh_match:
                        self._process_ssh_line(ssh_match, ip_pattern)
                        continue

        except FileNotFoundError:
            print(f"[!] Error: File '{self.file_path}' not found.")
            return False
        return True

    def _process_web_line(self, match):
        ip, timestamp, request, status, size = match.groups()
        status = int(status)

        for attack_type, patterns in WEB_ATTACK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    severity = "HIGH"
                    if attack_type == "Web Shell" and status == 200:
                         description = f"SUCCESSFUL SHELL ACCESS: {request[:40]}..."
                    else:
                         description = f"Attempted {attack_type}"
                    self.register_event(ip, attack_type, severity, description)
                    break 

        if status == 401: self.ip_activity[ip]['web_401'] += 1
        elif status == 404: self.ip_activity[ip]['web_404'] += 1

    def _process_ssh_line(self, match, ip_pattern):
        timestamp_str, process, message = match.groups()
        
        # Parse timestamp (Syslog format: Oct 25 12:00:00)
        # Note: We assume current year because syslog doesn't provide year
        try:
            log_time = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            # Adjust to current year to allow comparison
            log_time = log_time.replace(year=datetime.now().year)
        except ValueError:
            return # Skip line if date parse fails

        ip_match = ip_pattern.search(message)
        if ip_match:
            ip = ip_match.group(1)
            
            if "Failed password" in message or "authentication failure" in message:
                # STORE TIMESTAMP OF FAILURE
                self.ip_activity[ip]['fail_timestamps'].append(log_time)
            
            elif "Accepted password" in message:
                # Check previous failures for this IP
                fails_count = len(self.ip_activity[ip]['fail_timestamps'])
                if fails_count > 2:
                    self.register_event(ip, "Success After Failure", "HIGH", f"Login success after {fails_count} fails")
                # Reset failures on success
                self.ip_activity[ip]['fail_timestamps'] = []

    def analyze_behavior(self):
        print("[*] Running heuristic analysis...")
        for ip, data in self.ip_activity.items():
            
            # --- NEW TIME WINDOW LOGIC ---
            timestamps = sorted(data['fail_timestamps'])
            is_brute_force = False
            
            # Check if we have enough failures to even consider brute force
            if len(timestamps) >= BRUTE_FORCE_THRESHOLD:
                # Sliding window check
                # Check every group of 5 failures
                for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
                    start_time = timestamps[i]
                    end_time = timestamps[i + BRUTE_FORCE_THRESHOLD - 1]
                    
                    # Calculate difference in seconds
                    time_diff = (end_time - start_time).total_seconds()
                    
                    # If 5th fail happened within 60 seconds of 1st fail
                    if time_diff <= TIME_GAP_THRESHOLD:
                        is_brute_force = True
                        break
            
            if is_brute_force:
                self.register_event(ip, "Brute Force (SSH)", "HIGH", f"{len(timestamps)} fails (Detected rapid burst)")
            
            # Web stats (Standard)
            if data['web_401'] >= 5:
                self.register_event(ip, "Brute Force (Web)", "MEDIUM", f"{data['web_401']} failed web logins")
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

        header = f"\n{'='*90}\n{'UNIFIED THREAT REPORT':^90}\n{'='*90}\n"
        header += f"{'SEVERITY':<10} | {'TYPE':<22} | {'TARGET':<16} | {'DETAILS'}\n"
        header += "-" * 90
        print(header)
        file_output = [header]
        
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_events = sorted(self.suspicious_events, key=lambda x: severity_order.get(x['Severity'], 3))

        for event in sorted_events:
            color = "\033[91m" if event['Severity'] == "HIGH" else "\033[93m" if event['Severity'] == "MEDIUM" else "\033[92m"
            reset = "\033[0m"
            print(f"{color}{event['Severity']:<10}{reset} | {event['Type']:<22} | {event['Target']:<16} | {event['Description']}")
            file_output.append(f"{event['Severity']:<10} | {event['Type']:<22} | {event['Target']:<16} | {event['Description']}")

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
            report_lines = []
            report_lines.append(f"{'='*50}")
            report_lines.append(f"REPORT FOR: {ip_address}")
            report_lines.append(f"{'='*50}")
            report_lines.append(f"Total Reports    : {data.get('totalReports', 'N/A')}")
            report_lines.append(f"Confidence Score : {data.get('abuseConfidenceScore', 0)}%")
            report_lines.append(f"ISP              : {data.get('isp', 'Unknown')}")
            report_lines.append(f"Country          : {data.get('countryCode', 'Unknown')}")
            report_lines.append(f"Last Reported    : {data.get('lastReportedAt', 'Never')}")
            print("\n" + "\n".join(report_lines))
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
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{'='*40}")
        print(f"{'CYBER THREAT HUNTER v8.0':^40}")
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
