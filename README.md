# Threat-Hunter
A Python-based automated threat hunting tool to analyze server logs and detect OWASP Top 10 attacks (SQLi, XSS, Webshells) and Brute Force attempts. Integrates with AbuseIPDB for real-time threat intelligence and malicious IP identification.

# 🛡️ Threat Hunter: Automated Log Analysis & Intelligence Tool

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-SIEM-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 📌 Tool Overview
**Threat Hunter** is a command-line Python tool designed to automate the detection of security incidents in server logs. It acts as a lightweight **SIEM (Security Information and Event Management)** solution by parsing raw logs, detecting attack patterns (OWASP Top 10), and enriching IP addresses with real-time threat intelligence.

This tool bridges the gap between **IT Operations** and **Security Analysis**, allowing for rapid triage of Brute Force attacks, SQL Injections, and Web Shell uploads.

## 🚀 Key Features
* **Universal Log Parsing:** Automatically detects and parses both **Linux SSH Logs** (`auth.log`) and **Web Server Logs** (Apache/Nginx).
* **Attack Signature Engine:** Uses Regex to detect known attack patterns:
    * SQL Injection (SQLi)
    * Cross-Site Scripting (XSS)
    * Path Traversal (LFI)
    * Web Shell Uploads
* **Behavioral Analysis:** Identifies anomalies such as "Success after Failure" (potential breach) and Time Gaps (potential log tampering).
* **Threat Intelligence Integration:** Connects to the **AbuseIPDB API** to check the reputation score, ISP, and Country of suspicious IPs.
* **Severity Scoring:** Prioritizes alerts (HIGH/MEDIUM/LOW) to help analysts focus on critical threats first.

## 🛠️ Installation & Usage

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/Threat-Hunter-Tool.git](https://github.com/YOUR_USERNAME/Threat-Hunter-Tool.git)
cd Threat-Hunter-Tool
python threat_hunter.py '''

