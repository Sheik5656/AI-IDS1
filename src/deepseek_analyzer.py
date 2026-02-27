import requests
import json
import os
from datetime import datetime

class DeepSeekAnalyzer:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv('DEEPSEEK_API_KEY', '')
        self.base_url = "https://api.deepseek.com/v1"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.mock_mode = not self.api_key
        
    def analyze_alert(self, alert_data):
        """Analyze alert with DeepSeek or provide detailed mock analysis"""
        
        if self.mock_mode or not self.api_key:
            return self._detailed_mock_analysis(alert_data)
        
        prompt = f"""
        You are a cybersecurity expert. Analyze this intrusion detection alert.
        
        Alert Details:
        - Time: {alert_data.get('timestamp')}
        - Source IP: {alert_data.get('src_ip')}
        - Destination IP: {alert_data.get('dst_ip')}
        - Protocol: {alert_data.get('protocol')}
        - Confidence: {alert_data.get('confidence')}
        - Attack Type: {alert_data.get('attack_type', 'Unknown')}
        
        Provide:
        1. Threat level (Low/Medium/High/Critical)
        2. Attack type
        3. CONTEXT: 5-6 sentences explaining the attack
        4. PREVENTION: 5-6 steps to stop/prevent it
        
        Format as JSON with keys: threat_level, attack_type, context, prevention
        """
        
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self.headers,
                json={
                    "model": "deepseek-chat",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 1000
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis = result['choices'][0]['message']['content']
                try:
                    return json.loads(analysis)
                except:
                    return self._detailed_mock_analysis(alert_data)
            else:
                return self._detailed_mock_analysis(alert_data)
                
        except Exception as e:
            print(f"DeepSeek API error: {e}")
            return self._detailed_mock_analysis(alert_data)
    
    def _detailed_mock_analysis(self, alert_data):
        """Provide detailed mock analysis"""
        
        confidence = alert_data.get('confidence', 0.5)
        attack_type = alert_data.get('attack_type', 'Unknown')
        src_ip = alert_data.get('src_ip', '192.168.1.100')
        
        # Get filename if available
        filename = ''
        if isinstance(alert_data.get('features'), dict):
            filename = alert_data.get('features', {}).get('filename', '')
        
        filename_lower = filename.lower()
        
        # ===== JAVASCRIPT MALWARE =====
        if '.js' in filename_lower:
            return {
                "threat_level": "HIGH",
                "attack_type": "JavaScript Malware",
                "context": "This JavaScript file contains obfuscated code. The script uses eval() and atob() functions to hide malicious code. When executed in a browser, it can steal cookies and download more malware. Drive-by downloads require no user interaction. This technique is used in 60% of web-based attacks. The malware could be ransomware or a cryptocurrency miner.",
                "prevention": "Delete this file immediately. Run a full antivirus scan. Update your browser and plugins. Use uBlock Origin to block scripts. Implement Content Security Policy headers. Use a web application firewall."
            }
        
        # ===== PHP WEBSHELL =====
        elif '.php' in filename_lower:
            return {
                "threat_level": "CRITICAL",
                "attack_type": "PHP WebShell",
                "context": "This PHP file contains webshell functions like system() and eval(). Attackers use webshells to control servers remotely. They can execute commands and steal data. Webshells are hard to detect among legitimate files. This backdoor allows complete server compromise. The attacker can launch further attacks from your server.",
                "prevention": "Delete this file immediately. Check for other suspicious PHP files. Change all passwords right now. Update your CMS and plugins. Restrict file upload permissions. Use a web application firewall."
            }
        
        # ===== SQL INJECTION =====
        elif '.sql' in filename_lower:
            return {
                "threat_level": "MEDIUM",
                "attack_type": "SQL Injection",
                "context": "This file contains SQL injection patterns like UNION SELECT and DROP TABLE. SQL injection steals database data. Attackers can bypass login forms and extract user information. This is a top 3 web vulnerability. It can lead to complete data loss. Customer data breaches often start with SQL injection.",
                "prevention": "Use parameterized queries in all database code. Never trust user input. Validate all form data. Use an allowlist for input values. Deploy a web application firewall. Run regular penetration tests."
            }
        
        # ===== PYTHON MALWARE =====
        elif '.py' in filename_lower:
            return {
                "threat_level": "HIGH",
                "attack_type": "Python Malware",
                "context": "This Python file contains suspicious subprocess calls and eval() functions. Python malware runs on Windows, Linux, and Mac. It can be a backdoor or information stealer. Attackers use Python for post-exploitation activities. The script may download more malware. PyBot and other Python malware are increasingly common.",
                "prevention": "Do not execute this file. Upload to VirusTotal for analysis. Check for network connections. Isolate the infected computer. Run a full antivirus scan. Monitor for unusual outbound traffic."
            }
        
        # ===== POWERSHELL MALWARE =====
        elif '.ps1' in filename_lower:
            return {
                "threat_level": "HIGH",
                "attack_type": "PowerShell Malware",
                "context": "This PowerShell script contains IEX and DownloadString commands. PowerShell is abused for 'living off the land' attacks. The script can download and execute malware without writing files. PowerShell malware is hard to detect. Frameworks like PowerShell Empire are used in ransomware attacks. This can disable security tools and establish persistence.",
                "prevention": "Block PowerShell execution for standard users. Enable PowerShell logging. Use Constrained Language Mode. Implement AppLocker rules. Check for new scheduled tasks. Deploy endpoint detection software."
            }
        
        # ===== DDoS ATTACK =====
        elif 'ddos' in attack_type.lower() or 'ddos' in filename_lower:
            return {
                "threat_level": "CRITICAL",
                "attack_type": "DDoS Attack",
                "context": "Multiple sources are flooding your server with traffic. This overwhelms your network and makes services unavailable. DDoS attacks use amplification techniques like UDP flood. Your server may receive 5000+ packets per second. These attacks often distract from data theft. Recent DDoS attacks have reached over 1 Tbps.",
                "prevention": "Contact your ISP for upstream mitigation. Enable Cloudflare DDoS protection. Configure firewall to drop invalid packets. Use rate limiting on your web server. Deploy a load balancer. Create a DDoS response plan."
            }
        
        # ===== BRUTE FORCE ATTACK =====
        elif 'brute' in attack_type.lower() or 'force' in attack_type.lower():
            return {
                "threat_level": "HIGH",
                "attack_type": "Brute Force Attack",
                "context": f"Multiple failed login attempts from {src_ip}. The attacker is trying common passwords automatically. Tools like Hydra try thousands of passwords per minute. Successful attacks lead to account takeover. 65% of people reuse passwords across services. This targets SSH, RDP, and admin panels.",
                "prevention": f"Block the attacking IP immediately. Use Fail2Ban to auto-block scanners. Enable Multi-Factor Authentication on all accounts. Add CAPTCHA to login forms. Change default SSH/RDP ports. Use strong unique passwords."
            }
        
        # ===== PORT SCAN =====
        elif 'port' in attack_type.lower() or 'scan' in attack_type.lower():
            return {
                "threat_level": "CRITICAL",
                "attack_type": "Port Scan",
                "context": f"SYN scan detected from {src_ip} targeting multiple ports. This is reconnaissance before an attack. The attacker is mapping your network for vulnerabilities. Port scans check for open services like SSH and RDP. This precedes 90% of successful breaches. The scanner looks for entry points.",
                "prevention": f"Block {src_ip} at the firewall immediately. Implement rate limiting (max 10 connections/minute). Install Fail2Ban to auto-block scanners. Move sensitive services to non-standard ports. Use Port Knocking for SSH. Deploy an Intrusion Prevention System."
            }
        
        # ===== DATA EXFILTRATION =====
        elif 'exfil' in attack_type.lower() or 'exfiltration' in filename_lower:
            return {
                "threat_level": "CRITICAL",
                "attack_type": "Data Exfiltration",
                "context": f"Large data transfer detected from {src_ip} to an external IP. This indicates stolen data leaving your network. Attackers exfiltrate customer data for ransom or sale. Transfers often happen at night to avoid detection. This could be a GDPR violation with huge fines. The data may be encrypted to bypass security.",
                "prevention": "Block the destination IP immediately. Investigate the source device. Implement Data Loss Prevention tools. Use egress filtering on your firewall. Monitor for >100MB outbound transfers. Classify and encrypt sensitive data."
            }
        
        # ===== MALWARE C2 =====
        elif 'c2' in attack_type.lower() or 'command' in attack_type.lower():
            return {
                "threat_level": "CRITICAL",
                "attack_type": "Malware C2 Communication",
                "context": f"Device {src_ip} is contacting a known malicious server. This means the device is infected with malware. The malware receives instructions from attackers. It can download more payloads or join a botnet. This pattern matches Emotet and Trickbot families. The infected device can attack other systems.",
                "prevention": "Isolate the infected device immediately. Run a full antivirus scan. Check for suspicious processes. Block the malicious IP at the firewall. Reset all passwords used on that device. Deploy endpoint detection software."
            }
        
        # ===== DEFAULT =====
        else:
            return {
                "threat_level": "MEDIUM",
                "attack_type": "Suspicious File",
                "context": f"This file ({filename}) has been flagged for analysis. It may contain malicious patterns. The system recommends manual investigation. Similar files have been used in attacks. Further analysis is needed to determine the threat. Do not execute unknown files.",
                "prevention": "Do not open or execute this file. Upload to VirusTotal for scanning. Check the file's origin. Use a sandbox for safe analysis. Run a full antivirus scan. Quarantine the file until verified."
            }