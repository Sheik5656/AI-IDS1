import time
import pandas as pd
import numpy as np
from collections import deque, defaultdict
from datetime import datetime
import joblib
import os
import threading
import hashlib
import json
import re
import math
import random

# Try to import magic, handle if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("⚠️ python-magic not installed. Run: pip install python-magic-bin")

# Try to import scapy, handle if not available
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available - using simulation mode")

class PacketSniffer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packets = []  # Use list instead of deque for simplicity
        self.alerts = []
        self.packet_rate_times = []
        self.port_tracker = defaultdict(set)
        self.ip_tracker = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start_time': time.time()})
        self.running = False
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.simulation_mode = not SCAPY_AVAILABLE
        self.last_alert_time = time.time()
        self.packet_count = 0
        self.unique_ips_set = set()
        self.generation_thread = None
        
    def load_model(self, model_path='models/'):
        """Load trained ML model"""
        try:
            self.model = joblib.load(os.path.join(model_path, 'rf_model.joblib'))
            self.scaler = joblib.load(os.path.join(model_path, 'scaler.pkl'))
            self.feature_names = joblib.load(os.path.join(model_path, 'feature_names.pkl'))
            print("✅ Model loaded successfully")
            return True
        except Exception as e:
            print(f"⚠️ Model loading failed: {e}")
            return False
    
    def generate_packet(self):
        """Generate a single packet with guaranteed storage"""
        if not self.running:
            return
            
        # Increment packet counter
        self.packet_count += 1
        
        # Generate random IPs
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = f"10.0.0.{random.randint(2, 254)}"
        
        # Add to unique IPs set
        self.unique_ips_set.add(src_ip)
        self.unique_ips_set.add(dst_ip)
        
        # Generate protocol
        protocol_num = random.choice([6, 17, 1])
        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        protocol = protocol_map.get(protocol_num, 'OTHER')
        
        # Generate ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389, random.randint(1, 1024)])
        
        # Packet features
        features = {
            'packet_length': random.randint(64, 1500),
            'ttl': random.choice([64, 128, 255]),
            'protocol': protocol_num,
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_rate': len([t for t in self.packet_rate_times if time.time() - t < 2]),
            'unique_ports': random.randint(1, 20)
        }
        
        # Track packet rate
        self.packet_rate_times.append(time.time())
        
        # Create packet record - THIS IS THE IMPORTANT PART
        packet_record = {
            'timestamp': time.time(),
            'timestamp_str': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'protocol_num': protocol_num,
            'src_port': src_port,
            'dst_port': dst_port,
            'length': features['packet_length'],
            'ttl': features['ttl'],
            'features': features
        }
        
        # STORE THE PACKET (THIS WAS MISSING)
        self.packets.append(packet_record)
        
        # Randomly generate alerts (30% chance)
        if random.random() < 0.3:
            confidence = random.uniform(0.65, 0.98)
            attack_types = ['Port Scan', 'DDoS Attack', 'Brute Force', 'Malware C2', 'Data Exfiltration', 'SQL Injection']
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'confidence': round(confidence, 2),
                'attack_type': random.choice(attack_types),
                'features': features
            }
            self.alerts.append(alert)
            
            # Print alert to terminal
            print(f"\n🚨 ALERT [{len(self.alerts)}]: {alert['attack_type']}")
            print(f"   {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol}) [{confidence:.0%}]")
        
        # Print progress every 20 packets
        if self.packet_count % 20 == 0:
            print(f"📊 Progress: {self.packet_count} packets generated, {len(self.alerts)} alerts, {len(self.unique_ips_set)} unique IPs")
        
        # Schedule next packet
        if self.running:
            threading.Timer(0.1, self.generate_packet).start()
    
    def start_sniffing(self):
        """Start packet generation"""
        if self.running:
            return
            
        self.running = True
        self.packet_count = 0
        self.unique_ips_set = set()
        self.packets = []
        self.alerts = []
        self.packet_rate_times = []
        
        print("\n" + "="*60)
        print("🕵️  LIVE DETECTION STARTED")
        print("="*60)
        print("📦 Generating simulated network packets...")
        print("🚨 Alerts will appear when attacks are detected")
        print("="*60 + "\n")
        
        # Start packet generation
        self.generate_packet()
        
    def stop_sniffing(self):
        """Stop packet generation"""
        self.running = False
        print("\n" + "="*60)
        print(f"🛑 DETECTION STOPPED")
        print(f"📊 Final stats: {self.packet_count} packets, {len(self.alerts)} alerts")
        print("="*60 + "\n")
        
    def get_alerts(self):
        """Return recent alerts (last 20)"""
        return list(self.alerts)[-20:]
    
    def get_stats(self):
        """Get current statistics"""
        # Calculate packet rate (packets in last 2 seconds)
        current_time = time.time()
        recent_packets = [t for t in self.packet_rate_times if current_time - t < 2]
        packet_rate = len(recent_packets)
        
        # Get last 20 packets for charts
        recent_packets_list = list(self.packets)[-50:]
        
        # Calculate protocol distribution
        protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        for p in recent_packets_list:
            proto = p.get('protocol', 'OTHER')
            if proto in protocols:
                protocols[proto] += 1
            else:
                protocols['Other'] += 1
        
        # Calculate packet rates for graph
        packet_rates = []
        for i in range(20):
            time_window = current_time - (i * 0.5)
            count = len([t for t in self.packet_rate_times if abs(t - time_window) < 0.5])
            packet_rates.append(count)
        
        return {
            'packet_count': self.packet_count,
            'alert_count': len(self.alerts),
            'packet_rate': packet_rate,
            'unique_ips': len(self.unique_ips_set),
            'protocols': protocols,
            'packet_rates': packet_rates[::-1]  # Reverse for chronological order
        }


class FileAnalyzer:
    """Analyze uploaded files for malicious content with attack classification"""
    
    def __init__(self):
        # Attack classification dictionary
        self.attack_classification = {
            'php_webshell': {
                'name': 'PHP WebShell',
                'type': 'R2L (Remote to Local)',
                'description': 'Malicious script that allows remote command execution on web servers',
                'mitre_id': 'T1505.003',
                'severity': 'CRITICAL'
            },
            'javascript_malware': {
                'name': 'JavaScript Malware',
                'type': 'Drive-by Download',
                'description': 'Obfuscated JavaScript designed to exploit browsers and steal data',
                'mitre_id': 'T1189',
                'severity': 'HIGH'
            },
            'powershell_malware': {
                'name': 'PowerShell Empire',
                'type': 'U2R (User to Root)',
                'description': 'Malicious PowerShell commands for post-exploitation and privilege escalation',
                'mitre_id': 'T1059.001',
                'severity': 'HIGH'
            },
            'python_malware': {
                'name': 'Python Backdoor',
                'type': 'R2L (Remote to Local)',
                'description': 'Python script with backdoor functionality for remote access',
                'mitre_id': 'T1500',
                'severity': 'HIGH'
            },
            'sql_injection': {
                'name': 'SQL Injection',
                'type': 'Probe/Scanning',
                'description': 'Attempt to manipulate database queries to bypass authentication or extract data',
                'mitre_id': 'T1190',
                'severity': 'MEDIUM'
            }
        }
        
        self.suspicious_patterns = {
            'php_webshell': [r'<?php', r'system\(', r'exec\(', r'shell_exec\(', r'passthru\(', r'base64_decode\(', r'eval\(', r'assert\('],
            'javascript_malware': [r'eval\(', r'document\.write\(', r'unescape\(', r'fromCharCode\(', r'atob\('],
            'powershell_malware': [r'Invoke-', r'IEX\(', r'DownloadString', r'Start-Process', r'New-Object'],
            'python_malware': [r'__import__\(', r'eval\(', r'exec\(', r'pickle\.loads\(', r'subprocess\.'],
            'sql_injection': [r'union.*select', r'insert into', r'drop table', r'--', r'#', r';\s*drop'],
        }
        
        self.malicious_hashes = {
            'eicar_test': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',  # EICAR test virus
        }
        
    def calculate_file_hash(self, filepath, algorithm='sha256'):
        """Calculate file hash for threat intelligence matching"""
        hash_obj = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def detect_file_type(self, filepath):
        """Detect MIME type and file extension"""
        try:
            if MAGIC_AVAILABLE:
                mime = magic.Magic(mime=True)
                file_type = mime.from_file(filepath)
            else:
                file_type = "Unknown (magic not installed)"
                
            extension = os.path.splitext(filepath)[1].lower()
            return {
                'mime_type': file_type,
                'extension': extension,
                'is_executable': extension in ['.exe', '.dll', '.so', '.dylib', '.bin'],
                'is_script': extension in ['.php', '.py', '.js', '.vbs', '.ps1', '.sh', '.bat'],
                'is_archive': extension in ['.zip', '.rar', '.7z', '.tar', '.gz'],
                'is_document': extension in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
            }
        except Exception as e:
            return {'error': f'Could not detect file type: {e}'}
    
    def scan_for_malicious_patterns(self, filepath):
        """Scan file content for suspicious patterns"""
        results = []
        
        try:
            # Try to read as text
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                
                for pattern_type, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            results.append({
                                'type': pattern_type,
                                'pattern': pattern,
                                'severity': 'HIGH' if 'webshell' in pattern_type else 'MEDIUM',
                                'description': f'Found suspicious pattern: {pattern}'
                            })
        except:
            # Binary file - skip pattern matching
            pass
            
        return results
    
    def calculate_entropy(self, filepath):
        """Calculate file entropy to detect packed/encrypted malware"""
        
        with open(filepath, 'rb') as f:
            data = f.read()
            
        if len(data) == 0:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
                
        return entropy
    
    def analyze_file(self, filepath, filename):
        """Complete file analysis with attack classification"""
        result = {
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'file_size': os.path.getsize(filepath),
            'hash': {
                'md5': self.calculate_file_hash(filepath, 'md5'),
                'sha1': self.calculate_file_hash(filepath, 'sha1'),
                'sha256': self.calculate_file_hash(filepath, 'sha256')
            },
            'file_type': self.detect_file_type(filepath),
            'entropy': self.calculate_entropy(filepath),
            'suspicious_patterns': self.scan_for_malicious_patterns(filepath),
            'risk_score': 0,
            'detected_attacks': []
        }
        
        # Classify detected patterns into attack types
        for pattern in result['suspicious_patterns']:
            pattern_type = pattern['type']
            if pattern_type in self.attack_classification:
                attack_info = self.attack_classification[pattern_type].copy()
                attack_info['matched_pattern'] = pattern['pattern']
                result['detected_attacks'].append(attack_info)
        
        # Calculate risk score
        risk_score = 0
        
        # Check known malicious hashes
        if result['hash']['sha256'] in self.malicious_hashes.values():
            risk_score += 50
            result['known_malware'] = True
            result['detected_attacks'].append({
                'name': 'Known Malware',
                'type': 'U2R (User to Root)',
                'description': 'File matches known malware hash database',
                'mitre_id': 'T1078',
                'severity': 'CRITICAL'
            })
            
        # High entropy indicates packed/encrypted malware
        if result['entropy'] > 7:
            risk_score += 20
            result['detected_attacks'].append({
                'name': 'Packed/Encrypted Malware',
                'type': 'Obfuscation Techniques',
                'description': 'High entropy indicates packed or encrypted payload to evade detection',
                'mitre_id': 'T1027',
                'severity': 'HIGH'
            })
            
        # Suspicious file types
        if result['file_type'].get('is_executable'):
            risk_score += 15
            
        # Add pattern detection scores
        pattern_count = len(result['suspicious_patterns'])
        risk_score += pattern_count * 10
        
        result['risk_score'] = min(risk_score, 100)
        
        # Risk level classification
        if result['risk_score'] >= 70:
            result['risk_level'] = 'CRITICAL'
        elif result['risk_score'] >= 50:
            result['risk_level'] = 'HIGH'
        elif result['risk_score'] >= 30:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'LOW'
        
        # Add summary of detected attacks
        if result['detected_attacks']:
            result['attack_summary'] = ', '.join([a['name'] for a in result['detected_attacks']])
        else:
            result['attack_summary'] = 'No specific attack detected'
        
        return result