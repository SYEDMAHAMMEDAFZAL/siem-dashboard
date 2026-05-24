#!/usr/bin/env python3
"""
Log Generator — Simulates real attack scenarios
Author: S.Md.Afzal
GitHub: github.com/SYEDMAHAMMEDAFZAL
"""

import random
import time
import datetime
import json
import os

# Simulated IPs
ATTACK_IPS = [
    '192.168.1.105', '10.0.0.44', '172.16.0.23',
    '45.33.32.156', '198.51.100.22', '203.0.113.45'
]
NORMAL_IPS = [
    '192.168.1.1', '192.168.1.10', '192.168.1.20',
    '192.168.1.30', '192.168.1.50'
]
USERS = ['admin', 'root', 'afzal', 'user1', 'guest', 'test']
SERVICES = ['SSH', 'HTTP', 'FTP', 'MySQL', 'RDP', 'SMTP']
PORTS = [22, 80, 21, 3306, 3389, 25, 443, 8080, 23, 53]

def timestamp():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def generate_brute_force(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    user = random.choice(USERS)
    return {
        'timestamp': timestamp(),
        'event_type': 'BRUTE_FORCE',
        'source_ip': ip,
        'destination_ip': '192.168.1.100',
        'username': user,
        'service': 'SSH',
        'port': 22,
        'status': 'FAILED',
        'attempts': random.randint(10, 100),
        'severity': 'HIGH',
        'message': f'Multiple failed login attempts for user {user} from {ip}'
    }

def generate_port_scan(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    scanned_ports = random.sample(PORTS, random.randint(3, 8))
    return {
        'timestamp': timestamp(),
        'event_type': 'PORT_SCAN',
        'source_ip': ip,
        'destination_ip': '192.168.1.100',
        'username': 'N/A',
        'service': 'NETWORK',
        'port': scanned_ports,
        'status': 'DETECTED',
        'attempts': len(scanned_ports),
        'severity': 'MEDIUM',
        'message': f'Port scan detected from {ip} — ports: {scanned_ports}'
    }

def generate_failed_login():
    ip = random.choice(ATTACK_IPS + NORMAL_IPS)
    user = random.choice(USERS)
    service = random.choice(SERVICES)
    return {
        'timestamp': timestamp(),
        'event_type': 'FAILED_LOGIN',
        'source_ip': ip,
        'destination_ip': '192.168.1.100',
        'username': user,
        'service': service,
        'port': random.choice(PORTS),
        'status': 'FAILED',
        'attempts': random.randint(1, 5),
        'severity': 'LOW',
        'message': f'Failed login for {user} on {service} from {ip}'
    }

def generate_malware_alert():
    ip = random.choice(ATTACK_IPS)
    return {
        'timestamp': timestamp(),
        'event_type': 'MALWARE_DETECTED',
        'source_ip': ip,
        'destination_ip': '192.168.1.100',
        'username': 'SYSTEM',
        'service': 'ANTIVIRUS',
        'port': 0,
        'status': 'BLOCKED',
        'attempts': 1,
        'severity': 'CRITICAL',
        'message': f'Malware signature detected from {ip} — connection blocked'
    }

def generate_normal_traffic():
    ip = random.choice(NORMAL_IPS)
    user = random.choice(USERS)
    service = random.choice(['HTTP', 'HTTPS', 'DNS'])
    return {
        'timestamp': timestamp(),
        'event_type': 'NORMAL_TRAFFIC',
        'source_ip': ip,
        'destination_ip': '192.168.1.100',
        'username': user,
        'service': service,
        'port': random.choice([80, 443, 53]),
        'status': 'SUCCESS',
        'attempts': 1,
        'severity': 'INFO',
        'message': f'Normal {service} traffic from {ip}'
    }

def generate_logs(count=50):
    os.makedirs('logs', exist_ok=True)
    logs = []

    generators = [
        (generate_brute_force, 15),
        (generate_port_scan, 10),
        (generate_failed_login, 20),
        (generate_malware_alert, 5),
        (generate_normal_traffic, 50),
    ]

    for func, weight in generators:
        for _ in range(int(count * weight / 100)):
            logs.append(func())

    random.shuffle(logs)

    # Save to file
    log_file = f"logs/events_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(log_file, 'w') as f:
        json.dump(logs, f, indent=2)

    print(f"[+] Generated {len(logs)} log events → {log_file}")
    return logs, log_file

if __name__ == '__main__':
    print("[*] Generating simulated attack logs...")
    logs, path = generate_logs(100)
    print(f"[✓] Done. Check {path}")
