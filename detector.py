#!/usr/bin/env python3
"""
Threat Detector — Analyses logs and raises alerts
Author: S.Md.Afzal
GitHub: github.com/SYEDMAHAMMEDAFZAL
"""

import json
import os
import glob
import datetime
from collections import defaultdict

THRESHOLDS = {
    'brute_force_attempts': 10,
    'port_scan_ports': 3,
    'failed_login_count': 3,
}

def load_logs():
    all_logs = []
    log_files = glob.glob('logs/*.json')
    for f in log_files:
        with open(f, 'r') as file:
            all_logs.extend(json.load(file))
    return all_logs

def analyse_logs(logs):
    alerts = []
    ip_failed = defaultdict(int)
    ip_brute  = defaultdict(int)
    ip_scans  = defaultdict(int)

    for log in logs:
        ip = log.get('source_ip')
        etype = log.get('event_type')
        severity = log.get('severity')

        if etype == 'BRUTE_FORCE':
            ip_brute[ip] += log.get('attempts', 1)
            if ip_brute[ip] >= THRESHOLDS['brute_force_attempts']:
                alerts.append({
                    'timestamp': log['timestamp'],
                    'alert_type': 'BRUTE FORCE ATTACK',
                    'source_ip': ip,
                    'severity': 'HIGH',
                    'detail': f'IP {ip} made {ip_brute[ip]} login attempts',
                    'recommendation': 'Block IP immediately. Enable account lockout policy.'
                })

        elif etype == 'PORT_SCAN':
            ip_scans[ip] += 1
            alerts.append({
                'timestamp': log['timestamp'],
                'alert_type': 'PORT SCAN DETECTED',
                'source_ip': ip,
                'severity': 'MEDIUM',
                'detail': f'IP {ip} scanning multiple ports: {log.get("port")}',
                'recommendation': 'Monitor IP. Add to watchlist. Check firewall rules.'
            })

        elif etype == 'FAILED_LOGIN':
            ip_failed[ip] += log.get('attempts', 1)
            if ip_failed[ip] >= THRESHOLDS['failed_login_count']:
                alerts.append({
                    'timestamp': log['timestamp'],
                    'alert_type': 'REPEATED FAILED LOGINS',
                    'source_ip': ip,
                    'severity': 'LOW',
                    'detail': f'IP {ip} failed login {ip_failed[ip]} times',
                    'recommendation': 'Monitor IP activity. Consider rate limiting.'
                })

        elif etype == 'MALWARE_DETECTED':
            alerts.append({
                'timestamp': log['timestamp'],
                'alert_type': 'MALWARE DETECTED',
                'source_ip': ip,
                'severity': 'CRITICAL',
                'detail': log.get('message'),
                'recommendation': 'Isolate affected system. Run full antivirus scan. Check for persistence.'
            })

    return alerts

def get_stats(logs, alerts):
    severity_count = defaultdict(int)
    event_count    = defaultdict(int)
    ip_count       = defaultdict(int)

    for log in logs:
        event_count[log.get('event_type', 'UNKNOWN')] += 1
        ip_count[log.get('source_ip', 'unknown')] += 1

    for alert in alerts:
        severity_count[alert.get('severity', 'INFO')] += 1

    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        'total_logs':    len(logs),
        'total_alerts':  len(alerts),
        'critical':      severity_count.get('CRITICAL', 0),
        'high':          severity_count.get('HIGH', 0),
        'medium':        severity_count.get('MEDIUM', 0),
        'low':           severity_count.get('LOW', 0),
        'event_types':   dict(event_count),
        'top_ips':       top_ips,
    }

if __name__ == '__main__':
    print("[*] Loading logs...")
    logs = load_logs()
    print(f"[+] Loaded {len(logs)} events")

    print("[*] Analysing for threats...")
    alerts = analyse_logs(logs)
    print(f"[+] Found {len(alerts)} alerts")

    stats = get_stats(logs, alerts)
    print(f"\n--- THREAT SUMMARY ---")
    print(f"Total Events : {stats['total_logs']}")
    print(f"Total Alerts : {stats['total_alerts']}")
    print(f"CRITICAL     : {stats['critical']}")
    print(f"HIGH         : {stats['high']}")
    print(f"MEDIUM       : {stats['medium']}")
    print(f"LOW          : {stats['low']}")
    print(f"\nTop Attacker IPs:")
    for ip, count in stats['top_ips']:
        print(f"  {ip} → {count} events")
