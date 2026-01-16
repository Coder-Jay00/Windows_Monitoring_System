"""
Report Generator Module - STARTER CODE PROVIDED
Generates formatted detection reports.

This module is mostly complete - STUDY how it works
to understand report formatting and log management.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any
from colorama import Fore, Style, init

# Initialize colorama for Windows color support
init()


# ============================================================
# REPORT CONFIGURATION
# ============================================================

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
SEVERITY_COLORS = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.CYAN,
    'INFO': Fore.WHITE
}


def ensure_logs_dir():
    """Create logs directory if it doesn't exist."""
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)


def format_severity(severity: str) -> str:
    """Add color to severity level for console output."""
    color = SEVERITY_COLORS.get(severity.upper(), Fore.WHITE)
    return f"{color}{severity}{Style.RESET_ALL}"


def generate_console_report(
    parent_child_findings: List[Dict],
    service_findings: List[Dict],
    unauthorized_findings: List[Dict]
) -> None:
    """
    Generate a formatted console report of all findings.
    
    Args:
        parent_child_findings: Results from parent_child_detector
        service_findings: Results from service_auditor
        unauthorized_findings: Results from unauthorized_detector
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print("\n" + "=" * 70)
    print(f"{Fore.CYAN + Style.BRIGHT}    WINDOWS MONITORING AGENT - DETECTION REPORT{Style.RESET_ALL}")
    print("=" * 70)
    print(f"  Scan Time: {timestamp}")
    print("=" * 70)
    
    # Summary counts
    total_findings = len(parent_child_findings) + len(service_findings) + len(unauthorized_findings)
    
    if total_findings == 0:
        print(f"\n  {Fore.GREEN}✓ No suspicious activity detected{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.YELLOW}⚠ Found {total_findings} potential issues{Style.RESET_ALL}")
    
    # Parent-Child Findings
    print(f"\n{Fore.WHITE + Style.BRIGHT}─── PARENT-CHILD ANOMALIES ───{Style.RESET_ALL}")
    if parent_child_findings:
        for finding in parent_child_findings:
            severity = finding.get('severity', 'MEDIUM')
            print(f"\n  [{format_severity(severity)}] {finding.get('parent_name')} → {finding.get('child_name')}")
            print(f"      Child PID: {finding.get('child_pid')}")
            print(f"      Reason: {finding.get('reason')}")
    else:
        print(f"  {Fore.GREEN}✓ No suspicious parent-child relationships{Style.RESET_ALL}")
    
    # Service Findings
    print(f"\n{Fore.WHITE + Style.BRIGHT}─── SUSPICIOUS SERVICES ───{Style.RESET_ALL}")
    if service_findings:
        for finding in service_findings:
            severity = finding.get('severity', 'MEDIUM')
            print(f"\n  [{format_severity(severity)}] Service: {finding.get('name')}")
            print(f"      Path: {finding.get('path', 'Unknown')}")
            print(f"      Reasons: {', '.join(finding.get('reasons', []))}")
    else:
        print(f"  {Fore.GREEN}✓ No suspicious services detected{Style.RESET_ALL}")
    
    # Unauthorized Process Findings
    print(f"\n{Fore.WHITE + Style.BRIGHT}─── UNAUTHORIZED PROCESSES ───{Style.RESET_ALL}")
    if unauthorized_findings:
        for finding in unauthorized_findings:
            severity = finding.get('severity', 'MEDIUM')
            print(f"\n  [{format_severity(severity)}] Process: {finding.get('name')} (PID: {finding.get('pid')})")
            print(f"      Path: {finding.get('path', 'Unknown')}")
            print(f"      Type: {finding.get('detection_type', 'Unknown')}")
            print(f"      Reasons: {', '.join(finding.get('reasons', []))}")
    else:
        print(f"  {Fore.GREEN}✓ All processes are authorized{Style.RESET_ALL}")
    
    # Summary
    print("\n" + "=" * 70)
    high_count = sum(1 for f in parent_child_findings + service_findings + unauthorized_findings 
                    if f.get('severity', '').upper() == 'HIGH')
    med_count = sum(1 for f in parent_child_findings + service_findings + unauthorized_findings 
                   if f.get('severity', '').upper() == 'MEDIUM')
    low_count = total_findings - high_count - med_count
    
    print(f"  Summary: {total_findings} findings | "
          f"{format_severity('HIGH')}: {high_count} | "
          f"{format_severity('MEDIUM')}: {med_count} | "
          f"{format_severity('LOW')}: {low_count}")
    print("=" * 70 + "\n")


def save_json_report(
    parent_child_findings: List[Dict],
    service_findings: List[Dict],
    unauthorized_findings: List[Dict],
    filename: str = None
) -> str:
    """
    Save findings to a JSON file for further analysis.
    
    Args:
        parent_child_findings: Results from parent_child_detector
        service_findings: Results from service_auditor
        unauthorized_findings: Results from unauthorized_detector
        filename: Optional custom filename
        
    Returns:
        Path to saved report file
        
    TODO (YOUR TASK): Add more metadata to the report
    - System information (hostname, OS version)
    - Scan duration
    - Agent version
    """
    ensure_logs_dir()
    
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_report_{timestamp}.json"
    
    filepath = os.path.join(LOGS_DIR, filename)
    
    report = {
        'scan_timestamp': datetime.now().isoformat(),
        'findings': {
            'parent_child_anomalies': parent_child_findings,
            'suspicious_services': service_findings,
            'unauthorized_processes': unauthorized_findings
        },
        'summary': {
            'total_findings': len(parent_child_findings) + len(service_findings) + len(unauthorized_findings),
            'parent_child_count': len(parent_child_findings),
            'service_count': len(service_findings),
            'unauthorized_count': len(unauthorized_findings)
        }
        # TODO: Add system_info, scan_duration, etc.
    }
    
    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"Report saved to: {filepath}")
    return filepath


def save_log_entry(event_type: str, details: Dict) -> None:
    """
    Append a single event to the running log file.
    
    Use this for real-time logging during monitoring.
    
    Args:
        event_type: Type of event (ALERT, INFO, WARNING)
        details: Event details dictionary
    """
    ensure_logs_dir()
    
    log_file = os.path.join(LOGS_DIR, f"monitor_{datetime.now().strftime('%Y%m%d')}.log")
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': event_type,
        'details': details
    }
    
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')


# ============================================================
# TEST CODE
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("REPORT GENERATOR TEST")
    print("=" * 60)
    
    # Sample data for testing
    sample_parent_child = [
        {
            'parent_name': 'winword.exe',
            'child_name': 'powershell.exe',
            'child_pid': 1234,
            'reason': 'Word spawning PowerShell - possible macro attack',
            'severity': 'HIGH'
        }
    ]
    
    sample_services = [
        {
            'name': 'SuspiciousService',
            'path': 'C:\\Users\\Admin\\Temp\\svc.exe',
            'reasons': ['Running from user temp folder'],
            'severity': 'HIGH'
        }
    ]
    
    sample_unauthorized = [
        {
            'pid': 5678,
            'name': 'unknown.exe',
            'path': 'C:\\Users\\Public\\unknown.exe',
            'detection_type': 'NOT_WHITELISTED',
            'reasons': ['Process not in whitelist'],
            'severity': 'MEDIUM'
        }
    ]
    
    # Test console report
    print("\n[TEST] Generating console report with sample data...\n")
    generate_console_report(sample_parent_child, sample_services, sample_unauthorized)
    
    # Test JSON report
    print("[TEST] Saving JSON report...")
    filepath = save_json_report(sample_parent_child, sample_services, sample_unauthorized, "test_report.json")
    
    print("\n" + "=" * 60)
