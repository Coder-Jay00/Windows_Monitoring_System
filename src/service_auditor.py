"""
Service Auditor Module - YOU COMPLETE THIS MODULE
Audits Windows services for suspicious configurations.

UNDERSTAND THESE CONCEPTS:
1. What Windows services are and how they work
2. How attackers abuse services for persistence
3. What makes a service configuration suspicious

REFERENCE:
- MITRE ATT&CK T1543.003 (Windows Service)
- MITRE ATT&CK T1569.002 (Service Execution)
"""

import os
from typing import List, Dict, Tuple

# Choose ONE of these approaches to implement:
# Option A: Using WMI (recommended, easier)
# Option B: Using win32service (more control, harder)

# Uncomment the one you'll use:
# import wmi  # Option A
# import win32service  # Option B


# ============================================================
# SUSPICIOUS SERVICE INDICATORS
# Study these patterns - they indicate potential threats
# ============================================================

SUSPICIOUS_PATHS = [
    # Services should NOT run from these locations
    "\\Users\\",           # User directories
    "\\AppData\\",         # App data folders
    "\\Temp\\",            # Temporary folders
    "\\Downloads\\",       # Downloads folder
    "\\Desktop\\",         # Desktop
    "\\ProgramData\\",     # ProgramData (sometimes abused)
]

SUSPICIOUS_SERVICE_NAMES = [
    # Known malware service names (add more from research)
    # These are examples - real malware uses random/mimicking names
    "WindowsUpdate1",
    "WinDefend1",  # Mimics Windows Defender
    "svchost1",    # Mimics svchost
]

LEGITIMATE_SERVICE_PATHS = [
    # Services SHOULD run from these locations
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]


def get_all_services_wmi() -> List[Dict]:
    """
    Get all Windows services using WMI.
    """
    import wmi
    services = []
    
    try:
        # Connect to WMI
        c = wmi.WMI()
        
        # Query all services
        for service in c.Win32_Service():
            service_info = {
                'name': service.Name,
                'display_name': service.DisplayName,
                'state': service.State,
                'start_mode': service.StartMode,
                'path': service.PathName,
                'account': service.StartName
            }
            services.append(service_info)
            
    except Exception as e:
        print(f"Error querying services: {e}")
    
    return services


def check_suspicious_path(service_path: str) -> Tuple[bool, str]:
    """
    Check if a service's executable path is suspicious.
    """
    if not service_path:
        return (True, "No path specified")
    
    path_lower = service_path.lower()
    
    # Check for suspicious path patterns
    for sus_pattern in SUSPICIOUS_PATHS:
        if sus_pattern.lower() in path_lower:
            return (True, f"Running from suspicious location: {sus_pattern}")
    
    # Check if NOT in legitimate locations
    is_legitimate = False
    for legit_path in LEGITIMATE_SERVICE_PATHS:
        if legit_path.lower() in path_lower:
            is_legitimate = True
            break
    
    if not is_legitimate:
        return (True, "Not running from standard system location")
    
    return (False, "")


def detect_suspicious_services() -> List[Dict]:
    """
    Scan all services and identify suspicious ones.
    """
    suspicious = []
    
    # Get all services
    all_services = get_all_services_wmi()
    
    for service in all_services:
        reasons = []
        severity = 'LOW'
        
        service_path = service.get('path', '')
        service_name = service.get('name', '')
        
        # Check 1: Suspicious path
        is_sus_path, path_reason = check_suspicious_path(service_path)
        if is_sus_path:
            reasons.append(path_reason)
            severity = 'MEDIUM'
        
        # Check 2: Known malicious service names
        if service_name.lower() in [s.lower() for s in SUSPICIOUS_SERVICE_NAMES]:
            reasons.append(f"Known suspicious service name: {service_name}")
            severity = 'HIGH'
        
        # Check 3: Unquoted path vulnerability
        if check_unquoted_path(service_path):
            reasons.append("Unquoted service path - potential hijacking vulnerability")
            severity = 'MEDIUM' if severity == 'LOW' else severity
        
        # If any reasons found, add to suspicious list
        if reasons:
            suspicious.append({
                'name': service_name,
                'display_name': service.get('display_name', ''),
                'path': service_path,
                'state': service.get('state', 'Unknown'),
                'reasons': reasons,
                'severity': severity
            })
    
    return suspicious


def get_recently_created_services(days: int = 7) -> List[Dict]:
    """
    Find services created within the last N days.
    
    New services appearing suddenly can indicate compromise.
    
    Args:
        days: Number of days to look back
        
    Returns:
        List of recently created services
        
    TODO (YOUR TASK - ADVANCED): Implement this
    
    Approach:
    - Service creation times are stored in Registry
    - Path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>
    - Check the registry key's creation timestamp
    
    This is OPTIONAL but demonstrates registry forensics knowledge.
    """
    recent_services = []
    
    # TODO: YOUR CODE HERE (OPTIONAL ADVANCED TASK)
    # This requires using winreg module to read registry
    
    return recent_services


def audit_service_permissions() -> List[Dict]:
    """
    Check for services with dangerous permission configurations.
    
    Weak permissions can allow privilege escalation.
    
    TODO (YOUR TASK - ADVANCED): Research and implement
    
    Look for:
    - Services where non-admin users can modify config
    - Services with weak DACL (Discretionary Access Control List)
    - Unquoted service paths (allows DLL hijacking)
    
    This is OPTIONAL but demonstrates deep Windows security knowledge.
    """
    permission_issues = []
    
    # TODO: YOUR CODE HERE (OPTIONAL ADVANCED TASK)
    
    return permission_issues


# ============================================================
# HELPER: Detect Unquoted Service Paths
# This is a common vulnerability - provided for learning
# ============================================================

def check_unquoted_path(path: str) -> bool:
    """
    Check if a service path is unquoted AND contains spaces.
    
    Unquoted paths with spaces can be exploited:
    C:\\Program Files\\My App\\service.exe
    
    Windows might try to execute:
    C:\\Program.exe
    C:\\Program Files\\My.exe
    
    An attacker can place malicious executables at these paths.
    
    STUDY THIS FUNCTION - It's a real vulnerability!
    """
    if not path:
        return False
    
    # Extract path (remove arguments)
    # Service paths often have arguments like: "C:\path\svc.exe" -arg1
    
    # Check if path starts with quote
    if path.startswith('"'):
        return False  # Properly quoted
    
    # Check if path contains spaces
    # Find the executable part (before any arguments)
    parts = path.split()
    if len(parts) <= 1:
        return False  # No spaces
    
    # Has spaces and is not quoted = vulnerable
    return " " in path.split(" -")[0] if " -" in path else " " in path


# ============================================================
# TEST CODE
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("SERVICE AUDITOR TEST")
    print("=" * 60)
    
    # Test 1: Check unquoted path detection (provided)
    print("\n[TEST 1] Unquoted path vulnerability detection:")
    test_paths = [
        ('"C:\\Program Files\\App\\svc.exe"', False),  # Quoted - safe
        ('C:\\Windows\\System32\\svc.exe', False),      # No spaces - safe
        ('C:\\Program Files\\App\\svc.exe', True),      # Unquoted with spaces - VULNERABLE
    ]
    for path, expected in test_paths:
        result = check_unquoted_path(path)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {path[:40]}... Vulnerable: {result}")
    
    # Test 2: YOUR TODO - Get all services
    print("\n[TEST 2] Getting all services...")
    services = get_all_services_wmi()
    if services:
        print(f"  Found {len(services)} services")
        print("  First 3 services:")
        for svc in services[:3]:
            print(f"    - {svc.get('name')}: {svc.get('state')}")
    else:
        print("  TODO: Implement get_all_services_wmi() function!")
    
    # Test 3: YOUR TODO - Detect suspicious services
    print("\n[TEST 3] Scanning for suspicious services...")
    suspicious = detect_suspicious_services()
    if suspicious:
        print(f"  Found {len(suspicious)} suspicious services!")
        for svc in suspicious:
            print(f"  🚨 {svc}")
    elif services:  # Only show if we got services but no suspicious ones
        print("  No suspicious services detected (good!)")
    else:
        print("  TODO: Implement detect_suspicious_services() function!")
    
    print("\n" + "=" * 60)
