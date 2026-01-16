"""
Unauthorized Process Detector - YOU COMPLETE THIS MODULE
Detects processes not on the whitelist or matching blacklist patterns.

UNDERSTAND THESE CONCEPTS:
1. Why whitelisting is effective for security
2. Difference between whitelist and blacklist approaches
3. How to handle false positives/negatives

REFERENCE:
- Application Whitelisting best practices
- NIST Guidelines for application security
"""

import os
import json
from typing import List, Dict, Set
try:
    from src.process_monitor import get_all_processes
except ImportError:
    from process_monitor import get_all_processes


# ============================================================
# CONFIGURATION PATHS
# Your whitelist/blacklist files location
# ============================================================

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config')
WHITELIST_FILE = os.path.join(CONFIG_DIR, 'whitelist.json')
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklist.json')


# ============================================================
# DEFAULT WHITELIST - Common legitimate Windows processes
# You should CREATE the actual whitelist.json file
# ============================================================

DEFAULT_WHITELIST = [
    # Windows Core
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "taskhostw.exe",
    "sihost.exe",
    "ctfmon.exe",
    
    # Common Applications
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "code.exe",  # VS Code
    "python.exe",
    "pythonw.exe",
    "cmd.exe",
    "powershell.exe",
    "conhost.exe",
    "notepad.exe",
    
    # TODO: Add more legitimate processes you use
    # Research what processes YOUR system normally runs
]

DEFAULT_BLACKLIST = [
    # Known malicious process names (examples)
    # Real malware often uses random or mimicking names
    "mimikatz.exe",
    "pwdump.exe",
    "procdump.exe",  # Can be legitimate but often used maliciously
    "netcat.exe",
    "nc.exe",
    
    # TODO: Research and add known malware process names
    # Be careful - some tools are dual-use (legitimate + malicious)
]


def load_whitelist() -> Set[str]:
    """
    Load process whitelist from config file.
    """
    try:
        with open(WHITELIST_FILE, 'r') as f:
            data = json.load(f)
            # Handle both formats: list or dict with 'whitelist' key
            if isinstance(data, dict):
                processes = data.get('whitelist', [])
            else:
                processes = data
            return set(name.lower() for name in processes)
    except FileNotFoundError:
        print(f"  Whitelist file not found, using defaults")
        return set(name.lower() for name in DEFAULT_WHITELIST)
    except json.JSONDecodeError:
        print(f"  Error parsing whitelist file, using defaults")
        return set(name.lower() for name in DEFAULT_WHITELIST)


def load_blacklist() -> Set[str]:
    """
    Load process blacklist from config file.
    """
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict):
                processes = data.get('blacklist', [])
            else:
                processes = data
            return set(name.lower() for name in processes)
    except FileNotFoundError:
        return set(name.lower() for name in DEFAULT_BLACKLIST)
    except json.JSONDecodeError:
        return set(name.lower() for name in DEFAULT_BLACKLIST)


def is_process_whitelisted(process_name: str) -> bool:
    """
    Check if a process is in the whitelist.
    
    Args:
        process_name: Name of process to check
        
    Returns:
        True if process is whitelisted
    """
    whitelist = load_whitelist()
    return process_name.lower() in whitelist


def is_process_blacklisted(process_name: str) -> bool:
    """
    Check if a process is in the blacklist.
    
    Args:
        process_name: Name of process to check
        
    Returns:
        True if process is blacklisted (ALERT!)
    """
    blacklist = load_blacklist()
    return process_name.lower() in blacklist


def check_process_path(exe_path: str) -> Dict:
    """
    Analyze a process's executable path for suspicious indicators.
    """
    result = {
        'suspicious': False,
        'reasons': [],
        'severity': 'LOW'
    }
    
    if not exe_path or exe_path == "Access Denied":
        result['suspicious'] = True
        result['reasons'].append("Cannot access executable path")
        result['severity'] = 'MEDIUM'
        return result
    
    path_lower = exe_path.lower()
    
    # Suspicious path patterns to check
    suspicious_patterns = [
        ("\\temp\\", "Running from Temp folder", "HIGH"),
        ("\\tmp\\", "Running from Tmp folder", "HIGH"),
        ("\\downloads\\", "Running from Downloads folder", "MEDIUM"),
        ("\\appdata\\local\\temp", "Running from AppData Temp", "HIGH"),
        ("\\users\\public\\", "Running from Public folder", "MEDIUM"),
    ]
    
    # Check each pattern
    for pattern, reason, severity in suspicious_patterns:
        if pattern in path_lower:
            result['suspicious'] = True
            result['reasons'].append(reason)
            if severity == 'HIGH':
                result['severity'] = 'HIGH'
            elif severity == 'MEDIUM' and result['severity'] != 'HIGH':
                result['severity'] = 'MEDIUM'
    
    return result


def detect_unauthorized_processes() -> List[Dict]:
    """
    Main detection function - find all unauthorized/suspicious processes.
    """
    unauthorized = []
    
    # Get all running processes
    all_processes = get_all_processes()
    
    for proc in all_processes:
        reasons = []
        severity = 'LOW'
        detection_type = None
        
        proc_name = proc.get('name', '')
        proc_path = proc.get('exe_path', 'Unknown')
        
        # Check 1: Blacklisted process (HIGH priority)
        if is_process_blacklisted(proc_name):
            reasons.append(f"BLACKLISTED: {proc_name} is a known malicious process")
            severity = 'HIGH'
            detection_type = 'BLACKLISTED'
        
        # Check 2: Not whitelisted
        if not is_process_whitelisted(proc_name):
            reasons.append(f"Process '{proc_name}' not in whitelist")
            if severity != 'HIGH':
                severity = 'MEDIUM'
            if detection_type is None:
                detection_type = 'NOT_WHITELISTED'
        
        # Check 3: Suspicious path
        path_check = check_process_path(proc_path)
        if path_check['suspicious']:
            reasons.extend(path_check['reasons'])
            if path_check['severity'] == 'HIGH':
                severity = 'HIGH'
            if detection_type is None:
                detection_type = 'SUSPICIOUS_PATH'
        
        # Only add if there are findings
        if reasons:
            unauthorized.append({
                'pid': proc['pid'],
                'name': proc_name,
                'path': proc_path,
                'username': proc.get('username', 'Unknown'),
                'detection_type': detection_type,
                'reasons': reasons,
                'severity': severity
            })
    
    return unauthorized


def generate_baseline() -> None:
    """
    Generate a baseline whitelist from currently running processes.
    
    Run this on a CLEAN system to create your initial whitelist.
    
    TODO (YOUR TASK): Implement baseline generation
    
    Steps:
    1. Get all running processes
    2. Extract unique process names
    3. Save to whitelist.json in config directory
    
    IMPORTANT: Only run on a known-clean system!
    """
    print("Generating process baseline...")
    
    # TODO: YOUR CODE HERE
    # 1. Get all processes
    # 2. Extract unique names
    # 3. Create config directory if needed
    # 4. Write to WHITELIST_FILE as JSON
    
    print("TODO: Implement generate_baseline() function!")


# ============================================================
# TEST CODE
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("UNAUTHORIZED PROCESS DETECTOR TEST")
    print("=" * 60)
    
    # Test 1: Whitelist loading
    print("\n[TEST 1] Loading whitelist...")
    whitelist = load_whitelist()
    print(f"  Loaded {len(whitelist)} whitelisted processes")
    print(f"  Sample: {list(whitelist)[:5]}")
    
    # Test 2: Check known process
    print("\n[TEST 2] Checking known processes...")
    test_processes = ["explorer.exe", "svchost.exe", "definitely_malware.exe"]
    for proc in test_processes:
        is_wl = is_process_whitelisted(proc)
        is_bl = is_process_blacklisted(proc)
        print(f"  {proc}: Whitelisted={is_wl}, Blacklisted={is_bl}")
    
    # Test 3: YOUR TODO - Detect unauthorized
    print("\n[TEST 3] Detecting unauthorized processes...")
    unauthorized = detect_unauthorized_processes()
    if unauthorized:
        print(f"  Found {len(unauthorized)} potential issues:")
        for proc in unauthorized[:5]:  # Show first 5
            print(f"  🚨 {proc.get('name')} - {proc.get('reasons')}")
    else:
        print("  TODO: Implement detect_unauthorized_processes() function!")
        print("  (Or all processes are whitelisted - which is unlikely)")
    
    # Test 4: Baseline generation hint
    print("\n[TEST 4] Baseline generation...")
    print("  Run generate_baseline() on a clean system to create whitelist.json")
    print(f"  Config directory: {CONFIG_DIR}")
    
    print("\n" + "=" * 60)
