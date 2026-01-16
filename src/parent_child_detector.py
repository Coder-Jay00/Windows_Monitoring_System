"""
Parent-Child Process Detector - YOU COMPLETE THIS MODULE
Detects suspicious parent-child process relationships.

UNDERSTAND THESE CONCEPTS BEFORE CODING:
1. Why certain parent-child combos are suspicious
2. How malware uses process injection
3. What "living off the land" (LOLBins) means

REFERENCE:
- MITRE ATT&CK T1059 (Command and Scripting Interpreter)
- MITRE ATT&CK T1055 (Process Injection)
"""

from typing import List, Dict, Tuple
try:
    from src.process_monitor import get_all_processes, get_process_by_pid
except ImportError:
    from process_monitor import get_all_processes, get_process_by_pid


# ============================================================
# SUSPICIOUS PARENT-CHILD RULES
# These are provided for you - STUDY and UNDERSTAND them
# ============================================================

SUSPICIOUS_RELATIONSHIPS = [
    # (parent_name, child_name, reason)
    # Office Applications spawning shells - likely macro attack
    ("winword.exe", "cmd.exe", "Word spawning command prompt - possible macro attack"),
    ("winword.exe", "powershell.exe", "Word spawning PowerShell - possible macro attack"),
    ("excel.exe", "cmd.exe", "Excel spawning command prompt - possible macro attack"),
    ("excel.exe", "powershell.exe", "Excel spawning PowerShell - possible macro attack"),
    ("outlook.exe", "cmd.exe", "Outlook spawning command prompt - possible phishing"),
    ("outlook.exe", "powershell.exe", "Outlook spawning PowerShell - possible phishing"),
    
    # Browsers spawning shells - possible exploit
    ("chrome.exe", "cmd.exe", "Chrome spawning cmd - possible browser exploit"),
    ("firefox.exe", "cmd.exe", "Firefox spawning cmd - possible browser exploit"),
    ("msedge.exe", "cmd.exe", "Edge spawning cmd - possible browser exploit"),
    
    # Script hosts being abused
    ("mshta.exe", "powershell.exe", "MSHTA spawning PowerShell - common attack vector"),
    ("wscript.exe", "cmd.exe", "WScript spawning cmd - script-based attack"),
    ("cscript.exe", "powershell.exe", "CScript spawning PowerShell - script-based attack"),
    
    # Unusual spawns from Windows processes
    ("svchost.exe", "cmd.exe", "Service host spawning cmd - possible service exploitation"),
    ("wmiprvse.exe", "powershell.exe", "WMI Provider spawning PowerShell - WMI attack"),
    
    # TODO (YOUR TASK): Add 3-5 more suspicious relationships
    # Research common attack patterns and add them here
    # Examples to research: regsvr32.exe, rundll32.exe, certutil.exe
]


def check_single_relationship(parent_name: str, child_name: str) -> Tuple[bool, str]:
    """
    Check if a single parent-child relationship is suspicious.
    
    Args:
        parent_name: Name of parent process (e.g., "winword.exe")
        child_name: Name of child process (e.g., "cmd.exe")
        
    Returns:
        Tuple of (is_suspicious: bool, reason: str)
        
    EXAMPLE:
        >>> check_single_relationship("winword.exe", "cmd.exe")
        (True, "Word spawning command prompt - possible macro attack")
        
        >>> check_single_relationship("explorer.exe", "chrome.exe")
        (False, "")
    """
    # Normalize names to lowercase for comparison
    parent_lower = parent_name.lower()
    child_lower = child_name.lower()
    
    for sus_parent, sus_child, reason in SUSPICIOUS_RELATIONSHIPS:
        if parent_lower == sus_parent.lower() and child_lower == sus_child.lower():
            return (True, reason)
    
    return (False, "")


def analyze_all_relationships() -> List[Dict]:
    """
    Analyze all running processes for suspicious parent-child relationships.
    """
    suspicious_findings = []
    
    # Step 1: Get all running processes
    all_processes = get_all_processes()
    
    # Step 2: Check each process
    for proc in all_processes:
        child_pid = proc['pid']
        child_name = proc['name']
        child_path = proc.get('exe_path', 'Unknown')
        ppid = proc['ppid']
        
        # Skip if no parent
        if ppid is None:
            continue
        
        # Step 3: Get parent process info
        parent_info = get_process_by_pid(ppid)
        
        if parent_info is None:
            continue
        
        parent_name = parent_info.get('name', 'Unknown')
        parent_path = parent_info.get('exe_path', 'Unknown')
        
        # Step 4: Check if this relationship is suspicious
        is_suspicious, reason = check_single_relationship(parent_name, child_name)
        
        # Step 5: If suspicious, add to findings
        if is_suspicious:
            finding = {
                'child_pid': child_pid,
                'child_name': child_name,
                'child_path': child_path,
                'parent_pid': ppid,
                'parent_name': parent_name,
                'parent_path': parent_path,
                'reason': reason,
                'severity': 'HIGH'
            }
            suspicious_findings.append(finding)
    
    return suspicious_findings


def detect_deep_process_chains() -> List[Dict]:
    """
    Detect suspiciously deep process chains (process spawning many children in chain).
    
    Some malware creates long chains like:
    cmd.exe -> powershell.exe -> cmd.exe -> wscript.exe -> ...
    
    TODO (YOUR TASK): Implement this detection
    
    Approach:
    1. Build a process tree (use build_process_tree from process_monitor)
    2. For each process, trace its ancestry (walk up the parent chain)
    3. If chain depth > threshold (e.g., 5), flag as suspicious
    4. Return processes with unusually deep chains
    """
    deep_chains = []
    
    # TODO: YOUR CODE HERE
    
    return deep_chains


def get_process_ancestry(pid: int, max_depth: int = 10) -> List[Dict]:
    """Get the full ancestry chain of a process."""
    ancestry = []
    current_pid = pid
    depth = 0
    
    while current_pid is not None and depth < max_depth:
        proc_info = get_process_by_pid(current_pid)
        
        if proc_info is None:
            break
        
        ancestry.append(proc_info)
        current_pid = proc_info.get('ppid')
        depth += 1
        
        if current_pid is None or current_pid == 0 or current_pid == 4:
            break
    
    return ancestry


# ============================================================
# TEST CODE
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PARENT-CHILD DETECTOR TEST")
    print("=" * 60)
    
    # Test 1: Check known suspicious relationship
    print("\n[TEST 1] Testing known suspicious relationship:")
    is_sus, reason = check_single_relationship("winword.exe", "powershell.exe")
    print(f"  winword.exe -> powershell.exe")
    print(f"  Suspicious: {is_sus}")
    print(f"  Reason: {reason}")
    
    # Test 2: Check normal relationship
    print("\n[TEST 2] Testing normal relationship:")
    is_sus, reason = check_single_relationship("explorer.exe", "chrome.exe")
    print(f"  explorer.exe -> chrome.exe")
    print(f"  Suspicious: {is_sus}")
    
    # Test 3: YOUR TODO - Analyze all relationships
    print("\n[TEST 3] Analyzing all process relationships...")
    findings = analyze_all_relationships()
    if findings:
        print(f"  Found {len(findings)} suspicious relationships!")
        for finding in findings[:3]:  # Show first 3
            print(f"  - {finding}")
    else:
        print("  TODO: Implement analyze_all_relationships() function!")
    
    # Test 4: YOUR TODO - Get ancestry of current process
    import os
    print(f"\n[TEST 4] Getting ancestry of current process (PID: {os.getpid()})...")
    ancestry = get_process_ancestry(os.getpid())
    if ancestry:
        print("  Ancestry chain:")
        for i, proc in enumerate(ancestry):
            print(f"    {'  ' * i}-> {proc.get('name')} (PID: {proc.get('pid')})")
    else:
        print("  TODO: Implement get_process_ancestry() function!")
    
    print("\n" + "=" * 60)
