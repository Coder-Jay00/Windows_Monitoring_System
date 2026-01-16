"""
Process Monitor Module - STARTER CODE PROVIDED
This module handles process enumeration and basic info gathering.

YOU SHOULD UNDERSTAND:
- How psutil.process_iter() works
- What information each process attribute provides
- How to handle permission errors gracefully
"""

import psutil
from datetime import datetime
from typing import List, Dict, Optional


def get_all_processes() -> List[Dict]:
    """
    Enumerate all running processes and return their details.
    
    Returns:
        List of dictionaries containing process information
    
    STUDY THIS FUNCTION - Understand each attribute being collected
    """
    processes = []
    
    # process_iter() is more efficient than iterating manually
    # We specify attrs to fetch only what we need (faster)
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'username', 'create_time']):
        try:
            # Get basic info from the cached attrs
            pinfo = proc.info
            
            # Get additional info that requires separate calls
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = "Access Denied"
            
            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = []
            
            # Convert creation time to readable format
            create_time = datetime.fromtimestamp(pinfo['create_time']).strftime('%Y-%m-%d %H:%M:%S') if pinfo['create_time'] else "Unknown"
            
            process_data = {
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'ppid': pinfo['ppid'],
                'username': pinfo['username'],
                'exe_path': exe_path,
                'cmdline': cmdline,
                'create_time': create_time
            }
            
            processes.append(process_data)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process may have terminated or we don't have access
            # This is normal, just skip
            continue
    
    return processes


def get_process_by_pid(pid: int) -> Optional[Dict]:
    """
    Get detailed information about a specific process by PID.
    
    Args:
        pid: Process ID to look up
        
    Returns:
        Dictionary with process info, or None if not found
        
    TODO (YOUR TASK): Add more attributes like:
    - Memory usage (proc.memory_info())
    - CPU usage (proc.cpu_percent())
    - Open files (proc.open_files())
    - Network connections (proc.connections())
    """
    try:
        proc = psutil.Process(pid)
        
        return {
            'pid': proc.pid,
            'name': proc.name(),
            'ppid': proc.ppid(),
            'exe_path': proc.exe(),
            'cmdline': proc.cmdline(),
            'username': proc.username(),
            'status': proc.status(),
            'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            # TODO: Add memory_info, cpu_percent, etc.
        }
        
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return {'pid': pid, 'error': 'Access Denied'}


def get_parent_process(pid: int) -> Optional[Dict]:
    """
    Get the parent process of a given PID.
    
    Args:
        pid: Process ID to find parent for
        
    Returns:
        Parent process info dictionary, or None
    """
    try:
        proc = psutil.Process(pid)
        parent = proc.parent()
        
        if parent:
            return get_process_by_pid(parent.pid)
        return None
        
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def build_process_tree() -> Dict[int, List[int]]:
    """
    Build a mapping of parent PIDs to their child PIDs.
    """
    tree = {}
    
    # Step 1: Get all processes
    all_processes = get_all_processes()
    
    # Step 2: Loop through each process
    for proc in all_processes:
        pid = proc['pid']
        ppid = proc['ppid']
        
        # Step 3: Add this PID to its parent's children list
        if ppid is not None:
            if ppid not in tree:
                tree[ppid] = []
            tree[ppid].append(pid)
    
    return tree


# ============================================================
# TEST CODE - Run this file directly to test your understanding
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PROCESS MONITOR TEST")
    print("=" * 60)
    
    # Test 1: Get all processes
    print("\n[TEST 1] Enumerating all processes...")
    all_procs = get_all_processes()
    print(f"Found {len(all_procs)} running processes")
    
    # Print first 5 for verification
    print("\nFirst 5 processes:")
    for proc in all_procs[:5]:
        print(f"  PID: {proc['pid']}, Name: {proc['name']}, PPID: {proc['ppid']}")
    
    # Test 2: Get current process (this Python script)
    import os
    current_pid = os.getpid()
    print(f"\n[TEST 2] Current process (PID: {current_pid}):")
    current = get_process_by_pid(current_pid)
    for key, value in current.items():
        print(f"  {key}: {value}")
    
    # Test 3: Get parent of current process
    print(f"\n[TEST 3] Parent of current process:")
    parent = get_parent_process(current_pid)
    if parent:
        print(f"  Parent PID: {parent.get('pid')}, Name: {parent.get('name')}")
    
    # Test 4: YOUR TODO - Build process tree
    print("\n[TEST 4] Building process tree...")
    tree = build_process_tree()
    if tree:
        print(f"Built tree with {len(tree)} parent nodes")
    else:
        print("  TODO: Implement build_process_tree() function!")
    
    print("\n" + "=" * 60)
    print("Run this file to verify your changes work correctly!")
    print("=" * 60)
