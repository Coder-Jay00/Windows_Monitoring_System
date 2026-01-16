# Learning Guide & Interview Preparation

## 🎓 Core Concepts You MUST Understand

### 1. Windows Process Architecture

**What is a Process?**
- A running instance of a program
- Has its own memory space, resources, and at least one thread
- Identified by a unique Process ID (PID)

**Key Process Attributes:**
| Attribute | Description | How to Get (Python) |
|-----------|-------------|---------------------|
| PID | Unique process identifier | `process.pid` |
| PPID | Parent Process ID | `process.ppid()` |
| Name | Executable name | `process.name()` |
| Exe Path | Full path to executable | `process.exe()` |
| Cmdline | Command line arguments | `process.cmdline()` |
| Username | User running the process | `process.username()` |
| Create Time | When process started | `process.create_time()` |

**Interview Question**: "What is the difference between a process and a thread?"
> A process is an independent program with its own memory space. A thread is a unit of execution within a process that shares the process's memory. A process can have multiple threads.

---

### 2. Parent-Child Process Relationships

**How it works:**
- Every process (except System) has a parent that created it
- Parent spawns child using `CreateProcess()` API
- Child inherits certain properties from parent

**Normal Relationships:**
```
explorer.exe → chrome.exe      ✅ (User opened browser)
services.exe → svchost.exe     ✅ (System service)
cmd.exe → python.exe           ✅ (User ran script)
```

**Suspicious Relationships:**
```
winword.exe → cmd.exe          🚨 (Macro attack)
excel.exe → powershell.exe     🚨 (Malicious macro)
outlook.exe → mshta.exe        🚨 (Phishing payload)
svchost.exe → cmd.exe          🚨 (Service exploitation)
```

**Interview Question**: "Why is winword.exe spawning powershell.exe suspicious?"
> Microsoft Word is a document editor, not a shell launcher. If Word spawns PowerShell, it likely means a malicious macro is executing commands. Legitimate Word usage never requires spawning system shells.

---

### 3. Windows Services

**What are Services?**
- Background programs that run without user interaction
- Start automatically at boot (usually)
- Run with SYSTEM privileges (very powerful)

**Service States:**
- Running, Stopped, Paused, Starting, Stopping

**Why Attackers Target Services:**
1. **Persistence** - Services restart after reboot
2. **Privileges** - Often run as SYSTEM
3. **Stealth** - Users don't see services in taskbar

**Suspicious Service Indicators:**
- Running from `%TEMP%` or user directories
- Recently created/modified services
- Unusual service names
- Unsigned executables

**Interview Question**: "How would an attacker use a Windows service for persistence?"
> An attacker can create a malicious service using `sc create` or registry modification. The service runs their malware with SYSTEM privileges and automatically restarts after reboot, maintaining persistent access.

---

### 4. Detection Techniques

**A. Whitelist-Based Detection**
```
Known Good Processes → Allow
Unknown Process → Alert
```
Pros: Simple, low false positives for known-good
Cons: Can't detect new legitimate software

**B. Blacklist-Based Detection**
```
Known Bad Processes → Block/Alert
Everything Else → Allow
```
Pros: Catches known malware
Cons: Misses new malware (zero-day)

**C. Behavior-Based Detection**
```
Process does suspicious action → Alert
```
Pros: Can catch unknown malware
Cons: Higher false positives

**Interview Question**: "What is the difference between signature-based and behavior-based detection?"
> Signature-based detection matches against known malware hashes/patterns (like antivirus). Behavior-based detection monitors actions (like a Word doc spawning PowerShell) regardless of the specific malware. Behavior-based can catch zero-day attacks.

---

## 🔧 Python Libraries Deep Dive

### psutil - Process and System Utilities

```python
import psutil

# Get all processes
for proc in psutil.process_iter(['pid', 'name', 'ppid']):
    print(proc.info)

# Get specific process info
p = psutil.Process(1234)  # by PID
print(p.name())           # Process name
print(p.exe())            # Executable path
print(p.parent())         # Parent process object
print(p.children())       # List of child processes
```

**YOUR TASK**: Read psutil documentation and understand:
- `process_iter()` - How to iterate efficiently
- `Process.parent()` - Getting parent process
- Error handling for `NoSuchProcess`, `AccessDenied`

Documentation: https://psutil.readthedocs.io/

---

### WMI - Windows Management Instrumentation

```python
import wmi

c = wmi.WMI()

# Get all services
for service in c.Win32_Service():
    print(service.Name, service.State, service.PathName)

# Get all processes with more details
for process in c.Win32_Process():
    print(process.ProcessId, process.Name, process.ExecutablePath)
```

**YOUR TASK**: Understand WMI queries for:
- `Win32_Service` - Service enumeration
- `Win32_Process` - Process details
- `Win32_StartupCommand` - Startup programs

Documentation: https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page

---

## 📝 Interview Questions & Answers

### Technical Questions

**Q1: How does your tool detect malicious parent-child relationships?**
> I maintain a rule set of suspicious parent-child combinations. For each running process, I retrieve its parent using psutil. If the combination matches a known malicious pattern (like Office apps spawning shells), I generate an alert with details.

**Q2: What if a legitimate process triggers a false positive?**
> I implement a whitelist system. Users can add known-good processes or specific parent-child combinations to reduce false positives. The tool also logs context (path, user, timestamp) so analysts can investigate.

**Q3: How do you enumerate Windows services in Python?**
> I use the WMI library to query Win32_Service class. This gives me service name, display name, state, start mode, and executable path. I can also use the win32service module for lower-level access.

**Q4: What makes a service suspicious?**
> Key indicators include:
> - Running from temporary or user-writable directories
> - Unsigned executables
> - Recently created services (check registry timestamps)
> - Services with names similar to system services (typosquatting)
> - Services running under unusual accounts

**Q5: How would you handle access denied errors when reading process info?**
> Some system processes require elevated privileges. I wrap process queries in try-except blocks, catch AccessDenied exceptions, and either skip those processes or log that elevated access is needed. Running as Administrator helps.

### Scenario-Based Questions

**Q6: You see cmd.exe spawned from svchost.exe. Is this malicious?**
> Potentially. svchost.exe hosts Windows services, and some legitimate services might spawn cmd.exe for tasks. However, it's unusual and warrants investigation. I'd check:
> - Which service instance of svchost (using -k parameter)
> - What command cmd.exe is running
> - The timing and frequency

**Q7: A new service appeared on the system yesterday. How do you investigate?**
> I would:
> 1. Check the service's executable path and verify the binary
> 2. Look up the file hash on VirusTotal
> 3. Check if the executable is signed
> 4. Review the service's registry entries for creation time
> 5. Examine the user/process that created the service
> 6. Compare against a known-good baseline

---

## 🧪 Testing Your Understanding

Before you write code, answer these (write your answers!):

1. What psutil function gives you all running processes?
   YOUR ANSWER: _______________

2. How do you get a process's parent process ID?
   YOUR ANSWER: _______________

3. What WMI class contains Windows service information?
   YOUR ANSWER: _______________

4. Name 3 suspicious parent-child process combinations:
   YOUR ANSWER: _______________

5. Why would malware run from %TEMP%?
   YOUR ANSWER: _______________

---

## 📚 Required Reading (Do This!)

1. **psutil Documentation**
   https://psutil.readthedocs.io/en/latest/

2. **MITRE ATT&CK - Persistence Techniques**
   https://attack.mitre.org/tactics/TA0003/

3. **MITRE ATT&CK - Defense Evasion**
   https://attack.mitre.org/tactics/TA0005/

4. **Windows Process Internals**
   https://docs.microsoft.com/en-us/sysinternals/

5. **Sigma Rules (Detection Rules Format)**
   https://github.com/SigmaHQ/sigma
