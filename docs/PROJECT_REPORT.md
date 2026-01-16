# Windows Service & Process Monitoring Agent
## Project Report

---

### Submitted By
**Name:** Jay Thakkar  
**Year:** Third Year (B.E. Computer Science Engineering)  
**Academic Year:** 2024-2027

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [Objectives](#4-objectives)
5. [Literature Review](#5-literature-review)
6. [System Architecture](#6-system-architecture)
7. [Methodology](#7-methodology)
8. [Implementation](#8-implementation)
9. [Detection Techniques](#9-detection-techniques)
10. [Results & Testing](#10-results--testing)
11. [Future Enhancements](#11-future-enhancements)
12. [Conclusion](#12-conclusion)
13. [References](#13-references)

---

## 1. Abstract

This project presents a **Windows Service & Process Monitoring Agent** designed to detect malicious, unauthorized, or suspicious process behavior on Windows operating systems. The monitoring agent analyzes service configurations, process hierarchies, startup entries, and runtime activity to identify security anomalies.

The system implements three core detection mechanisms:
1. **Parent-Child Relationship Analysis** - Detecting suspicious process spawning patterns
2. **Windows Service Auditing** - Identifying malicious or misconfigured services
3. **Unauthorized Process Detection** - Whitelist/blacklist-based process monitoring

The agent provides real-time detection capabilities with comprehensive reporting in both console and JSON formats, making it suitable for Security Operations Center (SOC) environments and incident response activities.

**Keywords:** Windows Security, Process Monitoring, Malware Detection, Service Auditing, Blue Team, Digital Forensics

---

## 2. Introduction

### 2.1 Background

Windows operating systems are the most widely deployed desktop operating systems globally, making them a primary target for malware authors and cyber attackers. Modern threats increasingly rely on sophisticated techniques to evade traditional antivirus solutions, including:

- **Living off the Land (LotL)** - Abusing legitimate Windows tools for malicious purposes
- **Process Injection** - Hiding malicious code within legitimate processes
- **Service Persistence** - Installing malicious services for long-term access
- **Fileless Malware** - Operating entirely in memory without disk artifacts

Traditional signature-based detection methods struggle against these evolving threats, necessitating behavior-based monitoring solutions that can identify suspicious activity patterns rather than known malware signatures.

### 2.2 Motivation

The motivation for this project stems from:

1. **Increasing Sophistication of Attacks** - Modern malware uses advanced evasion techniques
2. **Need for Proactive Defense** - Detecting threats before damage occurs
3. **Educational Value** - Understanding Windows internals and security mechanisms
4. **Practical SOC Experience** - Building real-world applicable security tools

### 2.3 Scope

This project covers:
- Process enumeration and monitoring on Windows systems
- Parent-child process relationship analysis
- Windows service configuration auditing
- Whitelist/blacklist-based unauthorized process detection
- Alert generation and reporting

---

## 3. Problem Statement

Windows systems are frequently compromised through various attack vectors that abuse legitimate system functionality:

| Attack Vector | Description | Impact |
|---------------|-------------|--------|
| Malicious Services | Services registered under system privileges | Persistence, Privilege Escalation |
| Abnormal Process Relationships | Unusual parent-child process chains | Malware Execution, Detection Evasion |
| Startup Manipulation | Modifying startup entries | Persistence |
| Process Masquerading | Rogue processes mimicking legitimate names | Stealth Operations |

**The core problem addressed:**  
How can we effectively detect and alert on suspicious process behavior and service configurations in real-time without relying solely on signature-based detection?

---

## 4. Objectives

### Primary Objectives

1. **Monitor Active Windows Processes**
   - Enumerate all running processes with detailed attributes
   - Track process lineage (parent-child relationships)
   - Analyze process behavior patterns

2. **Audit Startup Services**
   - Enumerate all Windows services
   - Identify suspicious service configurations
   - Detect newly registered or modified services

3. **Detect Unauthorized Processes**
   - Implement whitelist-based detection
   - Maintain blacklist of known malicious processes
   - Identify processes running from suspicious locations

4. **Generate Actionable Alerts**
   - Provide severity-based alert classification
   - Generate detailed detection reports
   - Export findings in machine-readable format (JSON)

### Learning Objectives

- Understand Windows process architecture and service internals
- Implement rule-based and behavior-based detection logic
- Gain practical experience with Python for security tooling
- Develop skills applicable to SOC and incident response roles

---

## 5. Literature Review

### 5.1 Windows Process Architecture

Windows processes are fundamental units of execution, each containing:
- **Process ID (PID)** - Unique identifier
- **Parent Process ID (PPID)** - Process that created this process
- **Executable Path** - Location of the binary on disk
- **Command Line** - Arguments passed during execution
- **Security Context** - User account and privileges

Understanding process relationships is crucial for threat detection. Legitimate process hierarchies follow predictable patterns (e.g., explorer.exe spawning user applications), while malicious activity often creates anomalous chains.

### 5.2 MITRE ATT&CK Framework

The project aligns with several MITRE ATT&CK techniques:

| Technique ID | Name | Our Detection |
|--------------|------|---------------|
| T1059 | Command and Scripting Interpreter | Parent-child analysis |
| T1543.003 | Windows Service | Service auditing |
| T1055 | Process Injection | Process ancestry tracking |
| T1036 | Masquerading | Unauthorized process detection |

### 5.3 Related Work

- **Sysmon** - Microsoft's system monitoring tool for advanced logging
- **Process Monitor** - Sysinternals tool for real-time process monitoring
- **YARA** - Pattern matching tool for malware detection
- **Sigma Rules** - Generic signature format for detection rules

Our project builds upon these concepts to create an educational, customizable monitoring solution.

---

## 6. System Architecture

### 6.1 High-Level Architecture

![Architecture Diagram](docs/architecture_diagram.png)

The system follows a modular architecture with four primary detection modules:

```
┌─────────────────────────────────────────────────────────────┐
│                      main.py (Entry Point)                   │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   Process    │  │ Parent-Child │  │    Service       │   │
│  │   Monitor    │  │   Detector   │  │    Auditor       │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │                 │                    │             │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌────────┴─────────┐   │
│  │ Unauthorized │  │    psutil    │  │       WMI        │   │
│  │   Detector   │  │     API      │  │     Service      │   │
│  └──────┬───────┘  └──────────────┘  └──────────────────┘   │
│         │                                                    │
│  ┌──────┴────────────────────────────────────────────────┐  │
│  │              Report Generator                          │  │
│  │         (Console Output + JSON Export)                 │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Module Descriptions

| Module | File | Responsibility |
|--------|------|----------------|
| Process Monitor | `process_monitor.py` | Process enumeration, tree building |
| Parent-Child Detector | `parent_child_detector.py` | Suspicious relationship detection |
| Service Auditor | `service_auditor.py` | Windows service analysis |
| Unauthorized Detector | `unauthorized_detector.py` | Whitelist/blacklist checking |
| Report Generator | `report_generator.py` | Output formatting and export |

### 6.3 Data Flow

![Workflow Flowchart](docs/workflow_flowchart.png)

---

## 7. Methodology

### 7.1 Development Approach

The project followed an **incremental development methodology**:

1. **Research Phase** - Study Windows internals, existing tools, attack techniques
2. **Design Phase** - Define architecture, detection rules, data structures
3. **Implementation Phase** - Develop modules incrementally with testing
4. **Testing Phase** - Validate detection capabilities on test scenarios
5. **Documentation Phase** - Create comprehensive project documentation

### 7.2 Detection Methodology

#### Parent-Child Detection
- Maintain a rule set of suspicious parent-child combinations
- For each running process, retrieve parent information
- Compare against detection rules
- Flag matches with severity and context

#### Service Auditing
- Query WMI for all Windows services
- Check executable paths against suspicious patterns
- Identify unquoted service paths (security vulnerability)
- Flag services running from non-standard locations

#### Unauthorized Process Detection
- Load whitelist of known-good processes
- Load blacklist of known-bad processes
- For each running process, check membership
- Analyze executable paths for suspicious indicators

---

## 8. Implementation

### 8.1 Technologies Used

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Python 3.11 | Core implementation |
| Process API | psutil | Process enumeration |
| Windows API | WMI | Service querying |
| Win32 | pywin32 | Windows integration |
| Output | colorama | Console formatting |

### 8.2 Project Structure

```
windows_monitoring_agent/
├── main.py                      # Entry point with CLI
├── requirements.txt             # Python dependencies
├── config/
│   ├── whitelist.json          # Allowed processes
│   └── blacklist.json          # Known malicious processes
├── src/
│   ├── process_monitor.py      # Process enumeration
│   ├── parent_child_detector.py # Relationship analysis
│   ├── service_auditor.py      # Service auditing
│   ├── unauthorized_detector.py # Whitelist checking
│   └── report_generator.py     # Report generation
├── logs/                        # Detection reports
└── docs/                        # Documentation
```

### 8.3 Key Functions Implemented

#### Process Enumeration
```python
def get_all_processes() -> List[Dict]:
    """Enumerate all running processes with details."""
    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        # Collect process information
```

#### Parent-Child Analysis
```python
def analyze_all_relationships() -> List[Dict]:
    """Check all processes for suspicious parent-child combos."""
    for proc in all_processes:
        is_suspicious, reason = check_single_relationship(
            parent_name, child_name
        )
```

#### Service Auditing
```python
def get_all_services_wmi() -> List[Dict]:
    """Query Windows services via WMI."""
    c = wmi.WMI()
    for service in c.Win32_Service():
        # Extract service details
```

---

## 9. Detection Techniques

### 9.1 Suspicious Parent-Child Rules

| Parent Process | Child Process | Reason | Severity |
|----------------|---------------|--------|----------|
| winword.exe | cmd.exe | Macro attack | HIGH |
| winword.exe | powershell.exe | Macro attack | HIGH |
| excel.exe | cmd.exe | Macro attack | HIGH |
| excel.exe | powershell.exe | Macro attack | HIGH |
| outlook.exe | powershell.exe | Phishing payload | HIGH |
| chrome.exe | cmd.exe | Browser exploit | HIGH |
| mshta.exe | powershell.exe | LOLBin abuse | HIGH |
| svchost.exe | cmd.exe | Service exploitation | HIGH |

### 9.2 Suspicious Path Patterns

Services and processes running from these locations are flagged:
- `\Users\` - User directories
- `\AppData\` - Application data
- `\Temp\` - Temporary folders
- `\Downloads\` - Downloads folder
- `\Desktop\` - Desktop

### 9.3 Unquoted Service Path Detection

Unquoted service paths with spaces create security vulnerabilities:
```
Vulnerable: C:\Program Files\My App\service.exe
Safe:       "C:\Program Files\My App\service.exe"
```

---

## 10. Results & Testing

### 10.1 Test Environment

- **Operating System:** Windows 11
- **Python Version:** 3.11
- **Test Date:** January 2026

### 10.2 Sample Detection Output

```
╔══════════════════════════════════════════════════════════════╗
║     WINDOWS SERVICE & PROCESS MONITORING AGENT               ║
║     Cybersecurity Detection Tool                             ║
╚══════════════════════════════════════════════════════════════╝

[*] Starting full system scan at 2026-01-16 16:40:20
[*] This may take a few moments...

[1/3] Analyzing parent-child relationships...
[2/3] Auditing Windows services...
[3/3] Detecting unauthorized processes...

─── PARENT-CHILD ANOMALIES ───
✓ No suspicious parent-child relationships

─── SUSPICIOUS SERVICES ───
[MEDIUM] Service: WSearch
    Path: C:\WINDOWS\system32\SearchIndexer.exe
    Reasons: Unquoted service path - potential hijacking vulnerability

─── UNAUTHORIZED PROCESSES ───
[MEDIUM] Process: OfficeClickToRun.exe
    Type: NOT_WHITELISTED
    Reasons: Process 'OfficeClickToRun.exe' not in whitelist

Summary: 172 findings | HIGH: 0 | MEDIUM: 170 | LOW: 2
```

### 10.3 Performance Metrics

| Metric | Value |
|--------|-------|
| Process Enumeration Time | < 2 seconds |
| Service Query Time | < 3 seconds |
| Total Scan Time | < 10 seconds |
| Processes Analyzed | ~200 per scan |
| Services Audited | ~319 services |

---

## 11. Future Enhancements

### Short-Term Improvements
- [ ] Continuous monitoring mode with configurable intervals
- [ ] Email/SMS alert integration
- [ ] Baseline generation from clean system
- [ ] GUI interface for non-technical users

### Long-Term Goals
- [ ] Machine learning-based anomaly detection
- [ ] Network connection monitoring
- [ ] Registry modification tracking
- [ ] Integration with SIEM platforms
- [ ] Cross-platform support (Linux, macOS)

---

## 12. Conclusion

This project successfully demonstrates the development of a Windows security monitoring tool capable of detecting suspicious process behavior and service configurations. The implementation provides practical experience with:

1. **Windows Internals** - Understanding process architecture and service management
2. **Security Engineering** - Implementing detection logic and alert mechanisms
3. **Python Development** - Building modular, maintainable security tools
4. **Blue Team Operations** - Developing defensive security capabilities

The monitoring agent serves as both an educational tool for understanding threat detection techniques and a foundation for more advanced security monitoring solutions.

---

## 13. References

1. Microsoft Docs. (2024). *Windows Process Architecture*. https://docs.microsoft.com/en-us/windows/
2. MITRE. (2024). *ATT&CK Framework*. https://attack.mitre.org/
3. Sysinternals. (2024). *Process Monitor*. https://docs.microsoft.com/en-us/sysinternals/
4. psutil Documentation. (2024). https://psutil.readthedocs.io/
5. Python WMI Module. (2024). http://timgolden.me.uk/python/wmi/
6. SANS Institute. (2024). *Windows Forensic Analysis*. https://www.sans.org/

---

## Appendix A: Installation Guide

```powershell
# Clone or download the project
cd windows_monitoring_agent

# Create virtual environment
python -m venv venv

# Activate environment
.\venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt

# Run full scan
python main.py --full
```

---

## Appendix B: Command Line Options

| Option | Description |
|--------|-------------|
| `--full` | Run complete system scan |
| `--quick` | Run quick parent-child scan only |
| `--baseline` | Generate process whitelist baseline |
| `--continuous` | Run continuous monitoring |
| `--interval N` | Set monitoring interval (seconds) |
| `--json` | Export results to JSON |

---

<div align="center">

## Project Credits

**Developed By:** Jay Thakkar  
**Course:** Cyber Security & Digital Forensics  
**Year:** Third Year, B.E. Computer Science Engineering  
**Academic Year:** 2024-2027

---

*This project was developed as part of academic coursework in Cyber Security and Digital Forensics.*

</div>
