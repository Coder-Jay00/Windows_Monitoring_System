# Windows Monitoring Agent - Architecture & Flow Diagrams

## 1. System Architecture

```mermaid
graph TB
    subgraph "Main Entry Point"
        A[main.py] --> B{Command Args}
    end
    
    subgraph "Detection Modules"
        B -->|--full| C[Full Scan]
        C --> D[process_monitor.py]
        C --> E[parent_child_detector.py]
        C --> F[service_auditor.py]
        C --> G[unauthorized_detector.py]
    end
    
    subgraph "Data Sources"
        D --> H[(psutil API)]
        E --> H
        F --> I[(WMI Service)]
        G --> J[(Config Files)]
    end
    
    subgraph "Output"
        D --> K[report_generator.py]
        E --> K
        F --> K
        G --> K
        K --> L[Console Report]
        K --> M[JSON Report]
    end
```

---

## 2. Main Workflow Flowchart

```mermaid
flowchart TD
    START([START]) --> A[Initialize Agent]
    A --> B[Parse Command Line Args]
    B --> C{Scan Mode?}
    
    C -->|--full| D[Run Full Scan]
    C -->|--quick| E[Run Quick Scan]
    C -->|--baseline| F[Generate Baseline]
    C -->|None| G[Show Help]
    
    D --> H[Step 1: Enumerate Processes]
    H --> I[Step 2: Analyze Parent-Child]
    I --> J[Step 3: Audit Services]
    J --> K[Step 4: Detect Unauthorized]
    K --> L[Step 5: Generate Report]
    
    L --> M[Display Console Report]
    M --> N[Save JSON Report]
    N --> END([END])
    
    E --> I
    F --> O[Capture Current Processes]
    O --> P[Save to whitelist.json]
    P --> END
    G --> END
```

---

## 3. Parent-Child Detection Flow

```mermaid
flowchart TD
    A[Get All Processes] --> B[For Each Process]
    B --> C[Get Parent Process Info]
    C --> D{Parent Exists?}
    
    D -->|No| B
    D -->|Yes| E[Check Relationship Rules]
    
    E --> F{Suspicious Combo?}
    F -->|No| B
    F -->|Yes| G[Record Finding]
    
    G --> H[Add to Findings List]
    H --> B
    
    B --> I{More Processes?}
    I -->|Yes| B
    I -->|No| J[Return Findings]
    
    subgraph "Suspicious Rules"
        R1["winword.exe → cmd.exe"]
        R2["excel.exe → powershell.exe"]
        R3["outlook.exe → cmd.exe"]
        R4["mshta.exe → powershell.exe"]
    end
```

---

## 4. Service Audit Flow

```mermaid
flowchart TD
    A[Query WMI Win32_Service] --> B[Get All Services]
    B --> C[For Each Service]
    
    C --> D{Check Path}
    D -->|Suspicious Location| E[Flag: Path Issue]
    D -->|Safe| F{Check Name}
    
    E --> F
    F -->|Known Malware| G[Flag: Name Match]
    F -->|Unknown| H{Check Unquoted Path}
    
    G --> H
    H -->|Vulnerable| I[Flag: Unquoted Path]
    H -->|Safe| J{Any Flags?}
    
    I --> J
    J -->|Yes| K[Add to Suspicious List]
    J -->|No| L[Skip]
    
    K --> M{More Services?}
    L --> M
    M -->|Yes| C
    M -->|No| N[Return Suspicious Services]
```

---

## 5. Unauthorized Process Detection Flow

```mermaid
flowchart TD
    A[Load Whitelist] --> B[Load Blacklist]
    B --> C[Get All Processes]
    C --> D[For Each Process]
    
    D --> E{Blacklisted?}
    E -->|Yes| F["🚨 HIGH: Add to Findings"]
    E -->|No| G{Whitelisted?}
    
    G -->|Yes| H[Skip - Safe]
    G -->|No| I["⚠️ MEDIUM: Not Whitelisted"]
    
    I --> J{Suspicious Path?}
    J -->|Yes| K["🚨 HIGH: Path Alert"]
    J -->|No| L[Add Finding]
    
    F --> M{More Processes?}
    K --> L
    L --> M
    H --> M
    
    M -->|Yes| D
    M -->|No| N[Return All Findings]
```

---

## 6. Component Diagram

```mermaid
graph LR
    subgraph "User Interface"
        CLI[Command Line Interface]
    end
    
    subgraph "Core Modules"
        PM[Process Monitor]
        PCD[Parent-Child Detector]
        SA[Service Auditor]
        UD[Unauthorized Detector]
    end
    
    subgraph "Configuration"
        WL[(whitelist.json)]
        BL[(blacklist.json)]
    end
    
    subgraph "External APIs"
        PS[(psutil)]
        WMI[(WMI)]
    end
    
    subgraph "Output"
        CR[Console Report]
        JR[JSON Report]
    end
    
    CLI --> PM
    CLI --> PCD
    CLI --> SA
    CLI --> UD
    
    PM --> PS
    PCD --> PS
    SA --> WMI
    UD --> PS
    UD --> WL
    UD --> BL
    
    PM --> CR
    PCD --> CR
    SA --> CR
    UD --> CR
    CR --> JR
```

---

## 7. Detection Rules Summary

| Detection Type | Parent Process | Child Process | Severity | Reason |
|---------------|----------------|---------------|----------|--------|
| Macro Attack | winword.exe | cmd.exe | HIGH | Office spawning shell |
| Macro Attack | excel.exe | powershell.exe | HIGH | Office spawning shell |
| Phishing | outlook.exe | powershell.exe | HIGH | Email client spawning shell |
| Browser Exploit | chrome.exe | cmd.exe | HIGH | Browser spawning shell |
| LOLBin Abuse | mshta.exe | powershell.exe | HIGH | Script host abuse |
| Service Exploit | svchost.exe | cmd.exe | HIGH | Service spawning shell |

---

## How to Use These Diagrams

### Option 1: Mermaid Live Editor
1. Go to https://mermaid.live
2. Copy any diagram code block
3. Paste and export as PNG/SVG

### Option 2: Draw.io
1. Go to https://draw.io
2. Create new diagram
3. Manually recreate based on these flows

### Option 3: VS Code Extension
1. Install "Markdown Preview Mermaid Support" extension
2. Open this file
3. Preview to see rendered diagrams
