# Windows Service & Process Monitoring Agent
## Learning Project - Starter Templates

A cybersecurity monitoring tool for detecting malicious Windows process behavior.

## Project Structure
```
windows_monitoring_agent/
├── README.md                    # This file
├── LEARNING_GUIDE.md           # Concepts & interview prep
├── requirements.txt            # Python dependencies
├── config/
│   ├── whitelist.json          # Allowed processes (YOU CREATE)
│   └── detection_rules.json    # Detection rules (YOU CREATE)
├── src/
│   ├── __init__.py
│   ├── process_monitor.py      # Process enumeration (STARTER PROVIDED)
│   ├── parent_child_detector.py # Relationship analysis (YOU COMPLETE)
│   ├── service_auditor.py      # Service audit (YOU COMPLETE)
│   ├── unauthorized_detector.py # Whitelist checking (YOU COMPLETE)
│   └── report_generator.py     # Report generation (STARTER PROVIDED)
├── logs/                       # Output logs directory
└── main.py                     # Entry point (YOU COMPLETE)
```

## Setup Instructions
```powershell
# Create virtual environment
python -m venv venv

# Activate
.\venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt
```

## Your Tasks (60% of work)
1. Complete the TODO sections in each module
2. Create detection rules in config/
3. Implement the main.py orchestration
4. Test on your own system
5. Document your findings

## Running the Agent
```powershell
python main.py
```
