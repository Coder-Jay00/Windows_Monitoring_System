"""
Windows Monitoring Agent - Main Entry Point
YOU COMPLETE THIS FILE - This orchestrates all modules

UNDERSTAND:
- How to import and use modules
- How to handle command-line arguments
- How to structure a complete application
"""

import sys
import argparse
from datetime import datetime

# Import your modules
from src.process_monitor import get_all_processes, build_process_tree
from src.parent_child_detector import analyze_all_relationships
from src.service_auditor import detect_suspicious_services
from src.unauthorized_detector import detect_unauthorized_processes
from src.report_generator import generate_console_report, save_json_report


def print_banner():
    """Print application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║     WINDOWS SERVICE & PROCESS MONITORING AGENT               ║
    ║     Cybersecurity Detection Tool                             ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_full_scan():
    """Run a complete system scan with all detection modules."""
    print(f"\n[*] Starting full system scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] This may take a few moments...\n")
    
    # Step 1: Parent-Child Analysis
    print("[1/3] Analyzing parent-child relationships...")
    parent_child_findings = analyze_all_relationships()
    
    # Step 2: Service Audit
    print("[2/3] Auditing Windows services...")
    service_findings = detect_suspicious_services()
    
    # Step 3: Unauthorized Process Detection
    print("[3/3] Detecting unauthorized processes...")
    unauthorized_findings = detect_unauthorized_processes()
    
    # Generate Console Report
    generate_console_report(parent_child_findings, service_findings, unauthorized_findings)
    
    # Save JSON Report
    save_json_report(parent_child_findings, service_findings, unauthorized_findings)
    #         time.sleep(interval)
    # except KeyboardInterrupt:
    #     print("\n[*] Monitoring stopped by user")
    
    print("TODO: Implement run_continuous_monitoring() function!")


def generate_baseline():
    """
    Generate baseline whitelist from current system state.
    
    TODO (YOUR TASK): Call the baseline generator from unauthorized_detector
    """
    print("[*] Generating process baseline...")
    print("[*] Run this on a CLEAN system only!")
    
    # TODO: Call generate_baseline from unauthorized_detector
    
    print("TODO: Implement baseline generation!")


def main():
    """
    Main entry point - handle command-line arguments.
    
    TODO (YOUR TASK): Complete the argument handling
    """
    parser = argparse.ArgumentParser(
        description='Windows Service & Process Monitoring Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --full          Run a complete system scan
  python main.py --quick         Run quick parent-child scan only
  python main.py --continuous    Run continuous monitoring
  python main.py --baseline      Generate process whitelist baseline
        """
    )
    
    parser.add_argument('--full', action='store_true', help='Run full system scan')
    parser.add_argument('--quick', action='store_true', help='Run quick scan (parent-child only)')
    parser.add_argument('--continuous', action='store_true', help='Run continuous monitoring')
    parser.add_argument('--interval', type=int, default=60, help='Monitoring interval in seconds')
    parser.add_argument('--baseline', action='store_true', help='Generate process baseline')
    parser.add_argument('--json', action='store_true', help='Save report as JSON')
    
    args = parser.parse_args()
    
    print_banner()
    
    # TODO: Handle each argument
    if args.baseline:
        generate_baseline()
    elif args.continuous:
        run_continuous_monitoring(args.interval)
    elif args.quick:
        run_quick_scan()
    elif args.full:
        run_full_scan()
    else:
        # Default: show help
        parser.print_help()
        print("\n[!] No scan mode specified. Use --full for a complete scan.")


if __name__ == "__main__":
    main()
