"""
Standalone Driver: eBPF Monitor Launcher
----------------------------------------

This script serves as a simple example of how to invoke the eBPF monitoring module
(`start_monitoring(...)`) from the `ebpf_monitor.py` interface.

Usage:
- Launches monitoring on a given interface (default: "s1-eth1")
- Logs selected TCP packet fields to a file in json/csv/text format
- Runs for a specified duration (default: 30 seconds)
- Displays real-time dashboard output (optional)

Run with:
    sudo python3 analysis_tool.py --interface s1-eth2
"""

import sys
import os
import argparse
import threading

# Dynamically add the root 'src/' to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from ebpf.user.ebpf_monitor import start_monitoring

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run eBPF monitor on a given interface.")
    parser.add_argument("--interface", "-i", type=str, default="s1-eth1", help="Network interface to monitor")
    parser.add_argument("--format", "-f", type=str, default="json", choices=["json", "csv", "text"], help="Log format")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Monitoring duration in seconds")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable the real-time dashboard")

    args = parser.parse_args()

    output_path = f"logs/{args.interface}.{args.format}"
    features = ["saddr", "daddr", "sport", "dport", "pkt_len", "tcp_flags", "timestamp"]

    start_monitoring(
        interface=args.interface,
        features=features,
        output_path=output_path,
        log_format=args.format,
        duration=args.duration,
        stop_event=threading.Event(),
        enable_dashboard=not args.no_dashboard
    )
