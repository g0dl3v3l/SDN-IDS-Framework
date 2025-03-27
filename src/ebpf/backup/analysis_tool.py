"""
Standalone Driver: eBPF Monitor Launcher
----------------------------------------

This script serves as a simple example of how to invoke the eBPF monitoring module
(`start_monitoring(...)`) from the `ebpf_monitor.py` interface.

Usage:
- Launches monitoring on a given interface (default: "s1-eth4")
- Logs selected TCP packet fields to a file in json/csv/text format
- Runs for a specified duration (default: 30 seconds)

This is primarily used for debugging, standalone testing, or demonstrating the eBPF
integration without needing to manually build the controller or topology.

To modify:
- Change the interface name
- Adjust the list of features to log
- Choose a different output format
- Extend with multi-interface or analysis hooks

Make sure the eBPF program is properly compiled and kernel headers are in place.
"""

import sys
import os

# Dynamically add the root 'src/' to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from ebpf.user.ebpf_monitor import start_monitoring

# Example usage of the eBPF monitor module
if __name__ == "__main__":
    interface = "s1-eth1"
    features = ["saddr", "daddr", "sport", "dport", "pkt_len", "tcp_flags", "timestamp"]
    output_path = f"logs/{interface}.json"
    log_format = "json"         # Can be "json", "csv", or "text"
    duration = 30               # Run for 30 seconds

    start_monitoring(
        interface=interface,
        features=features,
        output_path=output_path,
        log_format=log_format,
        duration=duration
    )
