import os
import sys

# Add the root project path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from ebpf.user.ebpf_monitor import start_multi_monitoring

if __name__ == "__main__":
    # 🔧 Interfaces to monitor (update as needed)
    interfaces = ["s1-eth1", "s1-eth2", "s2-eth1"]

    # 🔧 Fields to capture
    features = ["saddr", "daddr", "sport", "dport", "pkt_len", "tcp_flags", "timestamp"]

    # 🔧 Output format: "json", "csv", or "text"
    log_format = "jsonl"

    # 🔧 Duration in seconds (or None to run until Ctrl+C)
    duration = 30

    # 🔧 Directory to store logs
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    print("[*] Launching multi-interface monitoring...")
    print(f"[*] Interfaces: {interfaces}")
    print(f"[*] Log Format: {log_format}")
    print(f"[*] Duration: {duration}s\n")

    print("[*] Starting single interface monitor...")



    # Call the multi-monitoring launcher
    start_multi_monitoring(
        interfaces=interfaces,
        features=features,
        log_format=log_format,
        duration=duration,
        log_dir=log_dir,
        enable_dashboard=False
    )
    print("[✓] Done.")
