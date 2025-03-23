import sys
import os

# Dynamically add the root 'src/' to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from ebpf.user.ebpf_monitor import start_monitoring



# Example usage of the eBPF monitor module
if __name__ == "__main__":
    interface = "s1-eth4"
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
