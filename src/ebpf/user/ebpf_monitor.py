# ebpf_monitor.py

"""
eBPF Monitoring Module for SDN-IDS
----------------------------------
[...same docstring as before...]
"""

import os
import time
import signal
import struct
import json
import csv
import socket
import threading
import multiprocessing
from ctypes import Structure, c_uint32, c_uint16, c_uint8, c_uint64
from collections import defaultdict
from bcc import BPF
from rich.live import Live
from rich.table import Table
from rich.console import Console

# Shared metric state
metrics_lock = threading.Lock()
monitor_metrics = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "flags": set(),
    "lost": 0
})


import os
import glob




class DataT(Structure):
    _fields_ = [
        ("saddr", c_uint32),
        ("daddr", c_uint32),
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("tcp_flags", c_uint8),
        ("pkt_len", c_uint32),
        ("timestamp", c_uint64),
    ]

def make_lost_cb(interface):
    def lost_cb(cpu_or_count, maybe_count=None):
        count = maybe_count if maybe_count is not None else cpu_or_count
        with metrics_lock:
            monitor_metrics[interface]["lost"] += count
    return lost_cb

class DashboardUpdater(threading.Thread):
    def __init__(self, metrics_dict, stop_event, refresh_interval=1.0):
        super().__init__(daemon=True)
        self.metrics_dict = metrics_dict
        self.stop_event = stop_event
        self.refresh_interval = refresh_interval
        self.console = Console()

    def render_table(self):
        table = Table(title="📊 eBPF Monitoring Dashboard", expand=True)
        table.add_column("Interface", style="bold cyan")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Flags Seen", justify="left")
        table.add_column("Lost Events", justify="right")
        with metrics_lock:
            for iface, data in self.metrics_dict.items():
                flags = ", ".join(sorted(data["flags"]))
                if len(flags) > 20:
                    flags = flags[:20] + "…"
                table.add_row(
                    iface,
                    str(data["packets"]),
                    str(data["bytes"]),
                    flags,
                    str(data["lost"])
                )
        return table

    def run(self):
        with Live(self.render_table(), refresh_per_second=1/self.refresh_interval, console=self.console) as live:
            while not self.stop_event.is_set():
                time.sleep(self.refresh_interval)
                live.update(self.render_table())

def start_monitoring(interface, features, output_path, log_format="json", duration=None, stop_event=None, enable_dashboard=False):
    """
    Attach an eBPF XDP program to a given interface and start collecting TCP packet metadata.

    Parameters:
    ----------
    interface : str
        Network interface name (e.g., "s1-eth1").

    features : list[str]
        Fields to extract and log from each TCP packet.

    output_path : str
        Path to the file where logs will be saved.

    log_format : str
        Logging format: "json", "csv", "text", or "jsonl" (JSON Lines).

    duration : int or None
        Number of seconds to run. If None, runs until Ctrl+C or stop_event is set.

    stop_event : threading.Event or None
        Optional stop event to terminate gracefully when triggered.

    enable_dashboard : bool
        Whether to enable the live CLI dashboard during monitoring.
    """
    import threading
    stop_event = stop_event or threading.Event()

    ebpf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ebpf.c"))
    if not os.path.exists(ebpf_path):
        raise FileNotFoundError(f"Missing ebpf.c at: {ebpf_path}")

    with open(ebpf_path, "r") as f_src:
        bpf_source = f_src.read()

    b = BPF(text=bpf_source, cflags=[
        "-I/usr/local/include/linux-6.8-headers/include",
        "-I/usr/local/include/linux-6.8-headers/include/linux",
        "-D__TARGET_ARCH_arm64",
        "-O2", "-Wall", "-g"
    ])

    fn = b.load_func("xdp_monitor_tcp", BPF.XDP)
    b.attach_xdp(interface, fn, 0)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    f = open(output_path, "w", newline="")

    if log_format == "csv":
        writer = csv.DictWriter(f, fieldnames=features)
        writer.writeheader()
    elif log_format == "json":
        f.write("[\n")
    elif log_format == "jsonl":
        pass  # No header needed

    def inet_str(addr):
        return socket.inet_ntoa(struct.pack("I", addr))

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        pkt = {}
        if "saddr" in features: pkt["saddr"] = inet_str(event.saddr)
        if "daddr" in features: pkt["daddr"] = inet_str(event.daddr)
        if "sport" in features: pkt["sport"] = event.sport
        if "dport" in features: pkt["dport"] = event.dport
        if "tcp_flags" in features: pkt["tcp_flags"] = f"0x{event.tcp_flags:02x}"
        if "pkt_len" in features: pkt["pkt_len"] = event.pkt_len
        if "timestamp" in features: pkt["timestamp"] = event.timestamp // 1_000_000

        with metrics_lock:
            monitor_metrics[interface]["packets"] += 1
            monitor_metrics[interface]["bytes"] += event.pkt_len
            monitor_metrics[interface]["flags"].add(pkt.get("tcp_flags"))

        if log_format == "text":
            f.write(" | ".join(f"{k}: {v}" for k, v in pkt.items()) + "\n")
        elif log_format == "csv":
            writer.writerow(pkt)
        elif log_format == "json":
            json.dump(pkt, f)
            f.write(",\n")
        elif log_format == "jsonl":
            f.write(json.dumps(pkt) + "\n")
        f.flush()

    def signal_handler(sig, frame):
        stop_event.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    if enable_dashboard:
        DashboardUpdater(monitor_metrics, stop_event).start()

    print(f"✅ Monitoring {interface} | Logging to {output_path} | Format: {log_format}")
    start_time = time.time()

    b["events"].event_type = DataT
    b["events"].open_perf_buffer(handle_event, lost_cb=make_lost_cb(interface), page_cnt=512)

    try:
        while not stop_event.is_set():
            b.perf_buffer_poll(timeout=1)
            if duration and (time.time() - start_time) >= duration:
                break
    finally:
        print(f"\n[!] Detaching XDP program from {interface}...")
        b.remove_xdp(interface, 0)
        if log_format == "json":
            f.seek(f.tell() - 2, os.SEEK_SET)
            f.write("\n]\n")
        f.close()
        print(f"[✓] Monitor on {interface} stopped and detached cleanly.")


def start_multi_monitoring(interfaces, features, log_format="json", duration=None, log_dir="logs", enable_dashboard=False):
    """
    Launches parallel eBPF monitors for multiple interfaces using multiprocessing.

    Parameters:
    ----------
    interfaces : list[str]
        List of network interfaces to monitor.

    features : list[str]
        List of TCP metadata fields to log.

    log_format : str
        Format to use for logging: "json", "csv", or "text".

    duration : int or None
        Time to run each monitor. If None, runs indefinitely.

    log_dir : str
        Directory to store per-interface log files.

    enable_dashboard : bool
        Whether to launch the terminal dashboard alongside.
    """
    processes = []
    stop_event = multiprocessing.Event()

    def monitor_worker(iface, features, log_format, duration, log_dir):
        import sys
        import os
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        sys.path.insert(0, project_root)

        from ebpf.user.ebpf_monitor import start_monitoring, monitor_metrics, metrics_lock

        output_path = os.path.join(log_dir, f"{iface}.{log_format}")
        try:
            start_monitoring(
                interface=iface,
                features=features,
                output_path=output_path,
                log_format=log_format,
                duration=duration,
                stop_event=threading.Event(),  # Each monitor gets its own local stop
                enable_dashboard=False  # Dashboard is launched once globally
            )
        except Exception as e:
            print(f"[!] Error in monitor for {iface}: {e}")

    if enable_dashboard:
        dashboard_thread = DashboardUpdater(monitor_metrics, stop_event)
        dashboard_thread.start()

    for iface in interfaces:
        p = multiprocessing.Process(
            target=monitor_worker,
            args=(iface, features, log_format, duration, log_dir)
        )
        processes.append(p)
        p.start()

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Terminating all monitors...")
        stop_event.set()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()
        print("[✓] All monitors stopped.")
