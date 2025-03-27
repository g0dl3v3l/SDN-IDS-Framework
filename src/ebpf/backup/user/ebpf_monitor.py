"""
eBPF Monitoring Module for SDN-IDS
----------------------------------

This module provides a high-performance, programmable TCP packet monitoring system using
eBPF/XDP and BCC. It allows dynamic attachment of a kernel-space XDP program to any
network interface and streams flow-level statistics and metadata to user space in real-time.

Features:
- Real-time TCP flow monitoring via eBPF
- Logging to CSV, JSON, or plain text formats
- Terminal display of decoded packet fields
- Configurable fields to capture
- Multiprocessing-based multi-interface monitoring
- Backward-compatible lost_cb handling
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
from bcc import BPF


class DataT(Structure):
    """
    Structure matching the kernel-space 'data_t' struct from the eBPF program.
    Used to decode packet metadata from the perf event buffer.
    """
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
    """
    Creates a compatible lost callback function for perf buffer handling.

    Handles both new (cpu, count) and old (count) BCC callback signatures.

    Parameters:
    ----------
    interface : str
        The name of the network interface being monitored.

    Returns:
    -------
    callable
        A callback function to handle lost packet notifications.
    """
    def lost_cb(cpu_or_count, maybe_count=None):
        if maybe_count is None:
            print(f"[!] Lost {cpu_or_count} packets (interface={interface})")
        else:
            print(f"[!] Lost {maybe_count} packets on CPU {cpu_or_count} (interface={interface})")
    return lost_cb


def start_monitoring(interface, features, output_path, log_format="json", duration=None, stop_event=None):
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
        Logging format: "json", "csv", or "text".

    duration : int or None
        Number of seconds to run. If None, runs until Ctrl+C or stop_event is set.

    stop_event : threading.Event or None
        Optional stop event to terminate gracefully when triggered.
    """
    stop_event = stop_event or threading.Event()

    ebpf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ebpf.c"))
    if not os.path.exists(ebpf_path):
        raise FileNotFoundError(f"Missing ebpf.c at: {ebpf_path}")

    with open(ebpf_path, "r") as f:
        bpf_source = f.read()

    try:
        b = BPF(text=bpf_source, cflags=[
            "-I/usr/local/include/linux-6.8-headers/include",
            "-I/usr/local/include/linux-6.8-headers/include/linux",
            "-D__TARGET_ARCH_arm64",
            "-O2", "-Wall", "-g"
        ])
    except Exception as e:
        raise RuntimeError(f"eBPF compilation failed: {e}")

    try:
        fn = b.load_func("xdp_monitor_tcp", BPF.XDP)
        b.attach_xdp(interface, fn, 0)
    except Exception as e:
        raise RuntimeError(f"Failed to attach to {interface}: {e}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    f = open(output_path, "w", newline="")

    if log_format == "csv":
        writer = csv.DictWriter(f, fieldnames=features)
        writer.writeheader()
    elif log_format == "json":
        f.write("[\n")

    def inet_str(addr):
        """
        Convert a 32-bit integer IP address to dotted-decimal string.
        """
        return socket.inet_ntoa(struct.pack("I", addr))

    def handle_event(cpu, data, size):
        """
        Callback triggered when a packet metadata is received from the kernel.

        Logs and prints packet fields as specified in the 'features' list.
        """
        try:
            event = b["events"].event(data)
        except Exception as e:
            print(f"[!] Perf decode error: {e}")
            return

        pkt = {}
        if "saddr" in features: pkt["saddr"] = inet_str(event.saddr)
        if "daddr" in features: pkt["daddr"] = inet_str(event.daddr)
        if "sport" in features: pkt["sport"] = event.sport
        if "dport" in features: pkt["dport"] = event.dport
        if "tcp_flags" in features: pkt["tcp_flags"] = f"0x{event.tcp_flags:02x}"
        if "pkt_len" in features: pkt["pkt_len"] = event.pkt_len
        if "timestamp" in features: pkt["timestamp"] = event.timestamp // 1_000_000

        if log_format == "text":
            f.write(" | ".join(f"{k}: {v}" for k, v in pkt.items()) + "\n")
        elif log_format == "csv":
            writer.writerow(pkt)
        elif log_format == "json":
            json.dump(pkt, f)
            f.write(",\n")

        f.flush()

        print(f"[TCP][{interface}] {pkt.get('saddr')}:{pkt.get('sport')} → {pkt.get('daddr')}:{pkt.get('dport')} | len={pkt.get('pkt_len')} | flags={pkt.get('tcp_flags')} | ts={pkt.get('timestamp')}")

    def signal_handler(sig, frame):
        """
        Signal handler to enable graceful exit on Ctrl+C or termination.
        """
        stop_event.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

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


def start_multi_monitoring(interfaces, features, log_format="json", duration=None, log_dir="logs"):
    """
    Launches parallel eBPF monitors for multiple interfaces using multiprocessing.

    Parameters:
    ----------
    interfaces : list[str]
        List of network interfaces to monitor (e.g., ["s1-eth1", "s2-eth2"]).

    features : list[str]
        List of TCP metadata fields to log.

    log_format : str
        Format to use for logging: "json", "csv", or "text".

    duration : int or None
        Time to run each monitor. If None, runs indefinitely.

    log_dir : str
        Directory to store per-interface log files.
    """
    processes = []

    def monitor_worker(iface, features, log_format, duration, log_dir):
        import sys
        import os
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        sys.path.insert(0, project_root)

        from ebpf.user.ebpf_monitor import start_monitoring

        output_path = os.path.join(log_dir, f"{iface}.{log_format}")
        try:
            start_monitoring(
                interface=iface,
                features=features,
                output_path=output_path,
                log_format=log_format,
                duration=duration
            )
        except Exception as e:
            print(f"[!] Error in monitor for {iface}: {e}")

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
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()
        print("[✓] All monitors stopped.")
