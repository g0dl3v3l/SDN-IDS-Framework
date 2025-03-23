import os
import time
import signal
import struct
import json
import csv
import socket
from ctypes import Structure, c_uint32, c_uint16, c_uint8, c_uint64
from bcc import BPF

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

stop_signal = False

def start_monitoring(interface, features, output_path, log_format="json", duration=None):
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
        return socket.inet_ntoa(struct.pack("I", addr))

    def handle_event(cpu, data, size):
        try:
            event = b["events"].event(data)
        except Exception as e:
            print(f"[!] Perf decode error: {e}")
            return

        pkt = {}

        if "saddr" in features:
            pkt["saddr"] = inet_str(event.saddr)
        if "daddr" in features:
            pkt["daddr"] = inet_str(event.daddr)
        if "sport" in features:
            pkt["sport"] = event.sport
        if "dport" in features:
            pkt["dport"] = event.dport
        if "tcp_flags" in features:
            pkt["tcp_flags"] = f"0x{event.tcp_flags:02x}"
        if "pkt_len" in features:
            pkt["pkt_len"] = event.pkt_len
        if "timestamp" in features:
            pkt["timestamp"] = event.timestamp // 1_000_000  # ns → ms

        # Log to file
        if log_format == "text":
            f.write(" | ".join(f"{k}: {v}" for k, v in pkt.items()) + "\n")
        elif log_format == "csv":
            writer.writerow(pkt)
        elif log_format == "json":
            json.dump(pkt, f)
            f.write(",\n")

        f.flush()

        # Print packet summary to terminal
        print(f"[TCP] {pkt.get('saddr')}:{pkt.get('sport')} → {pkt.get('daddr')}:{pkt.get('dport')} | len={pkt.get('pkt_len')} | flags={pkt.get('tcp_flags')} | ts={pkt.get('timestamp')}")

    def handle_lost(cpu, count):
        print(f"[!] Lost {count} events on CPU {cpu}")

    def signal_handler(sig, frame):
        global stop_signal
        stop_signal = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"✅ Monitoring {interface} | Logging to {output_path} | Format: {log_format}")
    start_time = time.time()

    b["events"].event_type = DataT
    b["events"].open_perf_buffer(handle_event, lost_cb=handle_lost)

    try:
        while not stop_signal:
            b.perf_buffer_poll(timeout=100)
            if duration and (time.time() - start_time) >= duration:
                break
    finally:
        print("\n[!] Detaching XDP program...")
        b.remove_xdp(interface, 0)
        if log_format == "json":
            f.seek(f.tell() - 2, os.SEEK_SET)
            f.write("\n]\n")
        f.close()
        print("[✓] Monitor stopped and detached cleanly.")
