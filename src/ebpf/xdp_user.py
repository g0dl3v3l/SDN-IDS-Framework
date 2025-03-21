from bcc import BPF
from bcc.utils import printb
import struct
from socket import inet_ntoa
import os

iface = "s1-eth4"

# Load precompiled BPF object and specify section
b = BPF()
fn = b.load_func("xdp_monitor_tcp", BPF.XDP, "xdp_prog.o")
b.attach_xdp(iface, fn, 0)

# Define event structure: 2 x u32 (IP), 2 x u16 (ports)
event_struct = "IIHH"

def handle_event(cpu, data, size):
    pkt = b["events"].event(data)
    parsed = struct.unpack(event_struct, pkt)
    src_ip = inet_ntoa(struct.pack("I", parsed[0]))
    dst_ip = inet_ntoa(struct.pack("I", parsed[1]))
    print(f"{src_ip} → {dst_ip} | {parsed[2]} → {parsed[3]}")

print(f"Listening on {iface}... Press Ctrl+C to stop.")
b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
    b.remove_xdp(iface, 0)
