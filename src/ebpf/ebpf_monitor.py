import sys
import subprocess
from bcc import BPF
from datetime import datetime
import ctypes as ct

# Ensure a network interface is provided
if len(sys.argv) < 2:
    print("Usage: sudo python3 bcc_monitor.py <interface>")
    sys.exit(1)

interface = sys.argv[1]

# BPF program to trace TCP packets (TC Mode)
bpf_program = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

int trace_tcp_packets(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct data_t pkt = {};

    // Ensure Ethernet header is within packet bounds
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = data + sizeof(*eth);

    // Ensure IP header is within packet bounds
    if ((void*)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcp = (void*)ip + sizeof(*ip);

    // Ensure TCP header is within packet bounds
    if ((void*)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;

    // Populate packet data
    pkt.saddr = ip->saddr;
    pkt.daddr = ip->daddr;
    pkt.sport = ntohs(tcp->source);
    pkt.dport = ntohs(tcp->dest);

    // Submit packet data to user space
    events.perf_submit(skb, &pkt, sizeof(pkt));

    return TC_ACT_OK;
}
"""

b = BPF(text=bpf_program, cflags=[
    "-I/usr/src/linux-headers-$(uname -r)/include",
    "-I/usr/src/linux-headers-$(uname -r)/include/uapi",
    "-I/usr/src/linux-headers-$(uname -r)/arch/arm64/include/generated/uapi",
    "-I/usr/src/linux-headers-$(uname -r)/arch/arm64/include/generated/uapi/asm"  # ✅ This is where `types.h` actually is
])
# Load the function for Traffic Control (TC)
fn = b.load_func("trace_tcp_packets", BPF.SCHED_CLS)

# Manually compile the BPF program using Clang
bpf_object_file = "/tmp/bpf_prog.o"
clang_cmd = f"clang -O2 -target bpf -c -xc - -o {bpf_object_file}"
proc = subprocess.Popen(clang_cmd, shell=True, stdin=subprocess.PIPE)
proc.communicate(input=bpf_program.encode())

# Ensure the BPF program compiled correctly
if proc.returncode != 0:
    print("❌ Failed to compile BPF program")
    sys.exit(1)

# Remove old TC settings before attaching BPF
tc_cleanup_cmd = f"tc qdisc del dev {interface} clsact"
subprocess.run(tc_cleanup_cmd, shell=True, stderr=subprocess.DEVNULL)  # Ignore errors if qdisc doesn't exist

tc_add_cmd = f"tc qdisc add dev {interface} clsact"
tc_filter_cmd = f"tc filter add dev {interface} ingress bpf direct-action obj {bpf_object_file}"

# Ensure TC clsact qdisc is attached
try:
    subprocess.run(tc_add_cmd, shell=True, check=True)
    subprocess.run(tc_filter_cmd, shell=True, check=True)
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to attach BPF to {interface}: {e}")
    sys.exit(1)

print(f"✅ Monitoring TCP packets on {interface}... Press Ctrl+C to stop.")

# Define output structure
class Data(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
    ]

# Convert IP addresses from integer to string
def inet_ntoa(addr):
    return ".".join(map(str, addr.to_bytes(4, 'big')))

# Callback function to print event data
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(f"{datetime.now()} {inet_ntoa(event.saddr)}:{event.sport} -> {inet_ntoa(event.daddr)}:{event.dport}")

# Open perf buffer and set callback
b["events"].open_perf_buffer(print_event)

# Event loop to process packets
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🔄 Detaching BPF program...")
    subprocess.run(tc_cleanup_cmd, shell=True)
    exit()
