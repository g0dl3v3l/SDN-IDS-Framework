Absolutely Tarun! Here's your updated 📄 `src/ebpf/README.md`, now with the **corrected build + run steps** you followed earlier (using manual `clang` compilation and `ip link set`), fully integrated.

---

```markdown
# eBPF Module – TCP Packet Monitoring (XDP)

This module is part of the larger **SDN-IDS-Framework**, responsible for real-time monitoring of TCP packets at the data plane using **eBPF/XDP**. It enables high-performance flow visibility directly at the network interface level.

---

## 📘 eBPF Component: File Roles & Execution Flow

### 📁 File Roles (Inside `src/ebpf/`)

| File            | Role |
|----------------|------|
| `ebpf.c`        | Kernel-space XDP program written in restricted C. Captures TCP packets and pushes metadata (src IP, dst IP, ports) to user space via a perf event map. |
| `xdp_prog.o`    | Compiled eBPF object from `ebpf.c`. This is what the kernel actually loads. |
| `xdp_user.c`    | User-space C program. Loads `xdp_prog.o`, attaches it to an interface (e.g., `s1-eth4`), listens for perf events, and prints TCP flow data in real-time. |
| `Makefile`      | Automates compilation of both kernel-space (`ebpf.c`) and user-space (`xdp_user.c`). |
| `README.md`     | Internal doc explaining how this eBPF module works, how to build and use it. |

---

## 🔁 General Flow of Execution

```text
                +--------------------------+
                |   Mininet Interface      |
                |     (e.g., s1-eth4)      |
                +-----------+--------------+
                            |
         Incoming TCP Packet triggers XDP hook
                            ↓
                    +---------------+
                    |   ebpf.c      |
                    |   (Kernel)    |
                    +---------------+
                            ↓
    Extract: src_ip, dst_ip, sport, dport (TCP only)
                            ↓
   Push to BPF perf buffer map named "events" (perf_event_output)
                            ↓
                    +------------------+
                    |   xdp_user.c     |
                    |   (User-space)   |
                    +------------------+
                            ↓
        Reads packet info via perf_buffer__poll()
                            ↓
       Prints to stdout or logs (extendable for gRPC/DB)
```

---

## ⚙️ Execution Methods

### ✅ Method 1: **Manual Compilation and Run (Recommended)**

```bash
# Compile the eBPF kernel program (with BTF support)
clang -O2 -g -Wall -target bpf \
  -I/usr/local/include/linux-6.8-headers/include \
  -D__TARGET_ARCH_arm64 \
  -c ebpf.c -o xdp_prog.o

# Attach the XDP program to a Mininet/host interface
sudo ip link set dev s1-eth4 xdp obj xdp_prog.o sec xdp

# Compile user-space listener
gcc -O2 -Wall -o xdp_user xdp_user.c -lbpf -lelf

# Run the monitor
sudo ./xdp_user
```

> ✅ After running this, start `iperf` traffic in Mininet and you’ll see flow outputs in your terminal.

---

### 🛑 To Detach the Program

If you Ctrl+C, the program detaches automatically.  
To manually detach:

```bash
sudo ip link set dev s1-eth4 xdp off
```

---

### 🔄 Interface Switching

To monitor another interface:

In `xdp_user.c`, change:

```c
const char *iface = "s1-eth4";
```

To:

```c
const char *iface = "h1-eth0"; // or any valid Mininet interface
```

Then recompile:
```bash
gcc -O2 -Wall -o xdp_user xdp_user.c -lbpf -lelf
```

---

## 📥 Future Extensions

- Add maps to count per-source IP traffic
- Use BPF tail calls or helper functions for modularity
- Export metrics to the RL IDS agent via gRPC or shared file
- Use `bpf_map_lookup_elem()` in user space to pull stats from maps

---

This eBPF module is pluggable and designed to scale with the evolving RL-based SDN-IDS system.
```

---

Let me know when you're ready to update the `README.md` at the **root of the repo**, or want to generate the `Makefile` for these steps!