

# 📄 `src/ebpf/README.md`

# eBPF Module – TCP Packet Monitoring (XDP)

This module is part of the larger **SDN-IDS-Framework**, responsible for real-time monitoring of TCP packets at the data plane using **eBPF/XDP**. It enables high-performance flow visibility directly at the network interface level.



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

### 🔁 General Flow of Execution

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

### ⚙️ Execution Methods

#### ✅ Method 1: **Using Makefile (Recommended)**

```bash
cd src/ebpf
make            # Builds xdp_prog.o and xdp_user
sudo ./xdp_user # Attaches and starts real-time monitoring
```

#### ✅ Method 2: **Manual Compilation**

```bash
# Compile the eBPF kernel program
clang -O2 -g -Wall -target bpf \
  -I/usr/local/include/linux-6.8-headers/include \
  -D__TARGET_ARCH_arm64 \
  -c ebpf.c -o xdp_prog.o

# Compile user-space loader
gcc -O2 -Wall -o xdp_user xdp_user.c -lbpf -lelf

# Run the monitor
sudo ./xdp_user
```

> ❌ If you get errors like `undefined reference to bpf_set_link_xdp_fd`, switch to `bpf_xdp_attach()` instead. (Already used in your version.)

---

### 🛑 To Detach the Program

If you Ctrl+C, the program detaches automatically.

To manually detach:
```bash
sudo ip link set dev s1-eth4 xdp off
```

---

### 🔄 Interface Switching

Want to attach to another interface?

In `xdp_user.c`, change this line:
```c
const char *iface = "s1-eth4";
```
to any other Mininet interface (e.g., `h1-eth0`, `eth0`, etc.)

---

### 📥 Future Extensions

- Add maps to count per-source IP traffic
- Use BPF tail calls or helper functions for modularity
- Export metrics to the RL IDS agent via gRPC or shared file
- Use `bpf_map_lookup_elem()` in user space to pull stats from maps

---

This eBPF module is pluggable and designed to scale with the evolving RL-based SDN-IDS system.
```

---

Let me know when you're ready and I’ll generate the updated **root-level README.md** next.