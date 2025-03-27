
# eBPF Module – TCP Packet Monitoring (XDP)

This module is part of the larger **SDN-IDS-Framework**, responsible for real-time monitoring of TCP packets at the data plane using **eBPF/XDP**. It enables high-performance flow visibility directly at the network interface level.


## 📘 eBPF Component: File Roles & Execution Flow

### 📁 File Roles (Inside `src/ebpf/`)

| File                         | Role |
|------------------------------|------|
| `ebpf.c`                     | Kernel-space XDP program. Captures TCP packets, extracts metadata, pushes events to user space via a perf buffer. |
| `xdp_user.c`                 | User-space C loader for `xdp_prog.o`. Attaches XDP to interface, reads perf events, prints/logs results. |
| `xdp_prog.o`                 | Compiled kernel object from `ebpf.c`. |
| `user/ebpf_monitor.py`       | 🧠 Python package using BCC. Attaches `ebpf.c`, processes events, logs data, and supports programmatic control. |
| `analysis_tool.py`           | Example driver that calls `start_monitoring(...)`. Used for quick tests and demos. |
| `test_multi_monitor.py`      | Multiprocessing launcher for monitoring multiple interfaces in parallel. |
| `dashboard_live_tail.py`     | 📊 CLI-based dashboard that live-tails and visualizes logs written by the monitor. |
| `README.md`                  | You’re here :) explains everything about the eBPF module. |

---

## 🔁 General Flow of Execution (Kernel to User)

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
    Extract: src_ip, dst_ip, sport, dport, flags, size, timestamp
                            ↓
   Push to BPF perf buffer map named "events" (perf_event_output)
                            ↓
        +-----------------------------+       +--------------------------------+
        |   xdp_user.c (C)            |   or  |   ebpf_monitor.py (Python)     |
        |   Raw stdout/log            |       |   CLI + Dashboard + Logs       |
        +-----------------------------+       +--------------------------------+
```

---

## ⚙️ Execution Methods

### ✅ Option 1: Manual C-Based Monitor (Standalone)

```bash
clang -O2 -g -Wall -target bpf \
  -I/usr/local/include/linux-6.8-headers/include \
  -D__TARGET_ARCH_arm64 \
  -c ebpf.c -o xdp_prog.o

sudo ip link set dev s1-eth4 xdp obj xdp_prog.o sec xdp

gcc -O2 -Wall -o xdp_user xdp_user.c -lbpf -lelf
sudo ./xdp_user
```

To detach:
```bash
sudo ip link set dev s1-eth4 xdp off
```

---

## 🧠 Option 2: Python-Based Monitor (Modular + Loggable)

### `analysis_tool.py` (Quick Launcher)

```bash
sudo python3 analysis_tool.py --interface s1-eth1 --format csv --duration 60
```

Logs are saved to:
```
logs/s1-eth1.csv
```

### ✅ Function Overview

You can invoke the monitor manually:
```python
from ebpf.user.ebpf_monitor import start_monitoring

start_monitoring(
    interface="s1-eth4",
    features=["saddr", "daddr", "sport", "dport", "pkt_len", "tcp_flags", "timestamp"],
    output_path="logs/s1-eth4.json",
    log_format="json",  # or "csv", "text"
    duration=30,
    enable_dashboard=True
)
```

---

## 📁 Output Formats Supported

| Format | Description |
|--------|-------------|
| `json` | Array of packet dicts; good for structured logs |
| `csv`  | Row-based; best for analysis tools |
| `text` | Line-per-packet string dump; human-readable |

Example JSON entry:
```json
{
  "saddr": "10.0.0.1",
  "daddr": "10.0.0.2",
  "sport": 5001,
  "dport": 42043,
  "pkt_len": 74,
  "tcp_flags": "0x12",
  "timestamp": 26392482
}
```

---

## 🖥️ Real-Time Dashboards

### ✅ Integrated Live Dashboard (via `rich`)

Use the `enable_dashboard=True` flag in any monitor function:

```bash
sudo python3 analysis_tool.py --interface s1-eth2 --dashboard
```

CLI will show:

```
┌────────────┬────────────┬──────────────┐
│ Interface  │ Packets    │ Flags Seen   │ 
├────────────┼────────────┼──────────────┤
│ s1-eth2    │ 1,203      │ SYN, ACK     │
│ s1-eth3    │ 2,034      │ SYN, RST     │
└────────────┴────────────┴──────────────┘
```

---

### ✅ Live Log Tail Dashboard

After running a monitor that logs to files (CSV or JSON), you can launch this:

```bash
sudo python3 dashboard_live_tail.py
```

This continuously reads the `logs/` folder and displays interface-wise stats.

---

## 🔄 Multi-Interface Monitoring (Parallel)

Use `test_multi_monitor.py` to monitor multiple interfaces in parallel:

```bash
sudo python3 test_multi_monitor.py
```

You can customize the interfaces list and enable the dashboard inside the script:
```python
start_multi_monitoring(
    interfaces=["s1-eth1", "s1-eth2"],
    features=["saddr", "daddr", "sport", "dport", "pkt_len", "tcp_flags", "timestamp"],
    log_format="csv",
    duration=60,
    enable_dashboard=True
)
```

Logs will be saved as:
```
logs/s1-eth1.csv
logs/s1-eth2.csv
```

---

## 🧪 Testing with Mininet + iPerf

From the Mininet CLI:

```bash
iperf h1 h2 &
iperf h3 h1 &
```

Or via custom Python traffic scripts:
```python
h1.cmd("iperf -s &")
h2.cmd("iperf -c 10.0.0.1 -t 30 &")
```

---

## 🔍 Customization Options

- Choose logging format: `csv`, `json`, or `text`
- Enable or disable real-time dashboard
- Dynamically choose interfaces and durations
- Add new fields to `features[]` list (if captured in `ebpf.c`)

---

## 🔮 Planned Extensions

- [ ] gRPC client integration to stream flow logs to RL agent
- [ ] Detect abnormal TCP flag patterns (e.g., SYN floods)
- [ ] Track per-IP flow stats using BPF maps
- [ ] Export metrics in Prometheus format
- [ ] Simulate noisy background traffic via `traffic_sim.py`

---

## 👥 Contributing

All eBPF logic is modular and extensible.

Feel free to add:
- More protocols (UDP, ICMP)
- Dashboard enhancements
- Prometheus exporters
- Real-time classification logic

---

Would you like me to now regenerate the updated **`Makefile`**, or should we move on to the **traffic generator script**?