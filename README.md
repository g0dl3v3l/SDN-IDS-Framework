

# 📄 Updated `README.md` (root of SDN-IDS-Framework)


# SDN-IDS-Framework

## **Overview**
This project implements a **Software-Defined Networking (SDN) Intrusion Detection System (IDS)** using:
- **Mininet** for network simulation.
- **Open vSwitch (OVS)** as SDN switches.
- **Ryu SDN Controller** for flow management.
- **Reinforcement Learning (RL) IDS** for real-time attack mitigation.
- **gRPC API** for communication between SDN components.
- **eBPF/XDP-based monitoring** for real-time packet visibility and flow statistics.

The goal is to **detect and mitigate DDoS attacks dynamically using RL-based flow control**.

---

## **1. Installation & Setup**

### **1.1 Prerequisites**
Before setting up the system, ensure you have:
- **Ubuntu 20.04+ or Debian-based OS**
- **Python 3.8**
- **Mininet**
- **Open vSwitch**
- **Ryu Controller**
- **gRPC API libraries**
- **clang, llvm, libbpf-dev, libelf-dev** (for eBPF)

(*... existing installation steps here ...*)

---

## **2. eBPF and Kernel Headers from Source**

When compiling eBPF programs on ARM64, follow the steps to remove default headers and install fresh ones from source:

(*... existing 2.1–2.6 steps unchanged ...*)

---

## **3. Project Structure**

```
SDN-IDS-Framework/
│── src/
│   ├── mininet/             # Mininet topology scripts
│   ├── ryu_controller/      # Ryu SDN Controller
│   ├── rl_agent/            # Reinforcement Learning IDS
│   ├── grpc_api/            # gRPC API for communication
│   ├── ebpf/                # eBPF packet monitoring (XDP)
│── configs/                 # Configuration files
│── scripts/                 # Deployment scripts
│── docs/                    # Documentation
│── tests/                   # Testing and validation scripts
│── datasets/                # Dataset storage (for RL model training)
│── models/                  # Trained RL models
│── results/                 # Experiment logs
│── .gitignore               # Ignore unnecessary files
│── README.md                # Project documentation
│── requirements.txt         # Python dependencies
│── Dockerfile               # Containerized deployment
│── docker-compose.yml       # Multi-service setup
```

---

## **3.1 eBPF Module: TCP Flow Monitoring with XDP**

The `src/ebpf/` directory implements a high-performance TCP packet monitor using **eBPF** with **XDP**. It allows real-time packet visibility at the kernel level, feeding live flow-level data into the SDN-IDS system.

### 🔁 Flow of Execution:

```
1. TCP packet arrives at interface (e.g., s1-eth4)
2. `ebpf.c` (XDP) parses TCP header and extracts: src_ip, dst_ip, sport, dport
3. Data is sent to a perf event buffer
4. `xdp_user.c` (user space) listens to this buffer and prints/logs info
```

### ▶️ Run

```bash
cd src/ebpf
make            # Builds both ebpf.o and xdp_user
sudo ./xdp_user # Starts the monitor
```

### 🧪 Example Output

```
✅ Listening for TCP packets on s1-eth4... Press Ctrl+C to exit
TCP packet: 10.0.2.2:5001 → 10.0.1.1:36174
```

### 🛠 Change Interface

Update `xdp_user.c`:
```c
const char *iface = "s1-eth4";
```

### 🛑 To Detach

```bash
sudo ip link set dev s1-eth4 xdp off
```

### 📥 Extendable Features

- Track UDP, ICMP, or all IP traffic
- Count packets per host/flow using hash maps
- Export statistics via gRPC to RL IDS
- Detect SYN floods, port scans using flow patterns

👉 See `src/ebpf/README.md` for in-depth usage and developer notes.

---

## **4. How to Contribute**
(*... no changes here ...*)

---

## **5. Next Steps (Pending Tasks)**

### ✅ What’s Done
✔ Basic SDN setup with Mininet, OVS, and Ryu  
✔ Static L3 Routing between subnets  
✔ eBPF-based TCP packet monitor integrated with the SDN dataplane  
✔ Basic packet forwarding and ARP handling  

### ❌ What’s Next
🔹 Integrate eBPF flow data into RL agent via gRPC  
🔹 Train RL IDS models on flow-based patterns  
🔹 Simulate DDoS and test dynamic mitigation strategies  

---

🎯 This updated README now provides a complete, clear reference for both setting up the system and using the eBPF-based monitoring component effectively.

Let me know if you'd like me to generate a companion `Makefile` or sample test script for eBPF validation.