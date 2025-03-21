Absolutely! Below is the **fully updated root-level `README.md`** with everything included — your original content plus the new eBPF section, detailed structure, flow, execution, and integration.

---

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
- **Python 3.8** (recommended for compatibility)
- **Virtual Environment (pipenv)**
- **Mininet**
- **Open vSwitch**
- **Ryu Controller**
- **gRPC API libraries**
- **Clang/LLVM, libbpf-dev, libelf-dev** (for eBPF compilation)

---

### **1.2 Installing Mininet**
```bash
sudo apt update
sudo apt install mininet
```
Verify installation:
```bash
sudo mn --test pingall
```

---

### **1.3 Installing Open vSwitch (OVS)**
```bash
sudo apt install openvswitch-switch
ovs-vsctl --version
```

---

### **1.4 Installing Ryu Controller**
> **Note:** Ryu requires specific Python versions and dependencies.
```bash
sudo apt install python3-pip
pip install pip==20.3.4
pip install setuptools==67.6.1
pip install eventlet==0.30.2
pip install ryu
```
To run Ryu:
```bash
ryu-manager src/ryu_controller/simple_router.py
```

---

### **1.5 Setting Up Virtual Environment**
```bash
pip install pipenv
mkdir sdn-ids-env
cd sdn-ids-env
pipenv install --python 3.8
pipenv shell
pipenv install ryu grpcio grpcio-tools
```

---

### **1.6 Running the Network**
1. **Start Mininet:**
   ```bash
   ./scripts/setup_mininet.sh
   ```
2. **Start Ryu Controller:**
   ```bash
   ./scripts/setup_ryu.sh
   ```
3. **Start RL IDS (once implemented):**
   ```bash
   ./scripts/setup_rl_agent.sh
   ```

---

## **2. eBPF and Kernel Headers from Source**

### **2.1 Remove Existing Kernel Headers (Optional)**
```bash
sudo apt-get purge linux-headers-$(uname -r)
sudo apt-get autoremove
```

---

### **2.2 Download and Extract the Kernel Source**
```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz
tar -xf linux-6.8.tar.xz
cd linux-6.8
```
Or:
```bash
apt-get source linux-image-$(uname -r)
```

---

### **2.3 Prepare the Kernel Source**
```bash
make mrproper
```

---

### **2.4 Install (Generate) the Kernel Headers**
```bash
sudo make headers_install INSTALL_HDR_PATH=/usr/local/include/linux-6.8-headers
```

---

### **2.5 Compile Your eBPF Code Using the New Headers**
```bash
clang -O2 -Wall -target bpf \
  -I/usr/local/include/linux-6.8-headers/include \
  -D__TARGET_ARCH_arm64 \
  -c src/ebpf/ebpf.c -o src/ebpf/xdp_prog.o
```

---

### **2.6 Attach and Test Your eBPF Program**
```bash
sudo ip link set dev eth0 xdp object src/ebpf/xdp_prog.o sec xdp
ip -details link show eth0
dmesg | tail
```

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

---

### 📁 File Roles

| File            | Role |
|----------------|------|
| `ebpf.c`        | Kernel-space XDP program to parse TCP packets and push metadata to a perf buffer. |
| `xdp_prog.o`    | Compiled object file from `ebpf.c`, loaded into the kernel. |
| `xdp_user.c`    | User-space loader: attaches XDP program, reads events from perf buffer, prints TCP flow data. |
| `Makefile`      | Automates compilation of kernel and user programs. |
| `README.md`     | Documentation for the eBPF module and its extension points. |

---

### 🔁 General Flow of Execution

```text
1. TCP packet hits interface (e.g., s1-eth4)
2. Kernel program (ebpf.c) extracts IPs and ports
3. Sends packet info to perf_event buffer
4. User-space program (xdp_user.c) receives and logs/streams the data
```

---

### ▶️ Build & Run

```bash
cd src/ebpf
make            # Builds xdp_prog.o and xdp_user
sudo ./xdp_user # Attaches and starts monitoring
```

Example Output:
```
✅ Listening for TCP packets on s1-eth4... Press Ctrl+C to exit
TCP packet: 10.0.2.2:5001 → 10.0.1.1:36174
```

---

### 🛠 Interface Selection

Edit `xdp_user.c` to update:
```c
const char *iface = "s1-eth4";
```

---

### 🛑 Detach Program

Automatically detaches on `Ctrl+C`. To detach manually:

```bash
sudo ip link set dev s1-eth4 xdp off
```

---

### 🔄 Extend This Module

- Capture UDP/ICMP traffic
- Count per-source IP flows using hash maps
- Export data to RL IDS over gRPC
- Write flow data to JSON, CSV, or Prometheus endpoints

📄 See [`src/ebpf/README.md`](src/ebpf/README.md) for developer-level documentation and extension details.

---

## **4. How to Contribute**

We follow a **structured workflow** for contributions:

1. **Fork the repository** and create a feature branch:
   ```bash
   git checkout -b feature/<your-feature-name>
   ```

2. **Make your changes** and commit:
   ```bash
   git add .
   git commit -m "Added feature <your-feature-name>"
   ```

3. **Push changes and create a pull request:**
   ```bash
   git push origin feature/<your-feature-name>
   ```

4. **Review process**: Collaborators will review your PR before merging.

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

📌 For questions, suggestions, or contributions, please open a GitHub issue or pull request!

```

---

Let me know if you'd like the `Makefile` next to complete this setup.