
# SDN-IDS-Framework

## **Overview**
This project implements a **Software-Defined Networking (SDN) Intrusion Detection System (IDS)** using:
- **Mininet** for network simulation.
- **Open vSwitch (OVS)** as SDN switches.
- **Ryu SDN Controller** for flow management.
- **Reinforcement Learning (RL) IDS** for real-time attack mitigation.
- **gRPC API** for communication between SDN components.

The goal is to **detect and mitigate DDoS attacks dynamically using RL-based flow control**.


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

### **1.2 Installing Mininet**
```bash
sudo apt update
sudo apt install mininet
```
Verify installation:
```bash
sudo mn --test pingall
```

### **1.3 Installing Open vSwitch (OVS)**
```bash
sudo apt install openvswitch-switch
ovs-vsctl --version
```

### **1.4 Installing Ryu Controller**
> **Note:** Ryu requires specific Python versions and dependencies. Follow these steps:
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

### **1.5 Setting Up Virtual Environment**
```bash
pip install pipenv
mkdir sdn-ids-env
cd sdn-ids-env
pipenv install --python 3.8
pipenv shell
pipenv install ryu grpcio grpcio-tools
```

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

When compiling eBPF programs on ARM64, you may encounter issues due to incompatible or incomplete kernel headers. If you run into errors (e.g., missing types or header files), follow these steps to remove the existing headers and install a fresh set from source.

### **2.1 Remove Existing Kernel Headers (Optional)**
If you wish to remove the currently installed headers:
```bash
sudo apt-get purge linux-headers-$(uname -r)
sudo apt-get autoremove
```

### **2.2 Download and Extract the Kernel Source**
Download the kernel source (for example, version 6.8) from kernel.org:
```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz
tar -xf linux-6.8.tar.xz
cd linux-6.8
```
*Note:* If you prefer Ubuntu’s patched source for your kernel, you can use:
```bash
apt-get source linux-image-$(uname -r)
```
Then navigate into the extracted source directory.

### **2.3 Prepare the Kernel Source**
Clean the source tree to ensure a fresh build:
```bash
make mrproper
```

### **2.4 Install (Generate) the Kernel Headers**
Use the kernel’s `headers_install` target to generate sanitized user-space headers. Choose an installation directory (for example, `/usr/local/include/linux-6.8-headers`):
```bash
sudo make headers_install INSTALL_HDR_PATH=/usr/local/include/linux-6.8-headers
```
This command installs the UAPI and sanitized headers needed for eBPF compilation in the specified directory.

### **2.5 Compile Your eBPF Code Using the New Headers**
When compiling your eBPF (XDP) program, point Clang to the freshly installed headers. For ARM64, also define the target architecture:
```bash
clang -O2 -Wall -target bpf \
  -I/usr/local/include/linux-6.8-headers/include \
  -D__TARGET_ARCH_arm64 \
  -c src/ebpf/ebpf.c -o src/ebpf/xdp_prog.o
```

### **2.6 Attach and Test Your eBPF Program**
Once compiled, attach the program to your network interface (e.g., `eth0`):
```bash
sudo ip link set dev eth0 xdp object src/ebpf/xdp_prog.o sec xdp
```
Verify that the program is loaded:
```bash
ip -details link show eth0
dmesg | tail
```

---

## **3. Project Structure**
```
SDN-IDS-Framework/
│── src/                     # Source code
│   ├── mininet/             # Mininet topology scripts
│   ├── ryu_controller/      # Ryu SDN Controller
│   ├── rl_agent/            # Reinforcement Learning IDS
│   ├── grpc_api/            # gRPC API for communication
│   ├── ebpf/                # eBPF packet monitoring
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
### ✅ **What’s Done**
✔ **Basic SDN setup with Mininet, OVS, and Ryu**  
✔ **Static L3 Routing between subnets**  
✔ **Basic packet forwarding and ARP handling**  

### ❌ **Pending Tasks**
🔹 **Implement gRPC communication for real-time SDN control**  
🔹 **Deploy eBPF packet monitoring for flow tracking**  
🔹 **Integrate RL-based IDS for intrusion detection**  
🔹 **Set up DDoS attack simulation & validate mitigation**  

---

### **Final Note**
This project is **under active development**! Feel free to **report issues, request features, or contribute** to the project.

📌 **For questions or suggestions, contact the team or open a GitHub issue!** 🚀
```

---

### Next Steps

1. **Save the Updated README.md**  
   Copy and paste the above content into your project's README.md file.

2. **Commit and Push to GitHub:**
   ```bash
   git add README.md
   git commit -m "Updated README with kernel headers and eBPF build instructions from source"
   git push origin main
   ```

3. **Review the Documentation:**  
   Verify that the instructions clearly explain how to remove existing headers, build new headers from source, and compile the eBPF program.

Feel free to modify any sections to best match your project's requirements. Let me know if you need any further adjustments or additional sections!
