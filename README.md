
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
📌 **Ryu requires specific Python versions and dependencies. Follow these steps:**
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

## **2. Project Structure**
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

## **3. How to Contribute**
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

## **4. Next Steps (Pending Tasks)**
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

### **Next Steps**
🚀 **Step 1:** Save the above **README.md** to your project root directory.  
🚀 **Step 2:** Commit and push to GitHub:
```bash
git add README.md
git commit -m "Added project documentation"
git push origin main
```
🚀 **Step 3:** Review and ensure all sections align with your expectations.

---
📌 **Do you need any modifications before finalizing this README? 🚀**