
## 1. Module Overview
This directory contains the Mininet-related code for the SDN-IDS project. It defines a custom topology and embeds a traffic generation utility designed to simulate realistic network traffic between hosts for testing intrusion detection and reinforcement learning models.

---

## 2. Files Included
| File                 | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `sdn_topology.py`    | Launches Mininet with a predefined two-subnet topology and integrated traffic generator |

---

## 3. Network Topology
The topology includes:
- Two Open vSwitch (OVS) switches: `s1`, `s2`
- Six hosts: `h1`-`h3` on `s1`, `h4`-`h6` on `s2`
- Subnets:
  - `10.0.1.0/24` on `s1` side
  - `10.0.2.0/24` on `s2` side
- A direct link between `s1` and `s2`
- Default routes set for each host
- Integration with a remote Ryu controller at `127.0.0.1:6633`

```
     h1   h2   h3        h4   h5   h6
      \   |   /          \   |   /
       \  |  /            \  |  /
         s1 -------------- s2
```

---

## 4. Traffic Generation
- Embedded in `sdn_topology.py` via a custom Mininet CLI command: `genTraffic`
- Randomly selects source-destination host pairs
- Simulates:
  - TCP/UDP using `iperf`
  - ICMP with `ping` or `ping -f`
  - Application-like requests with `curl` and `netcat`
- Mixes bursty and background flows
- Supports bi-directional and many-to-one traffic patterns

---

## 5. Usage Instructions
Run the script:
```bash
cd src/mininet
sudo python3 sdn_topology.py
```
This opens the Mininet CLI. Inside the CLI, run:
```bash
mininet> genTraffic
```
This triggers randomized traffic between hosts.

---

## 6. Customization
To modify the behavior:
- Change the number or IPs of hosts in `SDNTopo`
- Edit traffic types or timing in the `genTraffic` command logic
- Adjust subnet settings, default gateways, or link delays if needed

---

## 7. Dependencies
Make sure these are installed:
```bash
sudo apt install mininet iperf netcat curl
```

---

## 8. Future Enhancements
- Add flow labeling for supervised learning
- Interface with RL agent to adapt traffic patterns
- Extend to support DNS, QUIC, or custom protocol simulations

---

For project-wide instructions, refer to the root `README.md`.

