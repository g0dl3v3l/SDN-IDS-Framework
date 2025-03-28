#!/usr/bin/env python3

from mininet.topo import Topo 
from mininet.net import Mininet
from mininet.node import RemoteController ,OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial

import random
import time
import threading

class SDNTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Hosts in subnet 10.0.1.0/24 with default gateway 10.0.1.254
        h1 = self.addHost('h1', ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        h2 = self.addHost('h2', ip='10.0.1.2/24', defaultRoute='via 10.0.1.254')
        h3 = self.addHost('h3', ip='10.0.1.3/24', defaultRoute='via 10.0.1.254')

        # Hosts in subnet 10.0.2.0/24 with default gateway 10.0.2.254
        h4 = self.addHost('h4', ip='10.0.2.1/24', defaultRoute='via 10.0.2.254')
        h5 = self.addHost('h5', ip='10.0.2.2/24', defaultRoute='via 10.0.2.254')
        h6 = self.addHost('h6', ip='10.0.2.3/24', defaultRoute='via 10.0.2.254')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        self.addLink(s1, s2)


# ---------------- Traffic Generation Functions ---------------- #

def run_iperf_tcp(src, dst):
    dst.cmd('iperf -s -p 5001 &')
    time.sleep(0.3)
    src.cmd(f'iperf -c {dst.IP()} -p 5001 -t 5 &')

def run_iperf_udp(src, dst):
    dst.cmd('iperf -s -u -p 5002 &')
    time.sleep(0.3)
    src.cmd(f'iperf -u -c {dst.IP()} -p 5002 -t 5 -b 1M &')

def run_ping(src, dst):
    src.cmd(f'ping -c 10 -i 0.5 {dst.IP()} > /dev/null 2>&1 &')

def run_http_curl(src, dst):
    dst.cmd('python3 -m http.server 8080 &')
    time.sleep(0.3)
    src.cmd(f'curl http://{dst.IP()}:8080 > /dev/null 2>&1 &')

def run_ddos_burst(attackers, victim):
    for attacker in attackers:
        cmd = f'ping -f -c 100 {victim.IP()} > /dev/null 2>&1 &'
        attacker.cmd(cmd)

def start_traffic(net, duration=30):
    print("[*] Starting randomized traffic generation...\n")
    hosts = net.hosts
    start_time = time.time()

    def delayed_ddos():
        time.sleep(5)
        victim = random.choice(hosts)
        attackers = random.sample([h for h in hosts if h != victim], 3)
        print(f"[!] Simulating DDoS burst on {victim.name} from {[a.name for a in attackers]}")
        run_ddos_burst(attackers, victim)

    #threading.Thread(target=delayed_ddos, daemon=True).start()

    while time.time() - start_time < duration:
        src, dst = random.sample(hosts, 2)
        flow = random.choice(['tcp'])

        print(f"[*] Launching {flow.upper()} traffic: {src.name} → {dst.name}")
        if flow == 'tcp':
            run_iperf_tcp(src, dst)
        elif flow == 'udp':
            run_iperf_udp(src, dst)
        elif flow == 'ping':
            run_ping(src, dst)
        elif flow == 'http':
            run_http_curl(src, dst)

        time.sleep(random.uniform(1, 2))

    print("[*] Traffic generation completed.\n")


# ---------------- Custom CLI with genTraffic Command ---------------- #

class CustomCLI(CLI):
    def __init__(self, net):
        self.net = net
        super().__init__(net)

    def do_genTraffic(self, args):
        """Run randomized traffic generation. Usage: genTraffic"""
        print("[CLI] Launching new traffic session...")
        start_traffic(self.net, duration=30)


# ---------------- Main Mininet Startup ---------------- #

def run():
    OVSSwitch13 = partial(OVSSwitch, protocols='OpenFlow13')

    topo = SDNTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch13,
        build=False,
        waitConnected=True,
        autoSetMacs=True
    )

    info('*** Adding Ryu Controller (127.0.0.1:6633)\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1')
    net.build()
    info('*** Starting network\n')
    net.start()

    # Initial traffic (optional)
    start_traffic(net, duration=30)

    info('*** Entering Mininet CLI (you can now use: genTraffic)\n')
    CustomCLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
