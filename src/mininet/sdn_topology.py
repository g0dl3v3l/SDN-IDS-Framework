#!/usr/bin/env python3

from mininet.topo import Topo 
from mininet.net import Mininet
from mininet.node import RemoteController ,OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial



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
	# Ensure that the IP/port matches your Ryu controller's configuration.
	net.addController('c0', controller=RemoteController, ip='127.0.0.1')
	net.build()
	info('*** Starting network\n')
	net.start()

	info('*** Running CLI\n')
	CLI(net)


	info('*** Stoping network \n')
	net.stop()


if __name__ == '__main__':
	setLogLevel('info')
	run()











