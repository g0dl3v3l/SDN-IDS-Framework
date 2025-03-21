from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types

class SimpleRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)
        # L2 learning table for non-IP packets.
        self.mac_to_port = {}

        # Static host mapping: IP -> {dpid, port, mac}
        self.hosts = {
            '10.0.1.1': {'dpid': 1, 'port': 1, 'mac': '00:00:00:00:00:01'},
            '10.0.1.2': {'dpid': 1, 'port': 2, 'mac': '00:00:00:00:00:02'},
            '10.0.1.3': {'dpid': 1, 'port': 3, 'mac': '00:00:00:00:00:03'},
            '10.0.2.1': {'dpid': 2, 'port': 1, 'mac': '00:00:00:00:00:04'},
            '10.0.2.2': {'dpid': 2, 'port': 2, 'mac': '00:00:00:00:00:05'},
            '10.0.2.3': {'dpid': 2, 'port': 3, 'mac': '00:00:00:00:00:06'},
        }
        # Router interface info per switch.
        # For example, switch 1 (dpid 1) uses 10.0.1.254/XX with MAC 00:00:00:00:01:fe
        # and switch 2 (dpid 2) uses 10.0.2.254 with MAC 00:00:00:00:02:fe.
        # 'inter_port' is the port connecting to the other switch.
        self.router_interfaces = {
            1: {'ip': '10.0.1.254', 'mac': '00:00:00:00:01:fe', 'inter_port': 4},
            2: {'ip': '10.0.2.254', 'mac': '00:00:00:00:02:fe', 'inter_port': 4}
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow entry."""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Utility method to install a flow entry."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Main packet-in handler."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # Ignore LLDP packets.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt, msg.data)
            return

        if ip_pkt:
            self.handle_ip(datapath, in_port, eth, ip_pkt, pkt, msg)
            return

        # Fallback: L2 learning and forwarding.
        self.l2_forward(datapath, in_port, eth, msg)

    def l2_forward(self, datapath, in_port, eth, msg):
        """Simple L2 forwarding when no IP/ARP processing is needed."""
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = in_port
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, in_port, eth, arp_pkt, data):
        """ARP handling: reply if the ARP request targets the router interface."""
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        router_ip = self.router_interfaces.get(dpid, {}).get('ip')
        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == router_ip:
            self.logger.info("ARP request for router interface on dpid %s", dpid)
            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                src=self.router_interfaces[dpid]['mac'],
                dst=eth.src))
            arp_reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=self.router_interfaces[dpid]['mac'],
                src_ip=router_ip,
                dst_mac=eth.src,
                dst_ip=arp_pkt.src_ip))
            arp_reply.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=arp_reply.data)
            datapath.send_msg(out)
        else:
            # Flood ARP requests not for the router interface.
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=data)
            datapath.send_msg(out)

    def handle_ip(self, datapath, in_port, eth, ip_pkt, pkt, msg):
        """Handle IPv4 packets with L3 routing.
        
        Two cases:
         1. Packet from a local host destined for a remote host:
            - Rewrites Ethernet header with router MAC addresses and sends out via inter-switch link.
         2. Packet arriving on a switch from the inter-switch link destined for a local host:
            - Rewrites the destination MAC to the actual host MAC before delivering.
        """
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info("Handling IPv4 packet on dpid %s: %s -> %s",
                         dpid, ip_pkt.src, ip_pkt.dst)

        # If the packet is destined to one of the router interfaces, process it locally.
        if ip_pkt.dst in [self.router_interfaces[x]['ip'] for x in self.router_interfaces]:
            self.logger.info("Packet destined to router interface; processing locally.")
            return

        if ip_pkt.dst in self.hosts:
            dst_info = self.hosts[ip_pkt.dst]
            # Case 1: Packet from a local host destined for a remote host.
            if dst_info['dpid'] != dpid:
                # On the sending switch: rewrite to use router interfaces.
                out_port = self.router_interfaces[dpid]['inter_port']
                remote_dpid = dst_info['dpid']
                new_eth_src = self.router_interfaces[dpid]['mac']
                new_eth_dst = self.router_interfaces[remote_dpid]['mac']
                actions = [
                    parser.OFPActionSetField(eth_src=new_eth_src),
                    parser.OFPActionSetField(eth_dst=new_eth_dst),
                    parser.OFPActionOutput(out_port)
                ]
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst)
                self.add_flow(datapath, 10, match, actions, idle_timeout=30)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port,
                                          actions=actions,
                                          data=data)
                datapath.send_msg(out)
            else:
                # Case 2: Packet destined for a local host.
                # If the packet arrives via the inter-switch link, its eth_dst is still set to the router's MAC.
                # In that case, rewrite the destination MAC to the host's MAC.
                if in_port == self.router_interfaces[dpid]['inter_port']:
                    actions = [
                        parser.OFPActionSetField(eth_dst=dst_info['mac']),
                        parser.OFPActionOutput(dst_info['port'])
                    ]
                else:
                    actions = [parser.OFPActionOutput(dst_info['port'])]
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst)
                self.add_flow(datapath, 10, match, actions, idle_timeout=30)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port,
                                          actions=actions,
                                          data=data)
                datapath.send_msg(out)
        else:
            # Unknown destination: flood.
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
