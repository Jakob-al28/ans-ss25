"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, arp, ether_types, tcp, udp, icmp

import ipaddress

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_port_map = {}

        # Maps IP to (port, MAC)
        self.ip_to_mac_port = {}
    
        # Router DPID
        self.router_dpid = 3 # Assuming the router is switch s3

        # Map each subnet (based on IP/mask) to the correct router port for proper forwarding
        self.subnet_to_port = {
            ipaddress.ip_network("10.0.1.0/24"): 1,
            ipaddress.ip_network("10.0.2.0/24"): 2,
            ipaddress.ip_network("192.168.1.0/24"): 3
        }


        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        self.packet_buffer = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']  # port where the packet came in
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst  # destination MAC
        src = eth.src  # source MAC

        # Seperate logic for router and switch
        if datapath.id == self.router_dpid:
            self.handle_router_logic(pkt, datapath, msg, in_port, src, dst)
        else:
            self.handle_switch_logic(pkt, datapath, msg, in_port, src, dst)


    def handle_switch_logic(self, pkt, datapath, msg, in_port, src, dst):
        datapath_id = datapath.id # ID of switch
        ofp = datapath.ofproto # OpenFlow protocol version used by the switch
        ofpparser = datapath.ofproto_parser # Parser to create OpenFlow messages

        # Check if the switch ID is not already in the MAC-to-port map
        if datapath_id not in self.mac_port_map:
            self.mac_port_map[datapath_id] = {}
        
        self.mac_port_map[datapath_id][src] = in_port # Learn the source MAC and remember which port it came from

        # Check if the destination MAC is already in the MAC-to-port map
        if dst in self.mac_port_map[datapath_id]:
            out_port = self.mac_port_map[datapath_id][dst]
        else:
            out_port = ofp.OFPP_FLOOD  # flood it if we don’t know

        actions = [ofpparser.OFPActionOutput(out_port)]  # Tell the switch to send the packet out through the correct port

        # If we know where to send the packet (not flooding):
        if out_port != ofp.OFPP_FLOOD:
            # Create a match rule: if a packet comes from this source to this destination on this port
            match = ofpparser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Add a flow to the switch so it handles similar future packets by itself (no need to ask the controller again)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # Build a packet-out message to send this specific packet right now
        out = ofpparser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)



    def handle_router_logic(self, pkt, datapath, msg, in_port, src, dst):
        ofp = datapath.ofproto # OpenFlow protocol version used by the router
        ofpparser = datapath.ofproto_parser # Parser to create OpenFlow messages
        # The router is basically another OpenFlow switch with extra logic, which is why OpenFlow protocol is used here as well.

        # Check for ARP packet first
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            print(f"[Router] Got ARP packet: {arp_pkt.src_ip} → {arp_pkt.dst_ip}")

            # Learn from ARP replies (e.g., when ser replies to our request)
            self.ip_to_mac_port[arp_pkt.src_ip] = (in_port, arp_pkt.src_mac)

            if arp_pkt.opcode == arp.ARP_REQUEST:
                # Get incoming port and source IP of the ARP request
                target_ip = arp_pkt.dst_ip

                # See if the target IP is one of the router’s IPs
                for port, ip in self.port_to_own_ip.items():
                    if target_ip == ip:
                        # Send ARP reply
                        src_mac = self.port_to_own_mac[port]

                        arp_reply = packet.Packet() # Create a new empty packet, this will hold our ARP reply
                        # Add the Ethernet header for the ARP reply  
                        arp_reply.add_protocol(ethernet.ethernet(
                            ethertype=ether_types.ETH_TYPE_ARP,
                            src=src_mac,
                            dst=arp_pkt.src_mac
                        ))
                        # Add the actual ARP protocol content to the packet
                        arp_reply.add_protocol(arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=src_mac,
                            src_ip=target_ip,
                            dst_mac=arp_pkt.src_mac,
                            dst_ip=arp_pkt.src_ip
                        ))
                        arp_reply.serialize() # Prepare the packet so it can actually be sent
                        # Define the action: send the reply out of the same port the ARP request came in
                        actions = [ofpparser.OFPActionOutput(in_port)]
                        out = ofpparser.OFPPacketOut(
                            datapath=datapath,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=ofp.OFPP_CONTROLLER,
                            actions=actions,
                            data=arp_reply.data
                        )
                        datapath.send_msg(out)
                        print(f"[Router] Replied to ARP request for {target_ip}")
                        return

            elif arp_pkt.opcode == arp.ARP_REPLY:
                # Already learned above, but now handle buffered packet
                if arp_pkt.src_ip in self.packet_buffer:
                    buffered_msg, buffered_in_port, buffered_src_ip = self.packet_buffer.pop(arp_pkt.src_ip)
                    
                    router_mac = self.port_to_own_mac[in_port]
                    dst_mac = arp_pkt.src_mac

                    actions = [
                        ofpparser.OFPActionSetField(eth_src=router_mac),
                        ofpparser.OFPActionSetField(eth_dst=dst_mac),
                        ofpparser.OFPActionOutput(in_port)
                    ]

                    match = ofpparser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_dst=arp_pkt.src_ip,
                        ipv4_src=buffered_src_ip
                    )

                    self.add_flow(datapath, 1, match, actions)

                    out = ofpparser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=buffered_in_port,
                        actions=actions,
                        data=buffered_msg.data
                    )
                    datapath.send_msg(out)
                    print(f"[Router] Sent buffered packet to {arp_pkt.src_ip}")
                    
        # Check if it's an IPv4 packet
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ip_pkt:
            dst_ip = ip_pkt.dst
            src_ip = ip_pkt.src
            print(f"[Router] Got IPv4 packet: {src_ip} -> {dst_ip}")
        else:
            return

        # Learn the sender's IP → (port, MAC) mapping for future routing/ARP replies    
        self.ip_to_mac_port[src_ip] = (in_port, src)

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        src_ip_obj = ipaddress.ip_address(src_ip)
        dst_ip_obj = ipaddress.ip_address(dst_ip)

        # Block all traffic where one side is external and the other is internal
        ext_net = ipaddress.ip_network("192.168.1.0/24")
        internal_nets = [
            ipaddress.ip_network("10.0.1.0/24"),
            ipaddress.ip_network("10.0.2.0/24")
        ]

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if (
            src_ip_obj in ext_net and
            any(dst_ip_obj in net for net in internal_nets) and
            icmp_pkt
        ):
            print(f"[Router] Blocked ICMP from ext {src_ip} to internal {dst_ip}")
            return
 
        # Allow TCP/UDP between ext and h1/h2 (only block ext <-> ser)
        l4_tcp = pkt.get_protocol(tcp.tcp)
        l4_udp = pkt.get_protocol(udp.udp)

        if (
            ((src_ip_obj in ext_net and dst_ip_obj in ipaddress.ip_network("10.0.2.0/24")) or
            (dst_ip_obj in ext_net and src_ip_obj in ipaddress.ip_network("10.0.2.0/24")))
            and (l4_tcp or l4_udp)
        ):
            print(f"[Router] Blocked TCP/UDP between ext ({src_ip}) and ser ({dst_ip})")
            return

     
        # Convert the destination IP to an IP object for comparison
        dst_ip_obj = ipaddress.ip_address(dst_ip)

        out_port = None
        # Find the correct output port by checking which subnet the destination IP belongs to
        for subnet, port in self.subnet_to_port.items():
            if dst_ip_obj in subnet:
                out_port = port
                break

        if out_port is None:
            print(f"[Router] Unknown destination {dst_ip}, dropping.")
            return
        
        # Do we know how to reach the destination IP?
        if dst_ip in self.ip_to_mac_port:
            dst_mac_port = self.ip_to_mac_port[dst_ip]
            dst_mac = dst_mac_port[1]  # MAC of destination
            router_mac = self.port_to_own_mac[out_port] # MAC of the router's outgoing interface

            # Define actions: set the correct Ethernet source and destination MACs, then output to the correct port
            actions = [
                ofpparser.OFPActionSetField(eth_src=router_mac),
                ofpparser.OFPActionSetField(eth_dst=dst_mac),
                ofpparser.OFPActionOutput(out_port)
            ]

            # Match rule: match IPv4 packets from src_ip to dst_ip
            match = ofpparser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_dst=dst_ip, # Destination IP matches
                ipv4_src=src_ip  # Source IP matches
            )

            # Install flow so similar future packets are forwarded by the switch/router without involving the controller
            self.add_flow(datapath, 1, match, actions)

            out = ofpparser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)

            print(f"[Router] Forwarded {src_ip} → {dst_ip} via port {out_port}")

        else:
            print(f"[Router] Don't know MAC for {dst_ip} yet, waiting for ARP.")
            self.packet_buffer[dst_ip] = (msg, in_port, src_ip)
            # Send an ARP request to discover the MAC address
            dst_ip_obj = ipaddress.ip_address(dst_ip)

            for subnet, port in self.subnet_to_port.items():
                if dst_ip_obj in subnet:
                    router_mac = self.port_to_own_mac[port]
                    router_ip = self.port_to_own_ip[port]

                    arp_req = packet.Packet()
                    # Add the Ethernet header for the ARP request
                    arp_req.add_protocol(ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        src=router_mac, # Source MAC: router's MAC (on the outgoing port)
                        dst="ff:ff:ff:ff:ff:ff" # Destination MAC: broadcast to all hosts
                    ))
                    # Add the ARP message asking: "Who has dst_ip? Tell me your MAC"
                    arp_req.add_protocol(arp.arp(
                        opcode=arp.ARP_REQUEST,             # This is an ARP request, not a reply
                        src_mac=router_mac,                 # MAC of the router (asking the question)
                        src_ip=router_ip,                   # IP of the router (source IP)
                        dst_mac="00:00:00:00:00:00",        # Placeholder since we don't know the target's MAC
                        dst_ip=dst_ip                       # The IP we're trying to find the MAC for
                    ))
                    arp_req.serialize()

                    actions = [ofpparser.OFPActionOutput(port)]
                    out = ofpparser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER,
                        actions=actions,
                        data=arp_req.data
                    )
                    datapath.send_msg(out)
                    print(f"[Router] Sent ARP request for {dst_ip} on port {port}")
                    break
