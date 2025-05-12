"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import *
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network


port_to_own_ip = {
    1: IPv4Address("10.0.1.1"),
    2: IPv4Address("10.0.2.1"),
    3: IPv4Address("192.168.1.1"),
}

port_to_subnet = {
    1: IPv4Network("10.0.1.0/24"),
    2: IPv4Network("10.0.2.0/24"),
    3: IPv4Network("192.168.1.0/24"),
}

port_to_own_mac = {
    1: "00:00:00:00:01:01",
    2: "00:00:00:00:01:02",
    3: "00:00:00:00:01:03",
}

flood_mac = "ff:ff:ff:ff:ff:ff"


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        self.mac_addresses = dict()
        self.port_mac_map = dict()
        
    # This decorator is triggered, when the switch connects and sends its feature info.        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Retrieve OpenFlow protocol version and parser from the datapath
        # The datapath is the switch that the controller is connected to
        # The feature info includes the switch's capabilities, such as the number of ports and and datapath id.
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        # If a packet doesn’t match any other rule, it will be sent to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Adds a flow rule to send packets to the controller for further processing
        # One example of a rule: send a packet out port 2 if the destination MAC is 00:00:00:00:01:02        
        self.add_flow(datapath, match, actions, priority=0) 

    # Add a flow entry to the flow-table
    # The flow table is a set of rules that the switch uses to determine how to handle packets
    def add_flow(self, datapath, match, actions, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # When a packet matches, the switch should apply the given actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match, 
            instructions=inst, 
            **kwargs # Includes priority
        )
        # The priority determines the precedence of the flow entry, with higher values taking precedence over lower ones
        datapath.send_msg(mod)

    # Send datapacket from specified port
    def forward_packet(self, datapath, out_port, data):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        datapath.send_msg(
            # Create and send an OFPPacketOut message to the switch, instructing it to forward the packet
            ofp_parser.OFPPacketOut(
                datapath=datapath, 
                buffer_id=ofp.OFP_NO_BUFFER, 
                in_port=ofp.OFPP_CONTROLLER,
                actions=[ofp_parser.OFPActionOutput(out_port)], # Forward the serialized packet out the specified switch port
                data=data
            )
        )

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # Determine if it's traffic from a switch (ID 1 or 2) or a router (ID 3)
        if datapath.id in [1, 2]:
            self._handle_switch_traffic(datapath, pkt, in_port, eth_pkt, ofp, ofp_parser)
        else:
            self._handle_router_traffic(datapath, pkt, in_port, eth_pkt, ofp, ofp_parser)


    # Handle traffic from switches
    def _handle_switch_traffic(self, datapath, pkt, in_port, eth_pkt, ofp, ofp_parser):
        print(datapath.id, datetime.now(), "ETHERNET", eth_pkt.src, eth_pkt.dst)

        # Update port mapping for source MAC address
        self.port_mac_map[eth_pkt.src] = (in_port, datetime.now() + timedelta(5))

        # Check if packet is a broadcast
        if eth_pkt.dst == flood_mac:
            self._handle_broadcast(datapath, pkt, ofp, ofp_parser)
            return

        # Handle known destination MAC address
        out_port = self._determine_output_port(eth_pkt, ofp)
        self._install_flow_rules(datapath, eth_pkt, in_port, out_port, ofp_parser)
        self.forward_packet(datapath, out_port, pkt)


    # Handle traffic from routers
    def _handle_router_traffic(self, datapath, pkt, in_port, eth_pkt, ofp, ofp_parser):
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self._handle_arp(datapath, pkt, in_port, eth_pkt, arp_pkt)
        elif ip_pkt:
            self._handle_ip(datapath, pkt, in_port, eth_pkt, ip_pkt, ofp_parser)


    # Floods the packet to all ports and installs a flow rule for future broadcasts 
    def _handle_broadcast(self, datapath, pkt, ofp, ofp_parser):
        self.forward_packet(datapath, ofp.OFPP_FLOOD, pkt) # Flood packet to all ports
        self.add_flow(
            datapath,
            ofp_parser.OFPMatch(eth_dst=flood_mac), # Match broadcast packets
            [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)],
            priority=1
        )


    # Determine the output port for a given Ethernet packet
    def _determine_output_port(self, eth_pkt, ofp):
        if eth_pkt.dst in self.port_mac_map: #  Check if destination MAC is known
            out_port, deadline = self.port_mac_map[eth_pkt.dst]
            if deadline >= datetime.now(): # Check if entry is still valid
                return out_port
            else:
                del self.port_mac_map[eth_pkt.dst]
        return ofp.OFPP_FLOOD # Default to flooding if destination is unknown


    # Installs flow rules for the given Ethernet packet in the switch's flow table
    def _install_flow_rules(self, datapath, eth_pkt, in_port, out_port, ofp_parser):
        if out_port != datapath.ofproto.OFPP_FLOOD and eth_pkt.dst in self.port_mac_map:
            # Install flow to return packet to the source port
            self.add_flow(datapath, ofp_parser.OFPMatch(eth_dst=eth_pkt.src), [
                ofp_parser.OFPActionOutput(in_port)], priority=1, hard_timeout=5)
            # Install flow to forward packet to the destination port
            self.add_flow(datapath, ofp_parser.OFPMatch(eth_dst=eth_pkt.dst), [
                ofp_parser.OFPActionOutput(out_port)], priority=1, hard_timeout=5)


    # Handles ARP requests and replies, updating the MAC-to-IP mapping
    def _handle_arp(self, datapath, pkt, in_port, eth_pkt, arp_pkt):
        print(datapath.id, datetime.now(), "ARP", arp_pkt.src_ip, arp_pkt.dst_ip)
        self.mac_addresses[IPv4Address(arp_pkt.src_ip)] = (
            arp_pkt.src_mac, datetime.now() + timedelta(5)) # Update MAC-to-IP mapping

        # Respond to ARP request directed to router IP
        if arp_pkt.opcode == arp.ARP_REQUEST and IPv4Address(arp_pkt.dst_ip) == port_to_own_ip[in_port]:
            self._send_arp_reply(datapath, in_port, eth_pkt, arp_pkt)  # Send ARP reply to the requester


    # Sends an ARP reply to the sender in response to an ARP request
    def _send_arp_reply(self, datapath, in_port, eth_pkt, arp_pkt):
        response_pkt = packet.Packet()
        response_pkt.add_protocol(
            ethernet.ethernet(  # Ethernet header, used to encapsulate the ARP packet so the switch can read and learn the MAC address
                src=port_to_own_mac[in_port], 
                dst=eth_pkt.src, 
                ethertype=eth_pkt.ethertype)
        )
        response_pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY, # ARP reply message
                src_mac=port_to_own_mac[in_port], # Router's MAC address
                src_ip=port_to_own_ip[in_port], # Router's IP address
                dst_mac=arp_pkt.src_mac, # Sender's MAC address
                dst_ip=arp_pkt.src_ip)  # Sender's IP address
        )
        self.forward_packet(datapath, in_port, response_pkt)


    # Handles IP packets, including routing, TTL decrement, and ICMP processing
    def _handle_ip(self, datapath, pkt, in_port, eth_pkt, ip_pkt, ofp_parser):
        source = IPv4Address(ip_pkt.src)
        destination = IPv4Address(ip_pkt.dst)
        print(datapath.id, datetime.now(), "IP", source, destination)

        ip_pkt.ttl -= 1
        if ip_pkt.ttl == 0:
            self._send_icmp_time_exceeded(datapath, in_port, eth_pkt, ip_pkt)
            return  # TTL expired
        
        # Determine the source and destination port based on IP ranges
        src_port, src_subnet = next(filter(lambda item: source in item[1], port_to_subnet.items())) # the in method checks for subnet membership
        dst_port, dst_subnet = next(filter(lambda item: destination in item[1], port_to_subnet.items())) # The filter maps through all items and returns the first match due to the next function

        # Update MAC mapping from IP address
        if source in port_to_subnet[in_port]:
            self.mac_addresses[source] = (eth_pkt.src, datetime.now() + timedelta(5))

        if not self._should_process_packet(eth_pkt, src_port, dst_port, pkt):
            return # Skip packet if conditions to process it are not met

        # Handle ICMP to router
        if destination == port_to_own_ip[dst_port]:
            self._handle_icmp_to_router(pkt, dst_port, dst_subnet, source, ip_pkt, eth_pkt)
            self.forward_packet(datapath, dst_port, pkt) # Forward ICMP response back to the sender
        else:
            # Route the IP packet to the appropriate destination if it's not for the router
            self._route_ip_packet(datapath, pkt, dst_port, destination, 
                                src_subnet, eth_pkt, ofp_parser)


    # Checks if the packet should be processed based on source, destination, and ICMP conditions
    def _should_process_packet(self, eth_pkt, src_port, dst_port, pkt):
        if eth_pkt.dst != port_to_own_mac[src_port]: # Check if destination MAC matches the expected port
            return False    # Blocks all pings to non local gateways, rule only applies to IP packets because call stack comes from _handle_ip
        if {src_port, dst_port} == {2, 3}:  # Block communication between server and external
            return False
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        # Block ICMP Echo Request from source port 1 to router on port 3
        # The set operation allows all combinations of source and destination ports for ext to be blocked
        if ({src_port, dst_port} == {1, 3} and 
            icmp_pkt is not None and 
            icmp_pkt.type == icmp.ICMP_ECHO_REQUEST):
            return False
        return True # Process the packet if all conditions are met else block it


    # Handles ICMP requests to the router, specifically responding to ICMP Echo Requests
    def _handle_icmp_to_router(self, pkt, dst_port, dst_subnet, source, ip_pkt, eth_pkt):
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        # Only process if it's an ICMP Echo Request and the source is within the destination subnet
        if (icmp_pkt is None or 
            icmp_pkt.type != icmp.ICMP_ECHO_REQUEST or 
            source not in dst_subnet):
            return
        
        # Swap source and destination IP and Ethernet addresses to prepare ICMP Echo Reply
        ip_pkt.src, ip_pkt.dst = ip_pkt.dst, ip_pkt.src
        eth_pkt.src, eth_pkt.dst = eth_pkt.dst, eth_pkt.src
        icmp_pkt.type = icmp.ICMP_ECHO_REPLY # Change ICMP type to Echo Reply
        icmp_pkt.csum = 0 # Reset checksum for recalculation
        ip_pkt.csum = 0 # Reset IP checksum for recalculation


    # Routes an IP packet to the destination, either directly or by flooding if unknown
    def _route_ip_packet(self, datapath, pkt, dst_port, destination, 
                        src_subnet, eth_pkt, ofp_parser):
        if destination in self.mac_addresses: # Check if the destination MAC is known
            dst_mac, deadline = self.mac_addresses[destination]
            if deadline >= datetime.now(): # Ensure the MAC entry is still valid
                self._install_ip_flow_rule(
                    datapath, destination, src_subnet, 
                    dst_port, dst_mac, ofp_parser) # Install flow rule for the known destination
                eth_pkt.dst = dst_mac # Set destination MAC to the known MAC
            else:
                eth_pkt.dst = flood_mac # Use flood MAC if the MAC entry is expired
                del self.mac_addresses[destination] 
        else:
            eth_pkt.dst = flood_mac # Use flood MAC if destination MAC is unknown
        
        eth_pkt.src = port_to_own_mac[dst_port] # Set the source MAC address
        self.forward_packet(datapath, dst_port, pkt) # Forward the packet to the destination port
        
        if eth_pkt.dst == flood_mac:
            self._send_arp_request(datapath, dst_port, destination) # Send ARP request if MAC is unknown


    # Install flow rule for routing IP packets
    def _install_ip_flow_rule(self, datapath, destination, src_subnet, 
                            dst_port, dst_mac, ofp_parser):
        self.add_flow(datapath, ofp_parser.OFPMatch(
            eth_type=ethernet.ether.ETH_TYPE_IP, # Match IP packets
            ipv4_src=(src_subnet.network_address, src_subnet.netmask), # Match source subnet
            ipv4_dst=destination # Match destination IP
        ), [
            ofp_parser.OFPActionDecNwTtl(), # Decrement TTL for the packet
            ofp_parser.OFPActionSetField(eth_src=port_to_own_mac[dst_port]), # Set source MAC
            ofp_parser.OFPActionSetField(eth_dst=dst_mac), # Set destination MAC
            ofp_parser.OFPActionOutput(dst_port), # Output to the destination port
        ], hard_timeout=5) # Set flow timeout


    # Send ARP request if the destination MAC is unknown
    def _send_arp_request(self, datapath, dst_port, destination):
        arp_request_pkt = packet.Packet()
        arp_request_pkt.add_protocol(
            ethernet.ethernet(
                src=port_to_own_mac[dst_port], 
                ethertype=ethernet.ether.ETH_TYPE_ARP) # Set the Ethernet type to ARP
        )
        arp_request_pkt.add_protocol(
            arp.arp(
                src_mac=port_to_own_mac[dst_port], # Set the source MAC address
                src_ip=port_to_own_ip[dst_port], # Set the source IP address
                dst_ip=destination) # Set the destination IP address
        )
        self.forward_packet(datapath, dst_port, arp_request_pkt) # Forward the ARP request

    # Send ICMP Time Exceeded message to the sender when TTL expires
    def _send_icmp_time_exceeded(self, datapath, in_port, eth_pkt, ip_pkt):
        print(datapath.id, datetime.now(), "ICMP Time Exceeded: TTL=0 from", ip_pkt.src)
        # Ethernet layer
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            src=port_to_own_mac[in_port], 
                dst=eth_pkt.src, 
                ethertype=eth_pkt.ethertype))
        # IP layer
        reply.add_protocol(ipv4.ipv4(
            src=port_to_own_ip[in_port],
            dst=ip_pkt.src,
            proto=inet.IPPROTO_ICMP,
            ttl=64))
        # ICMP Time Exceeded
        reply.add_protocol(icmp.icmp(
            type_=icmp.ICMP_TIME_EXCEEDED,
            code=0,
            csum=0,
            data=icmp.TimeExceeded(data=b"")))

        self.forward_packet(datapath, in_port, reply.serialize())