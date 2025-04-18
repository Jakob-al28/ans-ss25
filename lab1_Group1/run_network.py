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

#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):

    def __init__(self):

        Topo.__init__(self)

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')  # router

        # Add hosts
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        # Link options
        linkopts = dict(bw=15, delay='10ms', use_htb=True)

        # Internal network
        self.addLink(h1, s1, **linkopts)
        self.addLink(h2, s1, **linkopts)
        self.addLink(ser, s2, **linkopts)

        # Router connections
        self.addLink(s1, s3, **linkopts)  # router port 1
        self.addLink(s2, s3, **linkopts)  # router port 2
        self.addLink(ext, s3, **linkopts) # router port 3

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

# How to test:
# 1. In one Vagrant terminal, run: ryu-manager ryu.app.simple_switch_13
# 2. In another Vagrant terminal, if not already there, do: cd /vagrant/lab1_Group1
# 3. Then run the script with: sudo python3 run_network.py
# Note: If you're running this directly on Linux (not in Vagrant), adjust the path accordingly.

# Inside Mininet do: 
# mininet> nodes
# mininet> net
# mininet> pingall

# As you can see from the pingall command, the network is physically connected, but since the controller only implements basic Layer 2 logic 
# and does not handle ARP or routing across subnets, most pings will fail until smarter switch/router logic is implemented.
