from mininet.topo import Topo
from mininet.link import TCLink

class Lab0Topo(Topo):
    def build(self):
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add links with bandwidth and delay
        self.addLink(h1, s1, bw=15, delay='10ms')
        self.addLink(h2, s1, bw=15, delay='10ms')
        self.addLink(h3, s2, bw=15, delay='10ms')
        self.addLink(h4, s2, bw=15, delay='10ms')
        self.addLink(s1, s2, bw=20, delay='45ms')

topos = {
    'lab0topo': Lab0Topo
}
