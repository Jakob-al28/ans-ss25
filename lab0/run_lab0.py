from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI

# Import the topology class from your other file
from lab0_topo import Lab0Topo

def run():
    topo = Lab0Topo()
    net = Mininet(topo=topo, link=TCLink)
    net.start()

    print("Running ping test...")
    net.pingAll()

    print("Dropping to Mininet CLI...")
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
