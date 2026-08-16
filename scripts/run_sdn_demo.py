#!/usr/bin/python3
"""
Sentinel SDN Demo Topology (Mininet)
Creates:
  h1 (Attacker) --- [ OVS Switch (s1) ] --- h2 (Target)
                          |
                      h3 (Honeypot Sink)
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def sentinel_topo():
    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3') # Honeypot IP

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info('*** Starting network\n')
    net.build()
    s1.start([])

    info('*** Post-startup configuration\n')
    # Optional: Start a simple listener on h2 to act as a target
    h2.cmd('python3 -m http.server 80 &')
    
    info('*** Sentinel SDN Demo Ready\n')
    info('Use h1 to attack h2: h1 ping -c 4 10.0.0.2\n')
    info('Observe SDN mitigation in the Sentinel Dashboard\n')
    
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    sentinel_topo()
