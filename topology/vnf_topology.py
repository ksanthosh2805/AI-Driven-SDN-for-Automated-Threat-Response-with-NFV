from mininet.topo import Topo

class VNFTopology(Topo):
    """
    Network topology with VNF integration
    
    Structure:
    
    h1 (192.168.1.1) \
                      s1 (Switch) <----> Port 3: pfSense
    h2 (192.168.1.2) /             <----> Port 4: Suricata
                      
    The switch is controlled by Ryu which steers traffic to VNFs
    """
    
    def build(self):
        # Create main switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        # Create regular hosts
        h1 = self.addHost('h1', ip='192.168.1.10/24', mac='00:00:00:00:01:01')
        h2 = self.addHost('h2', ip='192.168.1.11/24', mac='00:00:00:00:01:02')
        h3 = self.addHost('h3', ip='192.168.1.20/24', mac='00:00:00:00:01:03')
        
        # Create VNF representation hosts
        # (In real setup, these connect to pfSense/Suricata VMs)
        vnf_fw = self.addHost('vnf-fw', ip='192.168.1.100/24',
                             mac='00:00:00:00:02:01')
        vnf_ids = self.addHost('vnf-ids', ip='192.168.1.101/24',
                              mac='00:00:00:00:02:02')
        
        # Connect regular hosts
        self.addLink(h1, s1)      # Port 1
        self.addLink(h2, s1)      # Port 2  
        self.addLink(h3, s1)      # Also port 2
        
        # Connect VNFs (these will be controlled by Ryu)
        self.addLink(vnf_fw, s1)   # Port 3 (Firewall)
        self.addLink(vnf_ids, s1)  # Port 4 (IDS)

topos = {'vnf': (lambda: VNFTopology())}