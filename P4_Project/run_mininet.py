from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
from p4_mininet import P4Host, P4GrpcSwitch
import json
import argparse
import subprocess
import sys
import os
import psutil
parser = argparse.ArgumentParser(description="Mininet demo")
parser.add_argument(
    "--num-hosts",
    help="Number of hosts to connect to switch",
    type=int,
    action="store",
    default=1,
)
parser.add_argument(
    "--p4-file", help="Path to P4 file", type=str, action="store", required=False
)
args = parser.parse_args()
def get_all_virtual_interfaces():
    try:
        return (
            subprocess.check_output(
                ["ip addr | grep s.-eth. | cut -d':' -f2 | cut -d'@' -f1"], shell=True
            )
            .decode(sys.stdout.encoding)
            .splitlines()
        )
    except subprocess.CalledProcessError as e:
        print("Cannot retrieve interfaces.")
        print(e)
        return ""

class MultiSwitchTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, topo_file, sw_path, json_path, n, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        hosts = topo['hosts']
        switches = topo['switches']
        links=topo['links']
        for sw in switches:
            switch = self.addSwitch(
                switches[sw]["name"],
                sw_path=sw_path,
                json_path=json_path,
                grpc_port=switches[sw]["grpc_port"],
                thrift_port=int(switches[sw]["thrift_port"]),
                device_id=int(switches[sw]["device_id"]),
                cpu_port="255",
            )
        for h in hosts:
            host=self.addHost(h, ip=hosts[h]["ip"],mac =hosts[h]["mac"])
        for link in links:
            if len(link) == 3:
                host = link[0]
                switch = link[1]
                port=link[2]
                self.addLink(host, switch, port)
            if len(link) == 4:
                switch1 = link[0]
                switch2 = link[1]
                port1=link[2]
                port2=link[3]
                self.addLink(switch1, switch2, port1, port2)
def main():
    num_hosts = int(args.num_hosts)
    result = os.system(
        "p4c --target bmv2 --arch v1model --p4runtime-files switch_config.p4info.txt "
        + args.p4_file
    )
    p4_file = args.p4_file.split("/")[-1]
    json_file = p4_file.split(".")[0] + ".json"
    topo = MultiSwitchTopo("topology.json", "simple_switch_grpc", json_file, num_hosts)
    net = Mininet(
        topo=topo, host=P4Host, switch=P4GrpcSwitch, link=TCLink, controller=None
    )
    net.start()
    hosts=net.hosts
    with open('topology.json', 'r') as f:
        topology = json.load(f)
    hosts_dict=topology["hosts"]
    for host in hosts:
        name=host.name
        host_inf=hosts_dict.get(name)
        commands_string= host_inf.get("commands")
        host.cmd(commands_string[0])
        host.cmd(commands_string[1])

    interfaces = get_all_virtual_interfaces()
    for i in interfaces:
        if i != "":
            os.system("ip link set {} mtu 1600 > /dev/null".format(i))
            os.system("ethtool --offload {} rx off  tx off > /dev/null".format(i))
    net.staticArp()
    if result != 0:
        print("Error while compiling!")
        exit()
    switch_running = "simple_switch_grpc" in (p.name() for p in psutil.process_iter())
    if switch_running == False:
        print("The switch didnt start correctly! Check the path to your P4 file!!")
        exit()
    print("Starting mininet!")
    print('')
    print('======================================================================')
    print('Welcome to the BMV2 Mininet CLI!')
    print('======================================================================')
    print('Your P4 program is installed into the BMV2 software switch')
    print('and your initial runtime configuration is loaded. You can interact')
    print('with the network using the mininet CLI below.')
    print('')
    print('To inspect or change the switch configuration, connect to')
    print('its CLI from your host operating system using this command:')
    print('  simple_switch_CLI --thrift-port <switch thrift port>')
    print('')
    CLI(net)
    os.system("rm *.log*")
    os.system("sudo mn -c")
if __name__ == "__main__":
    setLogLevel("info")
    main()
