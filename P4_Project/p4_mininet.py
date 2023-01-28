from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info


class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print("**********")
        print(self.name)
        print(
            "default interface: %s\t%s\t%s"
            % (
                self.defaultIntf().name,
                self.defaultIntf().IP(),
                self.defaultIntf().MAC(),
            )
        )
        print("**********")


"""class P4Switch(Switch):
    #P4 virtual switch

    device_id = 0

    def __init__(
        self,
        name,
        sw_path=None,
        json_path=None,
        grpc_port=None,
        thrift_port=None,
        pcap_dump=False,
        verbose=False,
        device_id=None,
        enable_debugger=False,
        cpu_port=None,
        **kwargs
    ):
        Switch.__init__(self, name, **kwargs)
        assert sw_path
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.cpu_port = cpu_port
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-%d-log.ipc" % self.device_id

    @classmethod
    def setup(cls):
        pass

    def start(self, controllers):
        "Start up a new P4 switch"
        print("Starting P4 switch", self.name)
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(["-i", str(port) + "@" + intf.name])
        if self.pcap_dump:
            args.append("--pcap")
        args.extend(["--device-id", str(self.device_id)])
        P4Switch.device_id += 1
        notificationAddr = (
            "ipc:///tmp/bmv2-" + str(self.device_id) + "-notifications.ipc"
        )
        args.extend(["--notifications-addr", str(notificationAddr)])
        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")
        if self.enable_debugger:
            args.append("--debugger")
        args.append("-- --enable-swap")
        logfile = "p4s.%s.log" % self.name
        print(" ".join(args))

        self.cmd(" ".join(args) + " >" + logfile + " 2>&1 &")

        print("switch has been started")

    def stop(self):
        "Terminate IVS switch."
        self.output.flush()
        self.cmd("kill %" + self.sw_path)
        self.cmd("wait")
        self.deleteIntfs()

    def attach(self, intf):
        "Connect a data port"
        assert 0

    def detach(self, intf):
        "Disconnect a data port"
        assert 0
"""

class P4GrpcSwitch(Switch):
    """P4 virtual switch"""

    device_id = 0

    def __init__(
        self,
        name,
        sw_path=None,
        json_path=None,
        thrift_port=None,
        grpc_port=None,
        pcap_dump=False,
        verbose=False,
        device_id=None,
        enable_debugger=False,
        cpu_port=None,
        **kwargs
    ):
        Switch.__init__(self, name, **kwargs)
        assert sw_path
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        self.thrift_port = thrift_port
        self.grpc_port = grpc_port
        self.enable_debugger = enable_debugger
        self.cpu_port = cpu_port
        if device_id is not None:
            self.device_id = device_id
            P4GrpcSwitch.device_id = max(P4GrpcSwitch.device_id, device_id)
        else:
            self.device_id = P4GrpcSwitch.device_id
            P4GrpcSwitch.device_id += 1

    @classmethod
    def setup(cls):
        pass

    def start(self, controllers):
        "Start up a new P4 switch"
        print("Starting P4 switch", self.name)
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(["-i", str(port) + "@" + intf.name])
        if self.thrift_port:
            args.extend(["--thrift-port", str(self.thrift_port)])

        args.extend(["--device-id", str(self.device_id)])
        P4GrpcSwitch.device_id += 1
        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")

        args.append("--log-flush --log-level trace --log-file %s.log" % self.name)
        if self.grpc_port:
            args.append(
                "-- --grpc-server-addr 0.0.0.0:"
                + str(self.grpc_port)
                + " --cpu-port "
                + self.cpu_port
            )
        print(" ".join(args))
        self.cmd(" ".join(args) + " > %s.log 2>&1 &" % self.name)
        print("switch has been started")

    def stop(self):
        "Terminate IVS switch."
        self.cmd("kill %" + self.sw_path)
        self.cmd("wait")
        self.deleteIntfs()

    def attach(self, intf):
        "Connect a data port"
        assert 0

    def detach(self, intf):
        "Disconnect a data port"
        assert 0
