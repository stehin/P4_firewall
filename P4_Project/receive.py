#!/usr/bin/env python3
import os
import sys

from gss_header import gss
from scapy.all import IP, TCP, get_if_list, sniff



def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
        if IP in pkt:
            if pkt.getlayer(IP).ttl < 64: #to print only the received packet
                if TCP in pkt:
                    print("got a TCP packet")
                if gss in pkt:
                    print("got a gss packet")
                pkt.show2()
                sys.stdout.flush()
def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
