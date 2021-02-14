#!/usr/bin/env python3
from scapy.all import *


def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface=['br-919b07b9d385'],
            filter='icmp and src host 10.9.0.5', count=1, prn=print_pkt)
