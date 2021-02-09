#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface=['br-a4f9ade18181', 'br-919b07b9d385'], filter='icmp', prn=print_pkt)
