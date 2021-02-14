#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP


def spoof(x):
    if x[ICMP].type == 8:
        b = ICMP(seq=x[ICMP].seq, id=x[ICMP].id, type=0)
        a = IP()
        a.dst = x[IP].src
        a.src = x[IP].dst
        p = a / b / x[3]
        send(p,iface='br-45a48e422bd6')
        print(p.show())


receive = sniff(iface=['br-45a48e422bd6'], filter='icmp',
                count=10, prn=spoof)

