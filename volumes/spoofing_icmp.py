#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP


def spoof(x):
    if receive[0][ICMP].type == 8:
        print(receive[0][IP].src)
        b = ICMP(seq=2, id=1, type=0)
        a = IP(id=1)
        a.dst = receive[0][IP].src
        a.src = receive[0][IP].dst
        # a.ttl = ttl
        p = a / b / Raw(load=receive[0])
        send(p)
        print(p.show())


receive = sniff(iface=['br-919b07b9d385'], filter='icmp',
                count=13, prn=spoof)
#prn=lambda x: x.show()
