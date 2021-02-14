#!/usr/bin/env python3
from scapy.all import *
a = IP(id=1)
a.dst = '1.2.3.4'
b = ICMP(seq=2,id=1)
p = a/b/"ping"
r,u=sr(p)
r.show()

