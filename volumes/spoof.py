#!/usr/bin/env python3
from scapy.all import *

a = IP(id=1)
a.dst = '10.9.0.5'
a.src = '8.8.8.8'
b = ICMP(seq=2, id=1)
p = a / b
send(p)
