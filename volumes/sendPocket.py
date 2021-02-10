#!/usr/bin/env python3
from scapy.all import *
a = IP()
a.dst = '8.8.8.8'
b = TCP()
b.port = '23'
p = a/b
send(p)
