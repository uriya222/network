#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import sys


def routing(max_ttl: int, ip: str, max_tries: int = 3):
    problem_num = 0
    for i in range(max_ttl):
        a = IP(id=i+1)
        a.dst = ip
        a.ttl = i + 1
        b = ICMP(seq=i+1, id=1)
        p = a / b
        packet = sr1(p, verbose=0, retry=3, timeout=1)
        if packet is not None:
            print(f"{i+1} : ", packet[IP].src, " -> ", packet[IP].dst)
            if packet[IP].src == ip:
                break
        else:
            print(f"packet num {i+1} haven't received")
            problem_num = problem_num+1
            if problem_num == max_tries:
                break


if __name__ == '__main__':
    if len(sys.argv) > 1 and len(sys.argv) < 3:
        ip = sys.argv[1]
        print("my ip is:", get_if_addr(conf.iface))
        routing(30, ip)
    else:
        print(
            f"Usage: {sys.argv[0]} [ IP ] \n\nexample: {sys.argv[0]} 8.8.8.8\n")
