#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP


def routing(ttl: int, ip: str):
    id_c = 0
    return_list = list()
    for i in range(ttl):
        id_c += 1
        b = ICMP(seq=id_c, id=1)
        a = IP(id=id_c)
        a.dst = ip
        a.ttl = i + 1
        p = a / b
        send(p)
        pkta = sniff(filter='icmp', timeout=3, count=3)
        if len(pkta) > 0:
            for k in pkta[0]:
                for p in k:
                    return_list.append((p, i + 1))

    n = 0
    for i in return_list:
        if i[0][IP].src != get_if_addr(conf.iface):
            n += 1
            print(f"{i[1]} : ", i[0][IP].src, " -> ", i[0][IP].dst)
            if i[0][IP].src == ip:
                break
    return return_list

if __name__ == '__main__':
    print(get_if_addr(conf.iface))
    ip = '8.8.8.8'
    f = routing(15, ip)
