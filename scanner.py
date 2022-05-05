#!/usr/bin/python3

from scapy import all as scapy

ip = "172.20.10.1/24"

arp_request = scapy.ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
ans, unans = scapy.sr(arp_request, timeout=1)
print("IP Address\t\tMAC Address\n")
for x in ans:
    print(x[1].psrc + "\t\t" + x[1].hwsrc)