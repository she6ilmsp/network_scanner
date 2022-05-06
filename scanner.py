#!/usr/bin/python3

from scapy import all as scapy

ip = "172.20.10.1/24"

arp_request = scapy.ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
ans_list = scapy.sr(arp_request, timeout=1, verbose=False)[0]
print("IP Address\t\tMAC Address\n")
for ans in ans_list:
    print(ans[1].psrc + "\t\t" + ans[1].hwsrc)