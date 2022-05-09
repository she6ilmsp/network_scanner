#!/usr/bin/python3

import scapy.all as scapy


def sniffer(interface):
    scapy.sniff(iface=interface, prn=processing_sniffer, store=False)

def get_mac(ip_add):
    packet = scapy.ARP(op=1, pdst=ip_add, hwdst="ff:ff:ff:ff:ff:ff")
    ans_list = scapy.sr(packet)[0]
    return ans_list[0][1].hwsrc

def processing_sniffer(packet):
    if packet.haslayer(scapy.ARP) and "is-at" in str(packet[scapy.ARP].op):
        try:
            source_ip = packet[scapy.ARP].psrc
            source_mac = packet[scapy.ARP].hwsrc
            origin_mac = get_mac(source_ip)
            if source_mac != origin_mac:
                print("[***] You are under MITM attack...!!!")
        except IndexError:
            pass

sniffer("wlp2s0")

