import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP

def packet_listen(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)  # prn --> callback function


def analyze_packets(packet):
    if packet.haslayer(HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


packet_listen() # write a interface like ---> packet_listen("eth0") 