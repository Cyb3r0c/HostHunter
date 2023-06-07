import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.simplefilter("ignore", CryptographyDeprecationWarning)

import scapy.all as scapy
import netifaces
import socket
from mac_vendor_lookup import MacLookup
import argparse

banner= """
     _   _                           _   _                                                        
    | | | |   ___     _____  ______ | | | |  _   _   __    _ _______ _____   ______               
    | |_| |  / _  \  /  ___||__  __|| |_| | | | | | |  \  | |__  __||  ___| |  __  |
    |     | | | | | |  (_     | |   |     | | | | | |   \ | |  | |  | |___  | |__/ |   
    | |-| | | | | |  \_  \    | |   | |-| | | | | | | |\ \| |  | |  |  ___| |  _  /    
    | | | | | |_| | ___)  |   | |   | | | | | |_| | | | \   |  | |  | |___  | | \ \    
    |_| |_|  \___/ |_____ /   |_|   |_| |_| |_____| |_|  \__|  |_|  |_____| |_|  \_\ 
   

    HostHunter - Network mapper and device locator version 0.1
    Developed by Jose Ramon Ramirez Roca (Cyb3r0c) 
    """
print(banner)

#argument parser

def parse_network():
    # Create the argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('network' ,help='Network address to parse (CIDR notation) - Example: 192.168.0.0/24')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Access the parsed network address
    network = args.network

    return network





def scan_network(network_segment):
    arp_request = scapy.ARP(pdst=network_segment)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    hosts = []
    for response in answered:
        host = {"ip": response[1].psrc, "mac": response[1].hwsrc}
        hosts.append(host)

    return hosts



#Finds the default gateway

def find_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
    if default_gateway:
        return default_gateway[0]
    return None




# find the hostname of the device
def get_remote_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Hostname not found"



#Identifies the OS
def analyze_ttl(target_ip):
    # Create an ICMP packet (Echo Request)
    packet = scapy.IP(dst=target_ip) / scapy.ICMP()

    # Send the packet and receive the response
    response = scapy.sr1(packet, timeout=1, verbose=False)

    # Check if a response was received
    if response is not None:
        ttl = response.ttl
        

        if ttl <= 64:
            print("[*] Linux System")
        elif ttl <= 128 and ttl > 64:
            print("[*] Windows System")
        else:
            print("[*] Probably a Solaris/Cisco/FreeBSD system")
    else:
        print("[x] No response received.")



####  MAIN  CODE STARTS #### 

# Parses the network provided at the comand execution
parse_net = parse_network()

hosts = scan_network(parse_net)




for host in hosts:
    print("**************************************************************************")
    print(f"[*] IP: {host['ip']}\t MAC: {host['mac']}")
    try:
       vendor = MacLookup().lookup(host['mac'])
       print(f"[-] Vendor: {vendor}")
    except:
       print("No MAC vendor information could be retrieved" )

    ip_address = host['ip']
    hostname = get_remote_hostname(ip_address)
    analyze_ttl(ip_address)
    print("[!] Hostname> ",hostname)
    print("**************************************************************************")

# Call the function to find the default gateway
default_gateway = find_default_gateway()

if default_gateway:
    print("[*]Default Gateway:", default_gateway)
else:
    print("Default gateway not found.")
for host in hosts:
    print(f"{host['ip']}")
