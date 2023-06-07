# HostHunter
Easy and simple tool to perform initial reconnaissance and obtain device information within a subnet. Please note that as this is the first version, this tool can be used only locally and unfortunatelly does not work well over VPN (yet).

# Dependencies
pip install cryptography scapy netifaces socket mac_vendor_lookup 

# EXAMPLE USAGE

* sudo python3 host_hunter.py 192.168.0.0/24

````
     _   _                           _   _                                                        
    | | | |   ___     _____  ______ | | | |  _   _   __    _ _______ _____   ______               
    | |_| |  / _  \  /  ___||__  __|| |_| | | | | | |  \  | |__  __||  ___| |  __  |
    |     | | | | | |  (_     | |   |     | | | | | |   \ | |  | |  | |___  | |__/ |   
    | |-| | | | | |  \_  \    | |   | |-| | | | | | | |\ \| |  | |  |  ___| |  _  /    
    | | | | | |_| | ___)  |   | |   | | | | | |_| | | | \   |  | |  | |___  | | \ \    
    |_| |_|  \___/ |_____ /   |_|   |_| |_| |_____| |_|  \__|  |_|  |_____| |_|  \_\ 
   

    HostHunter - Network mapper and device locator version 0.1
    Developed by Jose Ramon Ramirez Roca (Cyb3r0c)  usage: host_hunter.py [-h] network
    
**************************************************************************
[*] IP: 192.168.0.1      MAC: xx:xx:xx:xx:xx:xx
[-] Vendor: BSkyB Ltd
[*] Linux System
[!] Hostname>  [HOSTNAME]
**************************************************************************
**************************************************************************
[*] IP: 192.168.0.2      MAC: xx:xx:xx:xx:xx:xx
[-] Vendor: Intel Corporate
[*] Windows System
[!] Hostname>  Hostname not found
**************************************************************************
**************************************************************************
[*] IP: 192.168.0.3      MAC: xx:xx:xx:xx:xx:xx
[-] Vendor: Intel Corporate
[x] No response received.
[!] Hostname>  [HOSTNAME]
**************************************************************************
