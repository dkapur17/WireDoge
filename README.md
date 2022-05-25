# WireDoge
*Like WireShark, but Doge.*

![Full Layout](https://user-images.githubusercontent.com/37783178/170180886-b1d3b1ee-a41d-4256-b114-9026358af66e.png)

WireDoge is a simple Man in the Middle Attack tool written in Python. 
It provides a friendly CLI menu interface that lets the attacker detect all the devices on their network, choose two hosts (one of which is generally the Gateway) and perform an ARP Cache poisoning attack to insert itself between the two targets.
Once the attacker's machine is between the two targets, they can choose what kind of packets to sniff from that link. Currently supported packet types are:

1. ICMP
2. TCP
3. UDP

![WireDoge ARP Spoofer](https://user-images.githubusercontent.com/37783178/170180987-8e460a96-c36d-4ee5-ad1b-23f6376e4b39.png)


The contents of the packets are well formatted in the output for easy understanding.

On completion of the attack, WireDoge cleans up after itself (name another dog that can do that, I'll wait), resets the ARP caches of the two target machines, leaving them none the wiser.
