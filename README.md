 # IP Reflector

 This is a ‘Man-in-the-middle defense’ program using Python and Scapy that listens to the network interface, 
 relaunch exploits sent through any IP, TCP or UDP packets at the victim host back to the attacker host, without affecting the victim.
 
 - To run the reflector program, use makefile to create executable
 - to execute program, use this format : 
	./reflector --interface <> --victim-ip <> --victim-ethernet <> --reflector-ip <> --reflector-ethernet <>
 - This program does not support IPv6 addresses
 - Supported protocols are ARP, IP, ICMP, TCP and UDP
