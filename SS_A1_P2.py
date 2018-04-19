#! /usr/bin/env python

# Import Scapy package

from scapy.all import *
import sys, getopt

#Take Arguments from Command Line------------------------------------------------

def main(argv):

	try:
		opts, args = getopt.getopt(argv,"hi:v:V:r:R:",["interface=","victim-ip=","victim-ethernet=","reflector-ip=","reflector-ethernet="])
	except getopt.GetoptError:
		print 'test.py --interface <> --victim-ip <>  --victim-ethernet <> --reflector-ip <> --reflector-ethernet <>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'test.py --interface <> --victim-ip <>  --victim-ethernet <> --reflector-ip <> --reflector-ethernet <>'
			sys.exit()
		elif opt in ("-i", "--interface"):
			interFace = arg
      		elif opt in ("-v", "--victim-ip"):
         		victim_ip = arg
		elif opt in ("-V", "--victim-ethernet"):
         		victim_ether = arg
		elif opt in ("-r", "--reflector-ip"):
         		reflector_ip = arg
		elif opt in ("-R", "--reflector-ethernet"):
         		reflector_ether = arg

	# Define Functions---------------------------------------------------------------
	
	# To check the Packet Type------------------------
	
	def sniffer_handler (pkt_handle):
			
		pkt_1 = pkt_handle[0]
		
		#Check if source field if not victim or reflector
		if (pkt_1[Ether].src != reflector_ether and pkt_1[Ether].src != victim_ether):
		
			if ARP in pkt_1:
				print " ARP Packet \n"
				arp_handler(pkt_1)
			elif TCP in pkt_1:
				print " TCP Packet \n"
				tcp_handler(pkt_1)
			elif UDP in pkt_1:
				print " UDP Packet \n"
				udp_handler(pkt_1)
			elif ICMP in pkt_1:
				print " ICMP Packet \n"
				icmp_handler(pkt_1)
			else:
				del pkt_handle
			return

	# To Send Packet Function------------------------

	def send_packet(pkt_send):
		sendp(pkt_send, iface = interFace)
		print "Packet is sent with following details : \n"
		pkt_send.show()
		return
	
	# If Packet is ARP-------------------------------
	
	def arp_handler(pkt_arp):
		
		print pkt_arp.show()
		print "packet is inside ARP function \n" 
	
		if pkt_arp[ARP].op == 1: #who-has request
			 
			if pkt_arp[ARP].pdst == victim_ip:  #sent for victim ip
	
				print "Attacker is asking for victim's Ethernet Address \n"
	
				# Extract Attacker info
				attacker_ether = pkt_arp[ARP].hwsrc ; attacker_ip = pkt_arp[ARP].psrc
	
				# Send victim information
				pkt_send = pkt_arp
				pkt_send[Ether].src = victim_ether ; pkt_send[Ether].dst = attacker_ether
				pkt_send[ARP].op = 2
				pkt_send[ARP].hwsrc = victim_ether ; pkt_send[ARP].psrc = victim_ip	
				pkt_send[ARP].hwdst = attacker_ether ; pkt_send[ARP].pdst = attacker_ip
	
				# send Packet
				send_packet(pkt_send)
	
			elif pkt_arp[ARP].pdst == reflector_ip:	#sent for reflector ip
	
				print " Attacker is asking for reflector's etherner address \n"
	
				# Extract Attacker info
				attacker_ether = pkt_arp[ARP].hwsrc ; attacker_ip = pkt_arp[ARP].psrc
	
				# Send reflector information
				pkt_send = pkt_arp
				pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
				pkt_send[ARP].op = 2
				pkt_send[ARP].hwsrc = reflector_ether ; pkt_send[ARP].psrc = reflector_ip
				pkt_send[ARP].hwdst = attacker_ether ; pkt_send[ARP].pdst = attacker_ip
	
				# send Packet
				send_packet(pkt_send)
	
			else:
				print " Other Packet -> is being deleted \n"
				del pkt_arp	
		else:
			print " Other Packet -> is being deleted \n"
			del pkt_arp
		return
	
	# If Packet is TCP------------------------------
	
	def tcp_handler (pkt_tcp):
	
		print pkt_tcp.show()
		print "Packet is inside TCP function \n"
	
		# check whether destination is reflector or victim
		if pkt_tcp[IP].dst == reflector_ip:
	
			print "Packet is sent for the refector \n"
	
			# Extract Attacker info
			attacker_ether = pkt_tcp[Ether].src ; attacker_ip = pkt_tcp[IP].src
			source_port = pkt_tcp[TCP].sport; dest_port = pkt_tcp[TCP].dport
	
			# source fields -> victim
			pkt_send = pkt_tcp
			del pkt_send[IP].chksum
			del pkt_send[TCP].chksum
			pkt_send[Ether].src = victim_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = victim_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)
	
	
		elif pkt_tcp[IP].dst == victim_ip:
	
			print "Packet is for Victim \n"
	
			# Extract Attacker info
			attacker_ether = pkt_tcp[Ether].src ; attacker_ip = pkt_tcp[IP].src
			source_port = pkt_tcp[TCP].sport; dest_port = pkt_tcp[TCP].dport
	
			# source fields -> reflector
			pkt_send = pkt_tcp
			del pkt_send[IP].chksum
			del pkt_send[TCP].chksum
			pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = reflector_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)

		elif pkt_tcp[IP].dst[-3:] == "255":

			print " Pcket is Broadcast type \n"

			# Extract Attacker info
			attacker_ether = pkt_tcp[Ether].src ; attacker_ip = pkt_tcp[IP].src
			source_port = pkt_tcp[TCP].sport; dest_port = pkt_tcp[TCP].dport
	
			# source fields -> reflector
			pkt_send = pkt_tcp
			del pkt_send[IP].chksum
			del pkt_send[TCP].chksum
			pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = reflector_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)

		else:
			print "Other Packet -> Delete \n"
			del pkt_tcp
		return
	
	# If Packet is UDP----------------------------------
	
	def udp_handler (pkt_udp):
	
		print pkt_udp.show()
		print "Packet is inside UDP function \n"
	
		if pkt_udp[IP].dst == victim_ip:
	
			print "Packet has been sent for Victim \n"		
			
			# Extract Attacker info
			attacker_ether = pkt_udp[Ether].src ; attacker_ip = pkt_udp[IP].src
			source_port = pkt_udp[UDP].sport; dest_port = pkt_udp[UDP].dport
	
			# manipulate the packet
			pkt_send = pkt_udp
			del pkt_send[IP].chksum
			del pkt_send[UDP].chksum
			pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = reflector_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)
	
		elif pkt_udp[IP].dst == reflector_ip:
	
			print "Packet is sent for Reflector \n"
	
			# Extract Attacker info
			attacker_ether = pkt_udp[Ether].src ; attacker_ip = pkt_udp[IP].src
			source_port = pkt_udp[UDP].sport; dest_port = pkt_udp[UDP].dport
	
			# manipulate the packet
			pkt_send = pkt_udp
			del pkt_send[IP].chksum
			del pkt_send[UDP].chksum
			pkt_send[Ether].src = victim_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = victim_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)

		elif pkt_udp[IP].dst[-3:] == "255":

			print "Packet is Broadcast type \n"
	
			# Extract Attacker info
			attacker_ether = pkt_udp[Ether].src ; attacker_ip = pkt_udp[IP].src
			source_port = pkt_udp[UDP].sport; dest_port = pkt_udp[UDP].dport
	
			# manipulate the packet
			pkt_send = pkt_udp
			del pkt_send[IP].chksum
			del pkt_send[UDP].chksum
			pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = reflector_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)		

		else:
	
			print "Other Packet -> Delete \n"
	
			del pkt_udp
		return

	# If Packet is ICMP----------------------------------
	
	def icmp_handler (pkt_icmp):
	
		print pkt_icmp.show()
		print "Packet is inside ICMP function \n"
	
		if pkt_icmp[IP].dst == victim_ip:
	
			print "Packet has been sent for Victim \n"		
			
			# Extract Attacker info
			attacker_ether = pkt_icmp[Ether].src ; attacker_ip = pkt_icmp[IP].src
	
			# manipulate the packet
			pkt_send = pkt_icmp
			del pkt_send[IP].chksum
			del pkt_send[ICMP].chksum
			pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = reflector_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)
	
		elif pkt_icmp[IP].dst == reflector_ip:
	
			print "Packet is sent for Reflector \n"
	
			# Extract Attacker info
			attacker_ether = pkt_icmp[Ether].src ; attacker_ip = pkt_icmp[IP].src
	
			# manipulate the packet
			pkt_send = pkt_icmp
			del pkt_send[IP].chksum
			del pkt_send[ICMP].chksum
			pkt_send[Ether].src = victim_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = victim_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)

		elif pkt_icmp[IP].dst[-3:] == "255":

			print "Packet is Broadcast type \n"		
			
			# Extract Attacker info
			attacker_ether = pkt_icmp[Ether].src ; attacker_ip = pkt_icmp[IP].src
	
			# manipulate the packet
			pkt_send = pkt_icmp
			del pkt_send[IP].chksum
			del pkt_send[ICMP].chksum
			pkt_send[Ether].src = reflector_ether ; pkt_send[Ether].dst = attacker_ether
			pkt_send[IP].src = reflector_ip ; pkt_send[IP].dst = attacker_ip
			pkt_send = pkt_send.__class__(str(pkt_send))
	
			# send the packet
			send_packet(pkt_send)

		else:
	
			print "Other Packet -> Delete \n"
	
			del pkt_icmp
		return
	
	# Sniff packets---------------------------------------------------------------------
	
	sniff(prn = sniffer_handler, iface = interFace)

	return

if __name__ == "__main__":
	main(sys.argv[1:])

