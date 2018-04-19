from scapy.all import *

## Create a Packet Counter
counter = 0

## Define our Custom Action function
def custom_action(packet):
    global counter
    counter += 1
    print("Packet #" + str(counter) + ": \n" + str(packet.show()))

## Setup sniff, filtering for IP traffic
sniff(filter="ip", prn=custom_action)
