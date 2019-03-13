import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

stations = []

def handler(packet):
	# if packet has a 802.11 layer and is a data frame
	if(packet.haslayer(Dot11) and packet.type == 2):
		# getting station MAC receiving address
		receiver = packet.getlayer(Dot11).addr1.upper()
		
		# keeping a list of the stations
		if (receiver not in stations):
			stations.append(receiver)
		# if we find the target, we print a confirmation
		if(receiver == targetMAC):
			print("Your client has been detected!")
			packet.show()

targetMAC = raw_input("Hello, please provide a MAC address: ")
timer = raw_input("How long do you want me to search for this address (seconds)? ")
timer = int(timer)

print("Sniffing... please be patient, you'll be notified if your client is detected.")
sniff(iface="mon1", prn = handler, timeout=timer)
