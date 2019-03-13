import pprint
import requests
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

MAC_URL = 'http://macvendors.co/api/%s'
stations = []


def handler(packet):
	# if packet has a 802.11 layer and is a data frame
	if(packet.haslayer(Dot11) and packet.type == 2):
		# getting station MAC receiving address
		receiver = packet.getlayer(Dot11).addr1.upper()
		
		# keeping a list of the stations
		if (receiver not in stations):
			stations.append(receiver)

timer = raw_input("How long do you want me to search for this address (seconds)? ")
timer = int(timer)
print("Sniffing... please be patient")
sniff(iface="mon1", prn = handler, timeout=timer)

for sta in stations:
	r = requests.get(MAC_URL % sta)
	res = r.json()['result']
	print("%s (%s) - %s" % (sta, res['company'], res['address']))
