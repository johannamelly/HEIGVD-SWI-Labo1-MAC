import pprint
import requests
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import json

MAC_URL = 'http://macvendors.co/api/%s'
stations = []
keeptrace = []

def handler(packet):
	# if packet has a 802.11 layer and is a data frame
	if(packet.haslayer(Dot11)):
		if( packet.type == 2):
			# getting station MAC receiving address
			receiver = packet.getlayer(Dot11).addr1.upper()
			# keeping a list of the unique stations
			if (receiver not in keeptrace):
				if(packet.haslayer(Dot11Beacon)):
					# get station and SSID
					stations.append([receiver, packet.info])
					keeptrace.append(receiver)
				else:
					# just get station
					stations.append([receiver, '/'])
					keeptrace.append(receiver)

timer = raw_input("How long do you want me to search for this address (seconds)? ")
timer = int(timer)
print("Sniffing... please be patient")
sniff(iface="mon1", prn = handler, timeout=timer)

for sta in stations:
	# requesting constructor
	r = requests.get(MAC_URL % sta[0])
	try:
		res = r.json()['result']
		# displaying
		if('error' in res):
			print("%s - %s" % (sta[0], sta[1]))
		else:
			print("%s (%s) - %s" % (sta[0], res['company'], sta[1]))
	except ValueError, e:
		print("%s - %s" % (sta[0], sta[1]))
