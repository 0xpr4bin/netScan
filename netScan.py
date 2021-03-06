#!/usr/bin/env python3


#Modules from python library.
import logging
from scapy.all import *
from threading import Thread
from queue import Queue
import pyfiglet
import socket
import sys

import argparse
from collections import Counter

lock=threading.Lock()
q=Queue()

#If any error occurs.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


ascii_banner=pyfiglet.figlet_format("netScan\n")
print(ascii_banner)

print(f'Author ---> Pr4bin Sigd3l\n.........................\n')


#Command line arguments.
def arg_parser():
	parser=argparse.ArgumentParser(description="Scanning networks\n........................")

	#optional arguments.
	parser.add_argument('ip', metavar='ip', help='host or ip of target networks')
	parser.add_argument('-p', '--port', dest='port', metavar='', help='specific port')
	parser.add_argument('-cp', '--capture', dest='capture', action='store_true', help='sniff/capture packet')

	#Both aswell as one can be executed -q or -v.
	group=parser.add_mutually_exclusive_group()
	group.add_argument('-q','--quiet',action='store_true',help='print quiet')
	group.add_argument('-v','--verbose',action='store_true',help='print verbose')

	args=parser.parse_args()

	if not args.ip:
		parser.error('[-] Please specify ip...')
	else:
		return args	


#calling funtion
options=arg_parser()

print(f'[+] Scanning networks........{options.ip}..........')
print("--------------------------------------------------")
print("Scanning started at:" + str(datetime.now()))
print("-" * 50,"\n\n")		

#Scanning IP and mac addresses.
def ip_scan(ip):

	#sending arp request as frames.
	arp_req_frame=ARP(pdst=ip)

	#broadcasting ether frame.
	broad_ether_frame=Ether(dst='ff:ff:ff:ff:ff:ff')

	#sending both frames and arp request
	broad_ether_arp_frame=broad_ether_frame/arp_req_frame

	#received packets.
	answr_list=srp(broad_ether_arp_frame,timeout=1,verbose=False)[1]
	result=list()
	for i in range(0,len(answr_list)):
		dic={"ip":answr_list[i][1].psrc,"mac":answr_list[i][1].hwsrc}
		result.append(dic)
	return result

#scanning for open ports 
def port_scan1(port,ip):
	print(f'\n\nScanning port________________________{port}')
	response=sr1(IP(dst=ip)/TCP(dport=port,flags='S'),timeout=0.6,verbose=0)
	if response is not None and TCP in response and response[TCP].flags == 0x12:
		print(f'Port {port} is open!\n\n')
	else:
		print(f' Port {port} is closed!!\n')	
	sr(IP(dst=ip)/TCP(dport=port,flags='R'),timeout=0.6,verbose=0)
		

#socket connection between two ports 
try:
	target=socket.gethostbyname(str(options.ip))
except socket.gaierror:
	print(f'Error getting Ip')
	sys.exit()	


def  port_scan2(port):
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	try:
		s.settimeout(2)
		conn=s.connect_ex((target,port))
		if not conn:
			print(f'Port {port} is open!')	
		s.close()
	except:
		pass


#using multi threading for fast scan
def Threader():
	while True:
		w=q.get()
		port_scan2(w)
		q.task_done()

#sniffing packet from networks
def sniff_packet():
	packet_counts =Counter()
	def custom_action(packet):
		# Create tuple of Src/Dst in sorted order
		key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
		packet_counts.update([key])
		return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"

		
	sniff(filter="ip", prn=custom_action, count=10)
	## Print out packet count per A <--> Z address pair
	print(f'\n\npacket captured',"_"*15)
	print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
	
if options.capture:
	sniff_packet()


def display(result):
	print(f'IP address\tMac address\n.........................')
	for i in result:
		print("{}\t{}".format(i["ip"],i["mac"]))

#output
if __name__=='__main__':
	output=ip_scan(options.ip)
	if options.quiet:
		print(f'{output}\n')
	elif options.verbose:
		display(output)
	else:
		print(f'The source ip and mac is > ...............\n{output}\n\n')	

	if options.port:
		port_scan1(int(options.port),str(options.ip))
	else:
		#Using multi_threading to fast scan 1023 well-known ports	
		for x in range(500):
			t=Thread(target=Threader)
			t.daemon=True
			t.start()	
		for i in range(0,1023):
			q.put(i)
		q.join()		


print("\n\n\nScanning finished at:" + str(datetime.now()))
print("-" * 50)		

