import logging

#If any error occurs.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


#Modules from python library.
from scapy.all import *
import argparse
import pyfiglet


#Banner to show fancy.
ascii_banner=pyfiglet.figlet_format("Network\t scanner\n")
print(ascii_banner)

print(f'Author->Pr4bin Sigd3l\n......................\n')


#Command line arguments.
def arg_parser():
	parser=argparse.ArgumentParser(description="Scanning networks\n........................")

	#optional arguments.
	parser.add_argument('-i', '--ip', dest='ip', metavar='', required=True, help='host or ip of target networks')
	parser.add_argument('-p', '--port', dest='port', metavar='', help='specific port')
	parser.add_argument('-c', '--capture', dest='capture', action='store_true', help='sniff/capture packet')

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
print("-" * 50)		

#Scanning IP and mac addresses.
def ip_scan(ip):

	#sending arp request as frames.
	arp_req_frame=ARP(pdst=ip)

	#broadcasting ether frame.
	broad_ether_frame=Ether(dst='ff:ff:ff:ff:ff:ff')

	#sending both frames and arp request
	broad_ether_arp_frame=broad_ether_frame/arp_req_frame

	#received packets.
	answr_list=srp(broad_ether_arp_frame,timeout=1,verbose=False)[0]
	result=list()
	

	for i in range(0,len(answr_list)):
		dic={"ip":answr_list[i][1].psrc,"mac":answr_list[i][1].hwsrc}
		result.append(dic)

	return result


#scanning for open ports 
def port_scan1(port,ip):
	response=sr1(IP(dst=ip)/TCP(dport=port,flags='S'),timeout=0.6,verbose=0)
	if response and response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
		print(f'Port {port} is open!')
	elif response and response.getlayer(TCP).flags==0x14:
		print(f'Port {port} is closed')
	else:
		print(f'All ports are closed')	
	sr(IP(dst=ip)/TCP(dport=port,flags='R'),timeout=0.6,verbose=0)
		

def  port_scan2(ip):
	for i in range(0,1000):
		response=sr1(IP(dst=ip)/TCP(dport=i,flags='S'),timeout=0.6,verbose=0)
		if response and response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
			print(f'Port {i} is open!')
		elif response and response.getlayer(TCP).flags==0x14:
			print(f'Port {i} is closed')
		else:
			print(f'All ports are closed')	
		sr(IP(dst=ip)/TCP(dport=port,flags='R'),timeout=0.6,verbose=0)



#sniffing packet from networks
def sniff_packet():
	capture=sniff(count=4,filter="tcp",store=False)
	capture.summary()
	wrpcap("sniff.pcap",capture)



def display(result):
	print(f'...................\nIP address\tMac address\n.........................')
	for i in reult:
		print("{}\t{}".format(i["ip"],i["mac"]))



if options.capture:
	sniff_packet()




#output
if __name__=='__main__':
	output=ip_scan(str(options.ip))

	if options.port:
		port_scan1(int(options.port),str(options.ip))
	else:
		port_scan2(str(options.ip))	


	if options.quiet:
		print(f'{output}\n')
	elif options.verbose:
		display(output)
	else:
		print(f'The source ip and mac is > ...............\n{output}')	






