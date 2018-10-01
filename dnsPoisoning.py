#!/usr/bin/python
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import os
import sys
import nfqueue
from scapy.all import *
# import argparse
import threading
import signal
import time
from subprocess import Popen


listofip = []

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
                    print('%s Host is up' % ip)
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


def main():
    while True:
        print "1 for Scan the IP "
        print "Do you want to Scan the IP "
        print "Do you want to Scan the IP "
        print "4 for Exit "

        input = int(raw_input(">"))
        if input == 1:
            ScanTheNetwork()
            targetSelect(listofip)
        elif input == 4:
            exit()



if __name__ =='__main__':
    main()
