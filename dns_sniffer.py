#!/usr/bin/python

from scapy.all import *
import sys
try:
    interface = raw_input("[*] Enter Desired Interface: ")

except KeyboardInterrupt:
    print "[*] User Requested Shutdown ... "
    print "[*] Exiting..."
    sys.exit(1)

def querysniff(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr==0:
            with open(str(ip_src), 'a') as f:
                
                f.write(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")\n\n")
               # print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"

sniff(iface = interface, filter = "port 53", prn = querysniff, store = 0)
print "\n[*] Shutting Down ..."


