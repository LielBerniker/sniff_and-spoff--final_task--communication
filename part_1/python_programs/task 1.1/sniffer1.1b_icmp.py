#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface=['docker0', 'enp0s3','lo'], filter='icmp', prn=print_pkt)
    
