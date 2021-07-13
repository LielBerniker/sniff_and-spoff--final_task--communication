#!/usr/bin/env python3
from scapy.all import *

#function that we use to show the packet info when using the sniffer
def print_pkt(pkt):
    pkt.show()
    
# sniffing packet with the wanted filter
pkt = sniff(iface=['docker0', 'enp0s3','lo'], filter='tcp and dst port 23 and src host 10.0.2.15', prn=print_pkt)
  
