#!/usr/bin/env python3
from scapy.all import *

#function that we use to show the packet info when using the sniffer
def print_pkt(pkt):
    pkt.show()
    
# sniffing packet with the wanted filter
pkt = sniff(iface=['docker0', 'enp0s3','lo'], filter='dst net 128.230.0.0/16', prn=print_pkt)
    
