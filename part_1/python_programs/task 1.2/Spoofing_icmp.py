#!/usr/bin/env python3
from scapy.all import *

#creating a spoofed packet 
a = IP()
a.dst = '172.17.0.1'#the packet dest
a.src = '1.2.3.4'# the spoofed src 
b = ICMP()
p = a/b
send(p)
