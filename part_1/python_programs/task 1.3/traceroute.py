#!/usr/bin/env python3

from scapy.all import *
import time

start_time = time.time()
go_on = True
host_ip = "www.amitdvir.com" # amit dvir site

# counter = ttl
counter = 1
router_count = 0
got_response = True
a=IP()
a.dst = host_ip
while go_on == True:
	a.ttl = counter
	b = ICMP()
	p = a/b
	# sr1 a function that send the req packet we made and send back one response packet
	response = sr1(p, timeout=10,verbose = 0)
	print("......................")
	
	#if response is none we couldent trace a router in the path
	if response is None:
		print("no replay sent back")
		
	#if response type is 0 means replay we arived to dest 
	elif response.type == 0:
		go_on = False
		break
		
	#if response type is 11 -exceeded , we trace a router but ttl was too low 
	else:
		router_count+=1
		print("router ip: " + response.src + " , router number "+ str(router_count) + " in trace")
	current_time = time.time()
	
	#if 10 min passed and we didnt find router in the path we asume thet the dest ip is not exists
	if (current_time - start_time) > 600:
		go_on = False
		got_response = False
		
	#ttl=ttl +1
	counter+=1
	
	
if got_response is False:
	print("it took to much time to reach the ip address!!!") 
else:
	print("the trace route to the ip address " + host_ip + " contain :" + str(router_count) +  " routers") 


#https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html  for the sr ans sr1 functions
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml , for the type of icmp
