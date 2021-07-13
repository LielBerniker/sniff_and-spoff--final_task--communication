CC=gcc
FLAGS= -Wall -g
all: sniff_tcp sniff_r sniff_icmp sniff_pass
sniff_tcp: sniffer2.1b_tcp.c
	$(CC) $(FLAGS) -o sniff_tcp sniffer2.1b_tcp.c -lpcap
sniff_r: sniffer_2.1a.c
	$(CC) $(FLAGS) -o sniff_r sniffer_2.1a.c -lpcap
sniff_icmp: sniffer_2.1b_icmp.c
	$(CC) $(FLAGS) -o sniff_icmp sniffer_2.1b_icmp.c -lpcap
sniff_pass: Sniffing_Passwords2.1c.c
	$(CC) $(FLAGS) -o sniff_pass Sniffing_Passwords2.1c.c -lpcap
.PHONY: clean all

clean:
	rm sniff_tcp sniff_r sniff_icmp sniff_pass