CC=gcc
FLAGS= -Wall -g
all: spoof_rqt spoof_rpl
spoof_rqt: spoof_icmp_rqt2.2b.c
	$(CC) $(FLAGS) -o spoof_rqt spoof_icmp_rqt2.2b.c
spoof_rpl: spoof_icmp_rpl2.2a.c
	$(CC) $(FLAGS) -o spoof_rpl spoof_icmp_rpl2.2a.c

.PHONY: clean all

clean:
	rm spoof_icmp spoof