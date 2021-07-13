CC=gcc
FLAGS= -Wall -g
all: s_and_s
s_and_s: snif_and_spoof.c
	$(CC) $(FLAGS) -o s_and_s snif_and_spoof.c -lpcap
.PHONY: clean all

clean:
	rm s_and_s