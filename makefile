mains =  test.c
CC = gcc
SNIFF = ./volumes/sniff
SPOOF = ./volumes/ipspoof

all: $(SNIFF) $(SPOOF) ./volumes/test

$(SNIFF):sniff.c
	$(CC) $^ -o $(SNIFF) -lpcap

$(SPOOF):ip_spoof.c
	$(CC) $^ -o $(SPOOF) -lpcap

./volumes/test:test.c
	$(CC) $^ -o ./volumes/test -lpcap

.PHONY: all clear

clear:
	-rm $(SNIFF) $(SPOOF) ./volumes/test