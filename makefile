mains =  test.c
CC = gcc
SNIFF = ./volumes/sniff
SPOOF = ./volumes/ipspoof
SNSP = ./volumes/sniff_spoof
all: $(SNIFF) $(SPOOF) $(SNSP) ./volumes/test

$(SNIFF):sniff.c
	$(CC) $^ -o $(SNIFF) -lpcap

$(SNSP):sniff_spoof.c
	$(CC) $^ -o $(SNSP) -lpcap

$(SPOOF):ip_spoof.c
	$(CC) $^ -o $(SPOOF) -lpcap

./volumes/test:test.c
	$(CC) $^ -o ./volumes/test -lpcap

.PHONY: all clear

clear:
	-rm $(SNIFF) $(SPOOF) $(SNSP) ./volumes/test