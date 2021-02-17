mains =  test.c
CC = gcc
SNIFF = ./volumes/sniff

all: $(SNIFF) ./volumes/test

$(SNIFF):sniff.c
	$(CC) $^ -o $(SNIFF) -lpcap

./volumes/test:test.c
	$(CC) $^ -o ./volumes/test -lpcap

.PHONY: all clear

clear:
	-rm $(SNIFF) ./volumes/test