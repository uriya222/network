mains =  test.c
CC = gcc

all: ./volumes/spoof ./volumes/test

./volumes/spoof:spoof.c
	$(CC) $^ -o ./volumes/spoof -lpcap

./volumes/test:test.c
	$(CC) $^ -o ./volumes/test -lpcap

.PHONY: all clear

clear:
	-rm ./volumes/spoof ./volumes/test