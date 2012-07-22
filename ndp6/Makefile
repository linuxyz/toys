## simple simple simple
CC=gcc
CFLAGS=-Wall -DDEBUG
SRCS=main.c icmp6talk.c nltalk.c
OBJS=$(SRCS:.c=.o)



all: neighbor6


debug: simple.c
	$(CC) -Wall -g -DDEBUG -o $@ $<


simple:	simple.c
	$(CC) -Wall -o $@ $<


neighbor6: $(OBJS)
	$(CC) -Wall -o $@ $(OBJS)
	scp $@ dspace@166.111.120.67:/media/software/openwrt/bin/


clean:
	rm -rf *.o simple neighbor6
