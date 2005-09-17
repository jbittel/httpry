# Makefile for HTTPry 8/12/2005

CC=gcc
CFLAGS=-Wall

httpry:
	$(CC) $(CFLAGS) ./src/httpry.c -o httpry -lpcap

all:	httpry

clean:
	rm -f httpry
