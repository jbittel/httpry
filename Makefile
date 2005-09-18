#
# Makefile 8/12/2005
#
# Copyright (c) 2005, Jason Bittel. All rights reserved.
# See included LICENSE file for specific licensing information
#
# This is hopefully a universal makefile for httpry. It currently has only
# been tested under Linux and FreeBSD. If you should compile and use the
# program under a different OS, please let me know.
#

CC	= gcc
CFLAGS	= -Wall -O3 -funroll-loops
LIBS	= -lpcap -I/usr/include/pcap -I/usr/local/include/pcap
PROG	= httpry

$(PROG): $(PROG).c
	@echo "--------------------------------------------------"
	@echo "This program has only been tested under Linux and"
	@echo "FreeBSD. If you should run it under a different"
	@echo "system, please let me know your experience."
	@echo "--------------------------------------------------"
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).c $(LIBS)

all:
	$(PROG)

install: $(PROG)
	@echo "Installing httpry into /usr/sbin"
	cp -f $(PROG) /usr/sbin/
	cp -f $(PROG).1 /usr/man/man1/ || cp -f $(PROG).1 /usr/local/man/man1/
	@echo "You'll need to manually move the perl scripts"
	@echo "and other tools to a place that makes sense to you."

uninstall:
	rm -f /usr/sbin/$(PROG)
	rm -f /usr/man/man1/$(PROG).1 || rm -f /usr/local/man/man1/$(PROG).1

clean:
	rm -f $(PROG)
