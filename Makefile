#
# Makefile | created: 8/12/2005
#
# This is (hopefully) a universal makefile for httpry.
#

CC	= gcc
CFLAGS	= -Wall -O3 -funroll-loops -ansi
LIBS	= -lpcap -I/usr/include/pcap -I/usr/local/include/pcap
PROG	= httpry

$(PROG): $(PROG).c list.c
	@echo "--------------------------------------------------"
	@echo " $(PROG) has been tested under the systems listed"
	@echo " in doc/tested-systems. It may not compile or run"
	@echo " properly under other systems."
	@echo "--------------------------------------------------"
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).c list.c $(LIBS)

all:
	$(PROG)

install: $(PROG)
	@echo "--------------------------------------------------"
	@echo " Installing $(PROG) into /usr/sbin/"
	@echo ""
	@echo " You will need to move the Perl scripts and other"
	@echo " tools to a location of your choosing manually."
	@echo "--------------------------------------------------"
	cp -f $(PROG) /usr/sbin/
	cp -f $(PROG).1 /usr/man/man1/ || cp -f $(PROG).1 /usr/local/man/man1/

uninstall:
	rm -f /usr/sbin/$(PROG)
	rm -f /usr/man/man1/$(PROG).1 || rm -f /usr/local/man/man1/$(PROG).1

clean:
	rm -f $(PROG)
