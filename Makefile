#
# Makefile for HTTPry 8/12/2005
#
# This is a universal makefile for httpry. It's currently only been tested
# under Linux and FreeBSD. If you should successfully compile and use the
# program under a different OS, please let me know.
#

CC	= gcc
LIBS	= -lpcap #-I/usr/include/pcap -I/usr/local/include/pcap
CFLAGS	= -O3 -Wall -fomit-frame-pointer -funroll-loops
PROG	= httpry

$(PROG): $(PROG).c
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).c $(LIBS)

all:
	$(PROG)

install: $(PROG)
	@echo "Installing httpry into /usr/sbin"
	cp -f $(PROG) /usr/sbin/
	@echo "You'll need to manually move the perl scripts"
	@echo "and other files to where ever you need them."

clean:
	rm -f $(PROG)
