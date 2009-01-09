#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>
#

CC		= gcc
CCFLAGS  	= -Wall -O3 -funroll-loops -I/usr/include/pcap -I/usr/local/include/pcap
DEBUGFLAGS	= -Wall -g -DDEBUG -I/usr/include/pcap -I/usr/local/include/pcap
LIBS		= -lpcap
PROG		= httpry
FILES		= httpry.c format.c methods.c utility.c

all: $(PROG)

$(PROG): $(FILES)
	$(CC) $(CCFLAGS) -o $(PROG) $(FILES) $(LIBS)

debug: $(FILES)
	@echo "--------------------------------------------------"
	@echo "Compiling $(PROG) in debug mode"
	@echo ""
	@echo "This will cause the program to run slightly"
	@echo "slower, but enables additional data verification"
	@echo "and sanity checks. Recommended for testing, not"
	@echo "production usage."
	@echo "--------------------------------------------------"
	@echo ""
	$(CC) $(DEBUGFLAGS) -o $(PROG) $(FILES) $(LIBS)

install: $(PROG)
	@echo "--------------------------------------------------"
	@echo "Installing $(PROG) into /usr/sbin/"
	@echo ""
	@echo "You can move the Perl scripts and other tools to"
	@echo "a location of your choosing manually"
	@echo "--------------------------------------------------"
	@echo ""
	cp -f $(PROG) /usr/sbin/
	cp -f $(PROG).1 /usr/man/man1/ || cp -f $(PROG).1 /usr/local/man/man1/

uninstall:
	rm -f /usr/sbin/$(PROG)
	rm -f /usr/man/man1/$(PROG).1 || rm -f /usr/local/man/man1/$(PROG).1

clean:
	rm -f $(PROG)
