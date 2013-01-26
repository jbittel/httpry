#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2012 Jason Bittel <jason.bittel@gmail.com>
#

CC		= gcc
CCFLAGS  	= -Wall -O3 -funroll-loops -I/usr/include/pcap -I${DESTDIR}/usr/include/pcap
DEBUGFLAGS	= -Wall -g -DDEBUG -I/usr/include/pcap -I${DESTDIR}/usr/include/pcap
LIBS		= -lpcap -lm -pthread
PROG		= httpry
FILES		= httpry.c format.c methods.c utility.c rate.c

.PHONY: all debug profile install uninstall clean


all: $(PROG)

$(PROG): $(FILES)
	$(CC) $(CCFLAGS) -o $(PROG) $(FILES) $(LIBS)

debug: $(FILES)
	@echo "--------------------------------------------------"
	@echo "Compiling $(PROG) in debug mode"
	@echo ""
	@echo "This will cause the program to run slightly"
	@echo "slower, but enables additional data verification"
	@echo "and sanity checks; recommended for testing, not"
	@echo "production usage"
	@echo "--------------------------------------------------"
	@echo ""
	$(CC) $(DEBUGFLAGS) -o $(PROG) $(FILES) $(LIBS)

profile: $(FILES)
	@echo "--------------------------------------------------"
	@echo "Compiling $(PROG) in profile mode"
	@echo ""
	@echo "This enables profiling so gprof can be used for"
	@echo "code analysis"
	@echo "--------------------------------------------------"
	@echo ""
	$(CC) $(CCFLAGS) -pg -o $(PROG) $(FILES) $(LIBS)

install: $(PROG)
	@echo "--------------------------------------------------"
	@echo "Installing $(PROG) into /usr/sbin/"
	@echo ""
	@echo "You can move the Perl scripts and other tools to"
	@echo "a location of your choosing manually"
	@echo "--------------------------------------------------"
	@echo ""
	install -d ${DESTDIR}/usr/sbin/
	cp -f $(PROG) ${DESTDIR}/usr/sbin/
	install -d ${DESTDIR}/usr/man/man1/
	cp -f $(PROG).1 ${DESTDIR}/usr/man/man1/ \
	|| cp -f $(PROG).1 ${DESTDIR}/usr/man/man1/

uninstall:
	rm -f /usr/sbin/$(PROG)
	rm -f /usr/man/man1/$(PROG).1 || rm -f ${DESTDIR}/usr/man/man1/$(PROG).1

clean:
	rm -f $(PROG)
