SHELL = /bin/sh

prefix = /usr/local/bin
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
mandir = ${prefix}/share/man/man1

CC ?= gcc
DEBUG = -g
CFLAGS ?= -O2
CFLAGS += $(DEBUG)
SRC = src
DOC = doc

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

all: pacforge

pacforge:
	$(CC) $(CFLAGS) $(SRC)/*.c -o $(SRC)/pacforge -I/usr/local/include -L/usr/local/lib -lpcap
#	$(CC) $(CFLAGS) $(SRC)/igmptool.c -o $(SRC)/pacforge -I/usr/local/include -L/usr/local/lib -lpcap

clean:
	rm -rf $(SRC)/pacforge

#install:
#	mkdir -p $(bindir)
#	chmod 755 $(bindir)
#	$(INSTALL_PROGRAM) $(SRC)/bittwist $(SRC)/bittwiste $(bindir)
#	mkdir -p $(mandir)
#	chmod 755 $(mandir)
#	$(INSTALL_DATA) $(DOC)/bittwist.1 $(DOC)/bittwiste.1 $(mandir)

#uninstall:
#	rm -f $(bindir)/bittwist $(bindir)/bittwiste
#	rm -f $(mandir)/bittwist.1 $(mandir)/bittwiste.1

