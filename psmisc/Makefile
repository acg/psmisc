CC=cc
CFLAGS=-O -DPSMISC_VERSION=\"`cat VERSION`\" \
  -D_GNU_SOURCE \
  -Wall -Wno-parentheses -Wwrite-strings -Wpointer-arith \
  # -Wcast-align -Wconversion -g
LDFLAGS=#-s -N #-Xlinker -qmagic
REAL_CPP=cc -E
PROGS=killall pstree fuser
EBINDIR=/bin		# essential binaries
BINDIR=/usr/bin		# not so essential ones
MANDIR=/usr/man/man1	# all man pages

all:		$(PROGS)

signames.h:	/usr/include/signal.h
		$(REAL_CPP) -dM - </usr/include/signal.h | \
		tr -s '\t ' ' ' | sort -n +2 | sed \
	's:#define SIG\([A-Z]\+[0-9]*\) \([0-9]\+\) *\(\|/\*.*\)$$:{\
\2,"\1" },:p;d' | \
		  grep -v '[0-9][0-9][0-9]' >signames.h || \
		  { rm -f signames.h; exit 1; }
		grep '^{ 1,"HUP" },$$' signames.h >/dev/null || \
		  { rm -f signames.h; exit 1; }

signals.o:	signals.h signals.c signames.h Makefile

fuser.o:	fuser.c comm.h signals.h Makefile VERSION
killall.o:	killall.c comm.h signals.h Makefile VERSION

fuser:		fuser.o signals.o
killall:	killall.o signals.o

pstree:		pstree.c comm.h Makefile VERSION
		$(CC) $(CFLAGS) $(LDFLAGS) -o pstree pstree.c -ltermcap

install:	$(PROGS)
#		EBINDIR is expected to exist, so we don't try to create it
		install -o 0 -g 0 -m 555 fuser $(EBINDIR)
		[ -d $(BINDIR) ] || install -d -o 0 -g 0 -m 755 $(BINDIR)
		install -o 0 -g 0 -m 555 killall $(BINDIR)
		install -o 0 -g 0 -m 555 pstree $(BINDIR)
		[ -d $(MANDIR) ] || install -d -o 0 -g 0 -m 755 $(MANDIR)
		install -o 0 -g 0 -m 444 fuser.1 $(MANDIR)
		install -o 0 -g 0 -m 444 killall.1 $(MANDIR)
		install -o 0 -g 0 -m 444 pstree.1 $(MANDIR)

install-pidof:
		@[ -x `echo $(BINDIR)`/killall ] || { \
		  echo "Need `echo $(BINDIR)`/killall to install pidof"; \
		  exit 1; }
		ln -sf killall `echo $(BINDIR)`/pidof
		install -o 0 -g 0 -m 444 pidof.1 $(MANDIR)

clean:
		rm -f *.o signames.h

spotless:	clean
		rm -f $(PROGS)
