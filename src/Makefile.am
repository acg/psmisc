
AM_CFLAGS = -Wall -DLOCALEDIR=\"/usr/share/locale\"

bin_PROGRAMS = fuser killall pstree

fuser_SOURCES = fuser.c comm.h signals.c signals.h signames.h loop.h

killall_SOURCES = killall.c comm.h signals.c signals.h signames.h

killall_LDADD = @FLASK_LIB@

pstree_SOURCES = pstree.c comm.h

pstree_LDADD = @TERMCAP_LIB@ @FLASK_LIB@

BUILT_SOURCES = signames.h

EXTRA_DIST = signames.c

CLEANFILES = signames.h

signames.h: signames.c
		@CPP@ -dM $< |\
		tr -s '\t ' ' ' | sort -n -k 3 | sed \
	's:#define SIG\([A-Z]\+[0-9]*\) \([0-9]\+\) *\(\|/\*.*\)$$:{\
\2,"\1" },:p;d' | \
		  grep -v '[0-9][0-9][0-9]' >signames.h || \
		  { rm -f signames.h; exit 1; }
		grep '^{ 1,"HUP" },$$' signames.h >/dev/null || \
		  { rm -f signames.h; exit 1; }

Makefile:	signames.h
