
AM_CFLAGS = -Wall -DLOCALEDIR=\"/usr/share/locale\"

bin_PROGRAMS = fuser killall pstree oldfuser peekfd

oldfuser_SOURCES = oldfuser.c comm.h signals.c signals.h loop.h i18n.h

fuser_SOURCES = fuser.c comm.h signals.c signals.h i18n.h fuser.h

killall_SOURCES = killall.c comm.h signals.c signals.h i18n.h

killall_LDADD = @SELINUX_LIB@

peekfd_SOURCES = peekfd.c

pstree_SOURCES = pstree.c comm.h i18n.h

pstree_LDADD = @TERMCAP_LIB@ @SELINUX_LIB@

BUILT_SOURCES = signames.h

EXTRA_DIST = signames.c 

CLEANFILES = signames.h

signames.h: signames.c Makefile
		export LC_ALL=C ; \
		@CPP@ -dM $< |\
		tr -s '\t ' ' ' | sort -n -k 3 | sed \
	's:#define SIG\([A-Z]\+[0-9]*\) \([0-9]\+\) *\(\|/\*.*\)$$:{\ \2,"\1" },:p;d' | \
		  grep -v '[0-9][0-9][0-9]' >signames.h || \
		  { rm -f signames.h; exit 1; }
		grep '^{ 1,"HUP" },$$' signames.h >/dev/null || \
		  { rm -f signames.h; exit 1; }

install-exec-hook:
		cd $(DESTDIR)$(bindir) && \
			( [ -h pstree.x11 ]  || $(LN_S) pstree pstree.x11)
