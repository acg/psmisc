#!/bin/sh
# Run this to generate all the initial makefiles, etc.
# This was lifted from the Gimp, and adapted slightly by
# Raph Levien .

DIE=0

PROJECT=psmisc

# Make it possible to specify path in the environment
: ${AUTOCONF=autoconf}
: ${AUTOHEADER=autoheader}
: ${AUTOMAKE=automake}
: ${ACLOCAL=aclocal}
: ${AUTOPOINT=autopoint}

($AUTOPOINT --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have gettext installed to compile $PROJECT."
	echo "Get ftp://ftp.gnu.org/pub/gnu/gettext-0.14.1.tar.gz"
	echo "(or a newer version if it is available)"
	DIE=1
}

($AUTOCONF --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
	DIE=1
}

($AUTOMAKE --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have automake installed to compile $PROJECT."
	echo "Get ftp://ftp.gnu.org/pub/gnu/automake-1.6.tar.gz"
	echo "(or a newer version if it is available)"
	DIE=1
}

if test "$DIE" -eq 1; then
	exit 1
fi

if test -z "$*"; then
	echo "I am going to run ./configure with no arguments - if you wish "
        echo "to pass any to it, please specify them on the $0 command line."
fi

case $CC in
*xlc | *xlc\ * | *lcc | *lcc\ *) am_opt=--include-deps;;
esac

for dir in .
do
  echo processing $dir
  cd $dir
  configdir="config"
  test -d $configdir || mkdir $configdir
  aclocalinclude="$ACLOCAL_FLAGS"
  $AUTOPOINT
  $ACLOCAL $aclocalinclude -I $configdir
  $AUTOHEADER -Wall
  $AUTOMAKE -Wall --add-missing --gnu $am_opt
  $AUTOCONF -Wall
  cd -
done

./configure "$@"

echo
echo "Now type 'make' to compile $PROJECT."

