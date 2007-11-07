#!/bin/sh
# Build all cryptlib modules

# Make sure that we've been given sufficient arguments.

if [ "$1" = "" ] ; then
	echo "$0: Missing OS name." >&2 ;
	exit 1 ;
fi
if [ "$2" = "" ] ; then
	echo "$0: Missing compiler name." >&2 ;
	exit 1 ;
fi
if [ "$3" = "" ] ; then
	echo "$0: Missing compiler flags." >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

OSNAME=$1
CC=$2
shift
shift

# Some systems have the development tools as optional components, or the
# tools are included but suck so much that everyone uses gcc instead.  For
# these systems we build with gcc if it's present, otherwise fall back to
# the native development tools.

buildWithGcc()
	{
	OSNAME=$1
	shift

	make CC=gcc LD=gcc \
		 CFLAGS="$* `./tools/ccopts.sh gcc` -DOSVERSION=`./tools/osversion.sh $OSNAME`" \
		 $OSNAME
	}

buildWithNativeTools()
	{
	OSNAME=$1
	CC=$2
	shift
	shift

	make CFLAGS="$* `./tools/ccopts.sh $CC` -DOSVERSION=`./tools/osversion.sh $OSNAME`" \
		 $OSNAME
	}

# Build cryptlib, taking into account OS-specific quirks.  We have to 
# special-case the situation where the OS name is an alias for uname rather 
# than being predefined (this occurs when cross-compiling), because the 
# resulting expansion would contain two levels of `` escapes.  To handle 
# this, we leave a predefined OS name in place, but replace a call to uname 
# with instructions to the osversion.sh script to figure it out for itself.  
# In addition since $CROSSCOMPILE is usually a null value, we add an extra 
# character to the comparison string to avoid syntax errors.  Finally, we
# put the CFLAGS on a single line to avoid visual problems through adding a
# line break and long string of whitespace in the middle of the definition.

case $OSNAME in
	'BeOS')
		make CFLAGS="$* `./tools/ccopts.sh $CC` -DOSVERSION=`./tools/osversion.sh BeOS` -D_STATIC_LINKING" \
			 BeOS ;; 

	'HP-UX')
		if gcc -v > /dev/null 2>&1 ; then 
			buildWithGcc HP-UX $* ; 
		else 
			buildWithNativeTools HP-UX $CC $* ; 
		fi ;; 

	'SunOS') 
		if [ `/usr/ucb/cc 2>&1 | grep -c installed` = '1' ] ; then 
			buildWithGcc SunOS $* ; 
		else 
			buildWithNativeTools SunOS $CC $* ; 
		fi ;; 

	*) 
		if [ `uname -m | cut -c 1-4` = 'CRAY' ] ; then 
			make CFLAGS="$* `./tools/ccopts.sh $CC` -DOSVERSION=`./tools/osversion.sh CRAY`" \
				 OSNAME="CRAY" CRAY ; 
		elif [ '$(CROSSCOMPILE)x' = '1x' ] ; then 
			make CFLAGS="$* `./tools/ccopts.sh $CC` -DOSVERSION=`./tools/osversion.sh $OSNAME`" \
				 $OSNAME ; 
		else 
			make CFLAGS="$* `./tools/ccopts.sh $CC` -DOSVERSION=`./tools/osversion.sh autodetect`" \
				 $OSNAME ; 
		fi ;; 
esac
