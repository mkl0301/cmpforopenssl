#!/bin/sh
# Build the shared library.  The options need to be tuned for some systems
# since there's no standard for shared libraries, and different versions of
# gcc also changed the way this was handled:
#
# AIX:			AIX requires some weird voodoo which is unlike any other
#				system's way of doing it (probably done by the MVS team,
#				see "AIX Linking and Loading Mechanisms" for a starter).
#				In addition to this, the shared lib (during development)
#				must be given permissions 750 to avoid loading it
#				permanently into the shared memory segment (only root can
#				remove it).  The production shared library must have a
#				555 (or whatever) permission.  Finally, the library has to
#				have a ".a" suffix (even though it's a shared lib), so we
#				tack this on after the $LIBNAME.
#
#				The various AIX options are: '-bnoentry' = don't look for a
#				main(), '-bE' = export the symbols in cryptlib.exp,
#				'-bM:SRE' = make it a shared library.
#				$(LD) -ldl -bE:cryptlib.exp -bM:SRE -bnoentry
# BeOS:			$(LD) -nostart
# Cygwin:		$(LD) -L/usr/local/lib -lcygipc
# HPUX:			Link with gcc (to the GNU libs) if compiled with gcc,
#				otherwise link with the standard compiler into the system
#				libs.  If you're mixing GNU and system libs (e.g. cryptlib
#				built with gcc and the calling app built with the HP cc),
#				you may want to use '-static-libgcc' to avoid having to ship
#				a copy of glibc just for cryptlib.
#				Note that on some versions of PHUX stripping the shared lib.
#				may prevent it from being linked, you may need to remove
#				this command in that case.
#				$(LD) -shared -Wl,-soname,lib$(PROJ).so.$(MAJ)
# Solaris:		$(LD) -G -ldl -o lib$(PROJ).so.$(MAJ)
#
# An additional possibility under the *BSDs and Linux is:
#
# *BSDs:		$(LD) -Bshareable -o lib$(PROJ).so.$(MAJ)
# Linux:		$(LD) -Bshareable -ldl -o lib$(PROJ).so.$(MAJ)

LINKFILE=link.tmp

# Make sure that we've been given sufficient arguments.

if [ "$1" = "" ] ; then
	echo "$0: Missing OS name." >&2 ;
	exit 1 ;
fi
if [ "$2" = "" ] ; then
	echo "$0: Missing library name." >&2 ;
	exit 1 ;
fi
if [ "$3" = "" ] ; then
	echo "$0: Missing linker name." >&2 ;
	exit 1 ;
fi
if [ "$4" = "" ] ; then
	echo "$0: Missing object filenames." >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

OSNAME=$1
LIBNAME=$2
LD=$3
shift
shift
shift

rm -f $LINKFILE
echo $* > $LINKFILE
case $OSNAME in
	'AIX')
		$LD -o shrlibcl.o -bE:cryptlib.exp -bM:SRE -bnoentry -lpthread \
			`cat $LINKFILE` `./tools/getlibs.sh AIX` ;
		ar -q $LIBNAME.a shrlibcl.o;
		rm -f shrlibcl.o;
		chmod 750 $LIBNAME.a ;;

	'BeOS' )
		$LD -nostart -o $LIBNAME `cat $LINKFILE` `./tools/getlibs.sh BeOS` ;
		strip $LIBNAME ;;

	'HP-UX')
		if [ $LD = "gcc" ] ; then
			$LD -shared -o libcl.sl `cat $LINKFILE` `./tools/getlibs.sh HP-UX` ;
		else
			$LD -b -o libcl.sl `cat $LINKFILE` `./tools/getlibs.sh HP-UX` ;
		fi
		strip libcl.sl ;;

	'SunOS')
		if [ $LD = "gcc" ] ; then
			$LD -shared -o $LIBNAME `cat $LINKFILE` `./tools/getlibs.sh autodetect` ;
		else
			$LD -G -ldl -o $LIBNAME `cat $LINKFILE` `./tools/getlibs.sh autodetect` ;
		fi
		strip $LIBNAME ;;

	*)
		$LD -shared -o $LIBNAME `cat $LINKFILE` `./tools/getlibs.sh autodetect` ;
		strip $LIBNAME ;;
esac
rm -f $LINKFILE
