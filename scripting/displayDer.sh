#!/bin/sh
myDir=`dirname $0`
. $myDir/settings.sh

if [ -z $1 ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0 CERTFILE.der"
	exit 1
fi

${OPENSSL} x509 -inform DER -text -in $1
