#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

CMD="${CMPCLIENT} --kur --server ${SERVER} --port ${PORT} --srvcert ${CACERT} --key ${CLKEY} --newkey ${NEWCLKEY} --clcert ${CLCERT} --newclcert ${NEWCLCERT} $*"
echo $CMD
$CMD
