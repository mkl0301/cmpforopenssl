#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

echo "${CMPSERVER} --daemon --server ${SERVER} --port ${PORT} --cacert ${CACERT} --key ${CAKEY}"

${CMPSERVER} --daemon --server ${SERVER} --port ${PORT} --cacert ${CACERT} --key ${CAKEY}
