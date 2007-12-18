#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ -z $1 ] || [ -z $2 ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0 USER PASSWORD"
	exit 1
fi

echo "${CMPCLIENT} --ir --server ${SERVER} --port ${PORT} --cacert ${CACERT} --key ${CLKEY} --clcert ${CLCERT} --hex --user $1 --password $2"
set -x
${CMPCLIENT} --ir --server ${SERVER} --port ${PORT} \
		--path ${SERVERPATH} \
		--proxy \
             --cacert ${CACERT} \
	     --key ${CLKEY} --clcert ${CLCERT} \
	     --user $1 --password $2
