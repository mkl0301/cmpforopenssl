#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ -z $1 ] || [ -z $2 ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0 USER PASSWORD"
	exit 1
fi

set -x
${CMPCLIENT} --ir \
	     --insta \
	     --server ${INSTA_SERVER} \
	     --port ${INSTA_PORT} \
	     --path ${INSTA_SERVERPATH} \
	     --proxy \
	     --cacert ${INSTA_CACERT} \
	     --key ${CLKEY} \
	     --clcert ${CLCERT} \
	     --user $1 \
	     --password $2
set +x
