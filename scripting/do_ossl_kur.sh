#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

echo "${CMPCLIENT} --kur --server ${SERVER} --port ${PORT} --cacert ${CACERT} --key ${CLKEY} --newkey ${NEWCLKEY} --clcert ${CLCERT} --newclcert ${NEWCLCERT}"

${CMPCLIENT} --kur --server ${SERVER} --port ${PORT} --cacert ${CACERT} --key ${CLKEY} --newkey ${NEWCLKEY} --clcert ${CLCERT} --newclcert ${NEWCLCERT}