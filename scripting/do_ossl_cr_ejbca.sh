#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

set -x

${CMPCLIENT} --cr \
	--insta3.3 \
	--server ${SERVER} \
	--port ${PORT} \
	--cacert ${CACERT} \
	--path "ejbca/publicweb/cmp" \
	--key ${CLKEY} \
	--newkey ${NEWCLKEY} \
	--clcert ${CLCERT} \
	--newclcert ${NEWCLCERT}  \
	--hex \
	--user $1 \
	--password $2

set +x

