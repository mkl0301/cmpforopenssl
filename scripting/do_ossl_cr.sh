#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

echo "${CMPCLIENT} --cr --server ${SERVER} --port ${PORT} --srvcert ${CACERT} --key ${CLKEY} --clcert ${CLCERT} --user $1 --password $2"
set -x
${CMPCLIENT} \
	--cr \
	--cryptlib \
	--server ${SERVER} \
	--port ${PORT} \
	--srvcert ${CACERT} \
	--key ${CLKEY} \
	--clcert ${CLCERT} \
	--user $1 \
	--password $2
set +x
