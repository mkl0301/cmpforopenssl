#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

echo "${CMPCLIENT} --cr --cryptlib --server ${SERVER} --port ${PORT} --cacert ${CACERT} --key ${CLKEY} --clcert ${CLCERT} --hex --user $1 --password $2"
set -x
${CMPCLIENT} \
	--cr \
	--cryptlib \
	--server ${SERVER} \
	--port ${PORT} \
	--cacert ${CACERT} \
	--key ${CLKEY} \
	--clcert ${CLCERT} \
	--hex \
	--user $1 \
	--password $2
set +x
