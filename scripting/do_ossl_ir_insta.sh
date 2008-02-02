#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

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
	     --user ${INSTA_USER} \
	     --password ${INSTA_PASS}
set +x
