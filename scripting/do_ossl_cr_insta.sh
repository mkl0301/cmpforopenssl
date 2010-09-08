#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

set -x
${CMPCLIENT} \
	--cr \
	--insta3.3 \
	--server ${INSTA_SERVER} \
	--port   ${INSTA_PORT}   \
	--path   ${INSTA_SERVERPATH} \
	--cacert ${INSTA_CACERT} \
	--key    ${CLKEY}  \
	--clcert ${CLCERT} \
	--newclcert ${NEWCLCERT} \
	--user ${INSTA_USER} \
	--password "${INSTA_PASS}" 
set +x
