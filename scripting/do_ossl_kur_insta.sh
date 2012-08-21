#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

set -x

${CMPCLIENT} --kur \
             --server ${INSTA_SERVER} \
	     --port ${INSTA_PORT} \
	     --srvcert ${INSTA_CACERT} \
	     --path "pkix/" \
	     --key ${CLKEY} \
	     --newkey ${NEWCLKEY} \
	     --subject "CN=Name" \
	     --clcert ${CLCERT} \
             --newclcert ${NEWCLCERT} 

set +x
