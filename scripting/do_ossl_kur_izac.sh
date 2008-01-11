#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

set -x

${CMPCLIENT} --kur \
             --cryptlib \
             --server ${IZAC_SERVER} \
	     --cacert ${IZAC_CACERT} \
	     --key ${CLKEY} \
	     --newkey ${NEWCLKEY} \
	     --clcert ${CLCERT} \
             --newclcert ${NEWCLCERT}
set +x
