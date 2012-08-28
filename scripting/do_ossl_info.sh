#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ -z $1 ] || [ -z $2 ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0 USER PASSWORD"
	exit 1
fi

echo "${CMPCLIENT} --info --server ${SERVER} --port ${PORT} --srvcert ${CACERT} --hex --user $1 --password $2"

#${CMPCLIENT} --info --server ${SERVER} --port ${PORT} \
#             --srvcert ${CACERT} \
#	     --hex --user $1 --password $2

${CMPCLIENT} --info --server ${SERVER} --port ${PORT} \
        --srvcert ${CACERT} \
	    --key ${CLKEY} --clcert ${CLCERT} \
	    --hex --user "$1" --password "$2" 
	    
	   # --path ejbca/publicweb/cmp
