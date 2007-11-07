#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo "Usage: $0"
	exit 1
fi

echo "${CMPSERVER} --createcert --cacert ${CACERT} --key ${CAKEY} --country ${SRVCOUNTRY} --organization ${SRVORG} --unit ${SRVUNIT} --commonname ${SRVCN}"

${CMPSERVER} --createcert --cacert ${CACERT} --key ${CAKEY} --country ${SRVCOUNTRY} --organization "${SRVORG}" --unit "${SRVUNIT}" --commonname "${SRVCN}"

echo "HINT:"
echo "  Don't forget to copy \"${CACERT}\" to the certs-directory"
echo "  of the client if it is different from this installation!"
