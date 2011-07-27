#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ -z $1 ] || [ -z $2 ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        echo "Usage: $0 USER PASSWORD"
        exit 1
fi

set -x
${CMPCLIENT} --ir --server ${SERVER} 
                  --port ${PORT} \
                  --cacert ${CACERT} \
                  --newkey ${CLKEY} \
                  --newkeypass "password" \
                  --newclcert ${CLCERT} \
                  --hex \
                  --user "$1" \
                  --password "$2"
set +x

# vi: ts=8 expandtab
