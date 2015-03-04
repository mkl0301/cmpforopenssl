#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

if [ -z $1 ] || [ -z $2 ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        echo "Usage: $0 USER PASSWORD"
        exit 1
fi

USR=$(echo "$1" | perl -ne 's/([0-9a-f]{2})/print chr hex $1/gie')
PAS=$(echo "$2" | perl -ne 's/([0-9a-f]{2})/print chr hex $1/gie')
set -x
${CMPCLIENT} --ir --server ${SERVER} \
                  --port ${PORT} \
                  --srvcert ${CACERT} \
                  --newkey ${CLKEY} \
                  --newkeypass "password" \
                  --newclcert ${CLCERT} \
                  --user "$USR" \
                  --password "$PAS"
set +x

# vi: ts=8 expandtab
