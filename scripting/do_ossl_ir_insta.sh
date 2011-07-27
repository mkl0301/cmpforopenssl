#!/usr/bin/env bash
myDir=`dirname $0`
. $myDir/settings.sh

set -x
${CMPCLIENT} --ir \
                  --insta3.3 \
                  --server ${INSTA_SERVER} \
                  --port ${INSTA_PORT} \
                  --path ${INSTA_SERVERPATH} \
                  --cacert ${INSTA_CACERT} \
                  --newkey ${CLKEY} \
                  --newkeypass "password" \
                  --newclcert ${CLCERT} \
                  --user ${INSTA_USER} \
                  --capubs tmp \
                  --subject "CN=Name" \
                  --password "${INSTA_PASS}" 
set +x

# vi: ts=8 expandtab
