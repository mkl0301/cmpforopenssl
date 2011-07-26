#!/bin/sh

# Creates directroy structure, private key and certificate for
# CMP Test Sub CA 1

# 2011-07-25 Martin.Peylo@nsn.com initial creation


ENTITY=otherCA

. functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.rootCA.cnf

# private key of the used CA
CAKEY=rootCA/private/privkey.rootCA.pem

CRT=${ENTITY}/cert.${ENTITY}.pem
XCRT=${ENTITY}/cert.x.${ENTITY}.pem
KEY=${ENTITY}/private/privkey.${ENTITY}.pem
XCSR=${ENTITY}/request.x.${ENTITY}.csr

#$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=CMP Test Sub CA 1/OU=CTO Research/O=NSN/L=Espoo/C=FI"

$OSSL x509 -x509toreq -in $CRT -out $XCSR -signkey $KEY
$OSSL ca  -config $OPENSSL_CONF -out $XCRT -batch -keyfile $CAKEY -extensions v3_subca -infiles $XCSR

# vi: ts=8 noexpandtab tw=0
