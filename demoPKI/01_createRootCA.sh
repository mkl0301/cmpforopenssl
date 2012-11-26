#!/bin/bash

# Creates directroy structure, private key and certificate for
# CMP Test Root CA

# 2011-07-25 Martin.Peylo@nsn.com initial creation


ENTITY=rootCA

. ./functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.rootCA.cnf
SSLEAY_CONF=$OPENSSL_CONF

# private key of the used CA
CAKEY=rootCA/private/privkey.rootCA.pem

createCaDirStructure $ENTITY

CRT=${ENTITY}/cert.${ENTITY}.pem
KEY=${ENTITY}/private/privkey.${ENTITY}.pem
CSR=${ENTITY}/request.${ENTITY}.csr

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=CMP Test Root CA/OU=CTO Research/O=NSN/L=Espoo/C=FI"
$OSSL ca  -config $OPENSSL_CONF -create_serial -out $CRT -days 3650 -batch -keyfile $CAKEY -selfsign -extensions v3_ca -infiles $CSR

# vi: ts=8 noexpandtab tw=0
