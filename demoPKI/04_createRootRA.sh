#!/bin/bash

# Creates directroy structure, private key and certificate for
# CMP Test Root RA

# 2011-07-25 Martin.Peylo@nsn.com initial creation


ENTITY=rootRA

. functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.rootCA.cnf

# private key of the used CA
CAKEY=rootCA/private/privkey.rootCA.pem

mkdir -p ${ENTITY}

CRT=${ENTITY}/cert.${ENTITY}.pem
KEY=${ENTITY}/privkey.${ENTITY}.pem
CSR=${ENTITY}/request.${ENTITY}.csr

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=CMP Test Root RA/OU=CTO Research/O=NSN/L=Espoo/C=FI"
$OSSL ca  -config $OPENSSL_CONF -out $CRT -batch -keyfile $CAKEY -extensions v3_ra -infiles $CSR

# vi: ts=8 noexpandtab tw=0
