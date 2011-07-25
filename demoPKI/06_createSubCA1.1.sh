#!/bin/sh

# Creates directroy structure, private key and certificate for
# CMP Test Sub CA 1.1

# 2011-07-25 Martin.Peylo@nsn.com initial creation


ENTITY=subCA1.1

. functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.subCA1.cnf

# private key of the used CA
CAKEY=subCA1/private/privkey.subCA1.pem

createCaDirStructure $ENTITY

CRT=${ENTITY}/cert.${ENTITY}.pem
KEY=${ENTITY}/private/privkey.${ENTITY}.pem
CSR=${ENTITY}/request.${ENTITY}.csr

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=CMP Test Sub CA 1.1/OU=CTO Research/O=NSN/L=Espoo/C=FI"
$OSSL ca  -config $OPENSSL_CONF -out $CRT -batch -keyfile $CAKEY -extensions v3_subsubca -infiles $CSR

# vi: ts=8 noexpandtab tw=0
