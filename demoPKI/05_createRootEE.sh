#!/bin/sh

# Creates directroy structure, private key and certificate for
# CMP Test Root EEs

# 2011-07-25 Martin.Peylo@nsn.com initial creation

if [ ! -n "$1" ]
then
  echo "ERROR, please specifiy EE number"
  echo "Usage:"
  echo "       $0 [number]"
  exit 1
fi

NUMBER=$1


ENTITY=rootEE

. functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.rootCA.cnf

# private key of the used CA
CAKEY=rootCA/private/privkey.rootCA.pem

mkdir -p ${ENTITY}

CRT=${ENTITY}/cert.${ENTITY}${NUMBER}.pem
KEY=${ENTITY}/privkey.${ENTITY}${NUMBER}.pem
CSR=${ENTITY}/request.${ENTITY}${NUMBER}.csr

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=CMP Test Root EE ${NUMBER}/OU=CTO Research/O=NSN/L=Espoo/C=FI"
$OSSL ca  -config $OPENSSL_CONF -out $CRT -batch -keyfile $CAKEY -infiles $CSR

# vi: ts=8 noexpandtab tw=0
