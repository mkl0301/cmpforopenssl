#!/bin/sh

# Creates directroy structure, private key and certificate for
# CMP Test Other EEs

# 2011-07-25 Martin.Peylo@nsn.com initial creation

if [ ! -n "$1" ]
then
  echo "ERROR, please specifiy EE number"
  echo "Usage:"
  echo "       $0 [number]"
  exit 1
fi

NUMBER=$1


ENTITY=otherEE

. functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.otherCA.cnf

# private key of the used CA
CAKEY=otherCA/private/privkey.otherCA.pem

mkdir -p ${ENTITY}s

CRT=${ENTITY}s/cert.${ENTITY}${NUMBER}.pem
KEY=${ENTITY}s/privkey.${ENTITY}${NUMBER}.pem
CSR=${ENTITY}s/request.${ENTITY}${NUMBER}.csr

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=Other Root EE ${NUMBER}/OU=Services/O=BeachTel/C=PW"
$OSSL ca  -config $OPENSSL_CONF -out $CRT -batch -keyfile $CAKEY -infiles $CSR

# vi: ts=8 noexpandtab tw=0
