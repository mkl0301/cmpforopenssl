#!/bin/sh

# Creates directroy structure, private key and certificate for
# CMP Test Sub 1.1 EE

# 2011-07-25 Martin.Peylo@nsn.com initial creation

if [ ! -n "$1" ]
then
  echo "ERROR, please specifiy EE number"
  echo "Usage:"
  echo "       $0 [number]"
  exit 1
fi

NUMBER=$1


ENTITY=sub2EE

. functions.sh

# configuration file for the used CA
OPENSSL_CONF=openssl.subCA2.cnf

# private key of the used CA
CAKEY=subCA2/private/privkey.subCA2.pem

mkdir -p ${ENTITY}s

CRT=${ENTITY}s/cert.${ENTITY}${NUMBER}.pem
KEY=${ENTITY}s/privkey.${ENTITY}${NUMBER}.pem
CSR=${ENTITY}s/request.${ENTITY}${NUMBER}.csr

$OSSL req -new -newkey rsa:1024 -config $OPENSSL_CONF -keyout $KEY -out $CSR -subj "/CN=CMP Test Sub 2 EE ${NUMBER}/OU=CTO Research/O=NSN/L=Espoo/C=FI"
$OSSL ca  -config $OPENSSL_CONF -out $CRT -batch -keyfile $CAKEY -infiles $CSR

# vi: ts=8 noexpandtab tw=0
