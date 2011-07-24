#!/bin/sh -x

OSSL=../src/openssl/apps/openssl
export OPENSSL_CONF=openssl.rootCA.cnf

ENTITY=rootCA

CATOP=$ENTITY

mkdir -p ${CATOP}/certs
mkdir -p ${CATOP}/crl
mkdir -p ${CATOP}/newcerts
mkdir -p ${CATOP}/private
touch ${CATOP}/index.txt
echo '01' > ${CATOP}/serial
echo '01' > ${CATOP}/crlnumber

CRT=${CATOP}/cert.${ENTITY}.pem
KEY=${CATOP}/private/privkey.${ENTITY}.pem
CSR=${CATOP}/request.${ENTITY}.csr

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR
$OSSL ca  -config $OPENSSL_CONF -create_serial -out $CRT -batch -keyfile $KEY -selfsign -extensions v3_ca -infiles $CSR

# vi: ts=8 noexpandtab tw=0
