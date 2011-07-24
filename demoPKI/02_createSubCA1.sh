#!/bin/sh -x

OSSL=../src/openssl/apps/openssl
OPENSSL_CONF=openssl.rootCA.cnf

ENTITY=subCA1

CATOP=$ENTITY
# create directory structure for CA
mkdir -p ${CATOP}
mkdir -p ${CATOP}/certs
mkdir -p ${CATOP}/crl
mkdir -p ${CATOP}/newcerts
mkdir -p ${CATOP}/private
# initialize needed CA "database" files 
touch ${CATOP}/index.txt
echo '01' > ${CATOP}/serial
echo '01' > ${CATOP}/crlnumber

CRT=${CATOP}/cert.${ENTITY}.pem
KEY=${CATOP}/private/privkey.${ENTITY}.pem
CSR=${CATOP}/request.${ENTITY}.csr

CAKEY=rootCA/private/privkey.rootCA.pem

$OSSL req -new -config $OPENSSL_CONF -keyout $KEY -out $CSR
$OSSL ca  -config $OPENSSL_CONF -out $CRT -batch -keyfile $CAKEY -extensions v3_ca -infiles $CSR

# vi: ts=8 noexpandtab tw=0
