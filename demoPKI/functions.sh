#!/bin/sh

OSSL=../src/openssl/apps/openssl

function createCaDirStructure() {
  # fail if no option was given
  if [ ! -n "$1" ] 
    then
      echo "Error in script, no directory given for createCaDirStructure().  Aborting"
      exit 1
    fi

  CATOP=$1
  echo "Creating directory structure for CA in ${CATOP}"
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
}

# vi: ts=8 noexpandtab tw=0
