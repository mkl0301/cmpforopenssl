#!/bin/sh

openssl x509 -inform DER -text -in $1
