touch index.txt 
openssl genrsa -out cakey.pem 2048
openssl req -new -config ca.cnf -key cakey.pem -out careq.csr -subj "/CN=Root CA"
openssl ca -config ca.cnf -create_serial -out cacert.pem -days 3650 -batch -keyfile cakey.pem -selfsign -extensions v3_ca -infiles careq.csr
openssl x509 -in cacert.pem -inform PEM -out cacert.der -outform DER
