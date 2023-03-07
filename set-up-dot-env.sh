#!/bin/bash

set -e
set -x

# this script prepares certs for local development and experimentation
# using mkcert (https://github.com/FiloSottile/mkcert), and sets up the
# environment accordingly in .env

rm -f cert.pem key.pem fullchain.pem

mkcert -cert-file cert.pem -key-file key.pem example.org

cp cert.pem fullchain.pem

CAROOT=$(mkcert -CAROOT)

cat "$CAROOT/rootCA.pem" >> fullchain.pem

CERT_ROOTS=`openssl x509 -noout -in "$CAROOT"/rootCA.pem -fingerprint -sha256 | cut -f 2 -d '=' | sed 's/://g' | awk '{print tolower($0)}'`

cat <<EOF > .env
DOMAIN=example.org
CERTFILE=fullchain.pem
KEYFILE=key.pem
CERT_ROOTS=$CERT_ROOTS
EOF
