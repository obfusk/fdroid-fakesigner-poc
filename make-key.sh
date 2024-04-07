#!/bin/bash
openssl req -x509 -newkey rsa:2048 -sha512 -outform DER -out cert-rsa.der -days 10000 -nodes -subj '/CN=oops' -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey-rsa.der
