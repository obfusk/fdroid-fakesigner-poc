#!/bin/bash
openssl req -x509 -newkey rsa:2048 -sha512 -outform DER -out cert-rsa-orig.der -days 10000 -nodes -subj '/CN=Foo Bar' -set_serial 1279905024 -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey-rsa-orig.der
openssl req -x509 -newkey rsa:2048 -sha512 -outform DER -out cert-rsa-fake.der -days 10000 -nodes -subj $'/CN=Foo\tBar' -set_serial 1279905024 -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey-rsa-fake.der
