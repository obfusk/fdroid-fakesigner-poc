#!/bin/bash
set -e
test -e cert-rsa.der      || ./make-key.sh
test -e cert-rsa-orig.der || ./make-key-v4.sh
python3 make-poc-v1.py    ; mv poc.apk poc1.apk
python3 make-poc-v2.py    ; mv poc.apk poc2.apk
python3 make-poc-v3a.py   ; mv poc.apk poc3a.apk
python3 make-poc-v3b.py   ; mv poc.apk poc3b.apk
python3 make-poc-v4.py    ; mv poc.apk poc4.apk
python3 make-poc-v5a.py   ; mv poc.apk poc5a.apk
python3 make-poc-v5b.py   ; mv poc.apk poc5b.apk
python3 make-poc-v6.py    ; mv poc.apk poc6.apk
rm poc-unsigned.apk poc-signed-orig.apk
