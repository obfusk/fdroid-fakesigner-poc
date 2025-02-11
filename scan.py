#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import hashlib
import logging
import sys
import zipfile

from pyasn1.codec.der.decoder import decode as pyasn1_decode
from pyasn1.codec.der.encoder import encode as pyasn1_encode
from pyasn1.error import PyAsn1Error
from pyasn1_modules import rfc2315                          # type: ignore[import-untyped]

from typing import Any, List, Optional, Tuple

try:
    from androguard.core import apk as ag_apk               # type: ignore[import-untyped]
except ImportError:
    from androguard.core.bytecodes import apk as ag_apk     # type: ignore[import-untyped]


class Err(Exception):
    pass


class Warn(Exception):
    pass


# NB: monkey patch of sorts
class HDict(dict):                                          # type: ignore[type-arg]
    def __init__(self) -> None:
        self.history: List[Tuple[Any, Any]] = []

    def __setitem__(self, k: Any, v: Any) -> None:
        self.history.append((k, v))
        super().__setitem__(k, v)

    # for androguard >= v4.1.2 which fixes duplicate block ID handling
    # but does not yet have an API to get all but the first
    def __contains__(self, k: Any) -> bool:
        return False


def wrangle_androguard(apk: str) -> Tuple[List[int], List[bytes], List[bytes], List[bytes]]:
    instance = ag_apk.APK(apk)
    assert getattr(instance, "_v2_blocks", None) == {}      # pylint: disable=C1803
    instance._v2_blocks = hdict = HDict()
    instance.parse_v2_v3_signature()
    block_ids = [k for k, v in hdict.history]
    instance = ag_apk.APK(apk)
    v3_certs = instance.get_certificates_der_v3()
    v2_certs = instance.get_certificates_der_v2()
    instance = ag_apk.APK(apk)
    assert instance._APK_SIG_KEY_V3_SIGNATURE == 0xf05368c0
    instance._APK_SIG_KEY_V3_SIGNATURE = 0x1b93ad61         # v3.1
    v31_certs = instance.get_certificates_der_v3()
    return block_ids, v2_certs, v3_certs, v31_certs


def check_apk_certs(apk: str) -> Optional[bytes]:
    block_ids, v2_certs, v3_certs, v31_certs = wrangle_androguard(apk)
    if len(block_ids) != len(set(block_ids)):
        raise Err("Duplicate block IDs")
    if len(v31_certs) > 1:
        raise Warn("Multiple v3.1 certificates")
    if len(v3_certs) > 1:
        raise Warn("Multiple v3 certificates")
    if len(v2_certs) > 1:
        raise Warn("Multiple v2 certificates")
    if not (v2_certs or v3_certs or v31_certs):
        return None
    if v31_certs and not v3_certs:
        raise Err("No v3 certs even though v3.1 cert is present")
    if v3_certs and v31_certs and v3_certs != v31_certs:
        raise Warn("Mismatch between v3 and v3.1 certificates (probably rotation)")
    if v2_certs and v3_certs and v2_certs != v3_certs:
        raise Warn("Mismatch between v2 and v3 certificates (possibly rotation)")
    result = v3_certs[0] if v3_certs else v2_certs[0]
    assert isinstance(result, bytes)
    return result


# FIXME: check for .RSA w/o .SF?
def check_jar_certs(apk: str) -> Optional[bytes]:
    signature_block_files = []
    with zipfile.ZipFile(apk, "r") as zf:
        for info in zf.infolist():
            if info.orig_filename.startswith("META-INF/"):
                if any(info.orig_filename.endswith(ext) for ext in (".DSA", ".EC", ".RSA")):
                    signature_block_files.append(zf.read(info))
            if any(c in info.orig_filename for c in "\x00\n\r"):
                raise Warn("NUL, LF, or CR in filename")
    if len(signature_block_files) > 1:
        raise Warn("Multiple signature block files")
    if not signature_block_files:
        return None
    certificates = []
    try:
        cinf = pyasn1_decode(signature_block_files[0], asn1Spec=rfc2315.ContentInfo())[0]
        if cinf["contentType"] != rfc2315.signedData:
            raise Err("Signature block file contentType is not signedData")
        sdat = pyasn1_decode(cinf["content"], asn1Spec=rfc2315.SignedData())[0]
        for cert in sdat["certificates"]:
            certificates.append(pyasn1_encode(cert))
    except PyAsn1Error as e:
        raise Err("Unable to parse signature block file data") from e
    if len(certificates) > 1:
        raise Warn("Multiple certificates in signature block file")
    if not certificates:
        raise Err("No certificates in signature block file")
    assert isinstance(certificates[0], bytes)
    return certificates[0]


# NB: this will flag some valid APKs too, e.g. those with certificate chains,
# rotation, or multiple signers
def check_apks(*apks: str, verbose: bool) -> bool:
    ok = True
    for apk in apks:
        if verbose:
            print(f"Checking {apk!r} ...")
        try:
            apk_cert = check_apk_certs(apk)
            jar_cert = check_jar_certs(apk)
            if apk_cert is None and jar_cert is None:
                raise Err("No certificates in APK")
            if apk_cert is not None and jar_cert is not None and apk_cert != jar_cert:
                raise Warn("Mismatch between v1 and v2/v3 certificates")
        except (Err, Warn) as e:
            ok = False
            if verbose:
                t = "Error" if isinstance(e, Err) else "Warning"
                print(f"  {t}: {e}", file=sys.stderr)
            else:
                print(f"{apk!r}: {e}", file=sys.stderr)
        else:
            if verbose:
                cert = apk_cert or jar_cert
                assert isinstance(cert, bytes)
                fingerprint = hashlib.sha256(cert).hexdigest()
                print(f"  OK {fingerprint}")
    return ok


def _nologging() -> None:
    # disable androguard warnings
    logging.getLogger().setLevel(logging.ERROR)
    try:
        from loguru import logger                           # type: ignore
        logger.remove()
    except ImportError:
        pass


if __name__ == "__main__":
    _nologging()
    parser = argparse.ArgumentParser(description="Check APKs for possible signature issues.")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("apks", metavar="APK", nargs="*", help="APK file(s) to check")
    args = parser.parse_args()
    if not check_apks(*args.apks, verbose=args.verbose):
        sys.exit(1)

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
