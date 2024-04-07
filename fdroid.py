#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import fdroidserver.common as c     # type: ignore[import-untyped]


class FakeOptions:
    verbose = True


c.config = {}
c.fill_config_defaults(c.config)
c.options = FakeOptions()

print(c.verify_apk_signature("poc.apk"))
print(c.apk_signer_fingerprint("poc.apk"))
