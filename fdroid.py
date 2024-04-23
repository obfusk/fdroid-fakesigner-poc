#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys

import fdroidserver.common as c     # type: ignore[import-untyped]


class FakeOptions:
    verbose = True


c.config = {}
c.fill_config_defaults(c.config)
c.options = FakeOptions()

poc = sys.argv[1] if len(sys.argv) > 1 else "poc.apk"

print(c.verify_apk_signature(poc))
print(c.apk_signer_fingerprint(poc))
