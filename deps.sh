#!/bin/bash
set -xe
if ! command -v apksigtool > /dev/null; then
  if [ "${1:-}" != --no-apt ]; then
    sudo apt-get update
    sudo apt-get install -y python3-{asn1crypto,click,cryptography,pyasn1,pyasn1-modules,simplejson}
  fi
  git clone -b v1.1.1 https://github.com/obfusk/apksigcopier.git
  ( cd apksigcopier && make install )
  git clone -b signing https://github.com/obfusk/apksigtool.git
  ( cd apksigtool && make install )
fi
if [ ! -e fake.apk ]; then
  git clone --depth=1 -b platform-tools-35.0.2 \
    https://android.googlesource.com/platform/tools/apksig.git
  ln -s apksig/src/test/resources/com/android/apksig/v2-ec-p256-targetSdk-30.apk app.apk
  ln -s apksig/src/test/resources/com/android/apksig/golden-aligned-v1v2v3-out.apk app2.apk
  cp apksig/src/test/resources/com/android/apksig/v3-only-with-stamp.apk app3.apk
  zip -d app3.apk stamp-cert-sha256
  wget -O fake.apk https://f-droid.org/archive/org.fdroid.fdroid_1017050.apk
fi
