# F-Droid Certificate Pinning Bypasses - Overview

Overview of `fdroidserver` `AllowedAPKSigningKeys` certificate pinning bypasses.

Published: 2025-01-10.

## APK Signatures

- Android uses 4 different types of APK signatures: v1, v2, v3, and v3.1.
- Version 2 was introduced with Android 7, version 3 (essentially version 2 with
  support for key rotation) with Android 9, version 3.1 (a slightly improved
  version 3) with Android 13.
- An APK can be signed with any combination of these (except v3.1 always comes
  with a v3 as well), but Android < 7 only supports v1 and Android < 9 only
  supports v1 and v2, etc.
- APKs that target Android 11 (`targetSdk` >= 30) cannot be installed on devices
  running Android >= 11 if they only have a v1 signature; APKs with a lower
  `targetSdk` still install fine on any version of Android with only a v1
  signature.
- Which key an app is signed with does not matter to Android (except for things
  like verified app links).
- But apps cannot be updated without a compatible signature.

Links:

- https://source.android.com/docs/security/features/apksigning/v2
- https://source.android.com/docs/security/features/apksigning/v3

## F-Droid Repositories

- The f-droid.org repository builds from a checkout of the upstream source code
  repository and either signs the APK with their own key, or, with Reproducible
  Builds (~10% of apps), copies the signature from the APK published by the
  upstream developer(s).
- Repositories like IzzyOnDroid do not build from source but publish APKs
  provided directly by the upstream developer(s).  With Reproducible Builds
  (~30% of apps at IzzyOnDroid), independent rebuilds verify that building from
  source produces a bitwise identical APK.

Links:

- https://reproducible-builds.org/
- https://f-droid.org/docs/Reproducible_Builds/
- https://android.izzysoft.de/articles/named/iod-scan-apkchecks
- https://android.izzysoft.de/articles/named/review-2024-outlook-2025

## Certificate Pinning

- The `AllowedAPKSigningKeys` setting is meant to pin the certificate of the
  signing key used.
- It ensures only APKs signed with one of the allowed keys can be published in
  the repository.
- For repositories like IzzyOnDroid, this ensures APKs can only be provided by
  someone in control of the upstream signing key.
- For f-droid.org Reproducible Builds it ensures the same.
- The f-droid.org repository does not have any other cryptographic checks to
  prevent updates from compromised upstream repositories: it will build whatever
  is published in the upstream source code repository (though with Reproducible
  Builds the build must be reproducible).

## Exploits

- Best practice for certificate pinning is to implement it as part of the
  signature verification; this is what `apkrepotool` does using `apksig`.
- The `fdroidserver` implementation uses `apksigner` to verify the APK has a
  valid signature, but uses completely different code to extract the certificate
  from the APK.
- Multiple exploits have been demonstrated that exploit these differences by
  creating signatures that are entirely valid according to `apksigner` but for
  which the `fdroidserver` code returns the wrong certificate fingerprint, one
  that can be freely chosen, thus completely defeating the certificate pinning
  protections.

Links:

- https://github.com/obfusk/fdroid-fakesigner-poc
- https://github.com/obfusk/apkrepotool

## Reaction

- The first vulnerability was ignored for a year after being publicly reported
  and only fixed after a PoC and patch were published.
- Despite known exploits being patched, new exploits have continuously been
  discovered.
- Despite repeated warnings of bad practice, the `fdroidserver` implementation
  still uses their own custom code for certificate extraction instead of
  combining signature verification and certificate extraction into one step
  using `apksig` (for which code was provided to them, which they ignored).
- F-Droid has falsely claimed that "APKs signed by v1-only are not even
  installable on latest Android versions".
- F-Droid has claimed to be unable to use the provided patches as-is because of
  "code quality issues" (private APIs) despite only the patch they already
  merged 8 months ago (`fdroidserver.patch`) matching that description.
- F-Droid is correct that the certificate pinning bypasses "can only be
  exploited when an upstream project is compromised first, and only new
  installations will be affected"; that is indeed how certificate pinning works.
- F-Droid deems the latest certificate pinning bypass "low urgency" because it
  "currently does not affect f-droid.org", showing a concerning disregard for
  the security requirements of other repositories relying on `fdroidserver` and
  seemingly confirming that preventing publishing updates from compromised
  upstream repositories using cryptographic checks is not considered part of the
  security model of f-droid.org.

Links:

- https://gitlab.com/fdroid/fdroidserver/-/issues/1128
- https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1466
- https://floss.social/@IzzyOnDroid/113765504171758318
- https://floss.social/@fdroidorg/113804900156856580
