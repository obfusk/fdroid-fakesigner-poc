# F-Droid Fake Signer PoC

PoC for `fdroidserver` `AllowedAPKSigningKeys` certificate pinning bypass.

Published: 2024-04-08; updated: 2024-04-14, 2024-04-20, 2024-12-30, 2025-01-06,
2025-01-08, 2025-01-09, 2025-01-10, 2025-01-19, 2025-01-21.

**NB: no new updates will be provided solely to correct any further
counterfactual statements by F-Droid.  We implore them to take responsibility
for their mistakes instead of spreading misinformation in order to downplay our
findings.**

NB: see also [`OVERVIEW.md`](OVERVIEW.md).

## oss-security

* https://www.openwall.com/lists/oss-security/2024/04/08/8
* https://www.openwall.com/lists/oss-security/2024/04/20/3
* https://www.openwall.com/lists/oss-security/2025/01/03/1
* https://www.openwall.com/lists/oss-security/2025/01/20/1

## Background

We started looking into Android APK Signing Block oddities at the request of
F-Droid [1] on 2021-08-25; we opened F-Droid issue "APK Signing Block
considerations" [2] on 2022-10-19.  No action was taken as a result.

We published the "Android APK Signing Block Payload PoC" [3] to the Reproducible
Builds mailing list [4] on 2023-01-31.

> But the Android APK Signature Scheme v2/v3 actually allows embedding arbitrary
> data (or code) in the signing block, meaning that two APKs with the exact same
> valid signature -- though not a bit-by-bit identical signing block -- can
> behave differently.

Jason Donenfeld reported "Potential security hazard: `apk_signer_fingerprint()`
looks at certs in reverse order that Android checks them" [5] on 2023-05-05; no
action was taken to fix this bug.

> However, there's a discrepancy between how these certificates are extracted
> and how Android actually implements signature checks. [...] Notice how [the
> google flowchart [6]] checks v3, then v2, and then v1. Yet the [F-Droid] code
> above looks at v1, then v2, and then v3, in reverse order. So v1 could have a
> bogus signer that some versions of Android never even look at, yet fdroid
> makes a security decision based on it. Yikes! Also, it's worth noting that
> apk_signer_fingerprint() also does not bother validating that the signatures
> are correct.

Andreas Itzchak Rehberg (IzzyOnDroid) reported about "BLOBs in APK signing
blocks" in "Ramping up security: additional APK checks are in place with the
IzzyOnDroid repo" [7] on 2024-03-25.  The accompanying German article
"Android-Apps auf dem Seziertisch: Eine vertiefte Betrachtung" [8] points out
that we noticed that `apksigner` and `androguard` handle duplicate signing
blocks rather differently: the former only sees the first, the latter only the
last, which allows all kinds of shenanigans.

## Observations

We observed that embedding a v1 (JAR) signature file in an APK with `minSdk >=
24` will be ignored by Android/`apksigner`, which only checks v2/v3 in that
case.  However, since `fdroidserver` checks v1 first, regardless of `minSdk`,
and does not verify the signature, it will accept a "fake" certificate and see
an incorrect certificate fingerprint.

We also realised that the above mentioned discrepancy between `apksigner` and
`androguard` (which `fdroidserver` uses to extract the v2/v3 certificates) can
be abused here as well.  Simply copying the v2/v3 signature from a different APK
and appending it to the APK Signing Block will not affect `apksigner`'s
verification, but `androguard`, and thus also `fdroidserver`, will see only the
second block.  Again, the signature is not verified, a "fake" certificate
accepted, and an incorrect fingerprint seen.

As a result, it is trivial to bypass the `AllowedAPKSigningKeys` certificate
pinning, as we can make `fdroidserver` see whatever certificate we want instead
of the one Android/`apksigner` does.  Note that we don't need a valid signature
for the APK (we really only need a copy of the DER certificate, though having
another APK signed with the certificate we want to use makes things easy).

### Update (2024-04-14)

Having been asked about multiple certificates in APK signatures [5], we realised
that, like v2/v3 signatures, v1 signatures can indeed also contain multiple
certificates (e.g. a certificate chain, though neither `jarsigner` nor
`apksigner` seem to enforce any relationships between certificates).  However,
unlike v2/v3 -- which guarantee that the certificate used for the signature is
always the first in the sequence -- v1 does not define an ordering: the
signature block file is a PKCS#7 DER-encoded ASN.1 data structure (per RFC 2315)
and uses a SET for the list of certificates.

Android/`apksigner` will find and use the first certificate that matches the
relevant `SignerInfo`, ignoring any other certificates, but `fdroidserver`
always returns the first certificate it finds in the signature block file.  Thus
we can once again trick it into seeing any certificate we want -- as long as it
only checks the v1 certificate (e.g. when the `fdroidserver.patch` has not been
applied or the APK only has a v1 signature).

NB: apps with `targetSdk >= 30` are required to have a v2/v3 signature.

NB: Android < N will only check the first `SignerInfo`, later versions pick the
first one that verifies if there are multiple.

### Update (2024-04-20)

Despite repeated warnings [5] that using the last certificate instead of the
first one does not in any way fix the vulnerability described in the 2024-04-14
update (PoC #3), the proposed patches for `fdroidserver` [10] and `androguard`
[11] do exactly this.  With that patch, version A (which inserts the fake
certificate first) of the PoC now fails, but version B (which inserts it last)
now works.

### Update (2024-12-30 #1)

Instead of adopting the fixes we proposed, F-Droid wrote and merged their own
patch [10], ignoring repeated warnings it had significant flaws (including an
incorrect implementation of v1 signature verification and making it impossible
to have APKs with rotated keys in a repository).  As a result it is possible to
construct a valid v1 signature that `fdroidserver` matches to the wrong
certificate.

We do this by simply creating and prepending a second SignerInfo using our own
certificate, which has the same serial number and an almost identical issuer --
e.g. a common name with a space (0x20) replaced by a tab (0x09) or a DEL (0x7f)
appended -- to exploit an implementation that will match the SignerInfo against
the wrong certificate through incorrect canonicalisation.

Luckily, the impact is lower than that of the other vulnerabilities as it does
require a valid signature from the certificate one wishes to spoof.

### Update (2024-12-30 #2)

Unfortunately, we found another more severe vulnerability as well, caused by a
regex incorrectly handling newlines in filenames.  This allows another trivial
bypass of certificate pinning, as we can once again make `fdroidserver` see
whatever certificate we want instead of the one Android/`apksigner` does (as
long as we have a valid v1 signature for some other APK).

The regex in question, `^META-INF/.*\.(DSA|EC|RSA)$`, is supposed to match all
filenames that start with `META-INF/` and end with `.DSA`, `.EC,` or `.RSA`.
Unfortunately, the `.*` does not match newlines, and the `$` matches not just
the end of the string but "the end of the string or just before the newline at
the end of the string".  As a result we can use a newline in the filename of the
real signature files (before the extension), which Android/`apksigner` see but
`fdroidserver` does not, and a newline after the `.RSA` extension for the
spoofed signature files, which `fdroidserver` will see but Android/`apksigner`
will not.

NB: `androguard` seems to use a similarly incorrect regex.

We can do almost the exact same thing with NUL bytes instead of newlines,
independently of the flawed regex, because Python's `ZipInfo.filename` is
sanitised by removing any NUL byte and everything after it.  This will have the
same result for `fdroidserver` and `apksigner` (which happily accepts NUL bytes
in filenames) as above, but luckily Android rejects APKs with NUL bytes in
filenames, and such an APK will thus fail to install.

NB: in light of all of the above we reiterate that we strongly recommend using
the official `apksig` library (used by `apksigner`) to both verify APK
signatures and return the first signer's certificate to avoid these kind of
implementation mistakes and inconsistencies and thus further vulnerabilities.
Handling common cases correctly is fairly easy, but handling edge cases
correctly is hard; rolling your own implementation without the required
expertise and care to get it right is irresponsible.

### Update (2025-01-06)

F-Droid claims that the latest vulnerability "does not affect the repository on
f-droid.org".  Which suggests that they do not understand the significance of
this certificate pinning bypass, or they do not believe certificate pinning is
meant to provide protection against a compromise of an upstream repository
without a compromise of the upstream signing key.  Both are worrying.

All of the vulnerabilities described here were discovered by us *by accident*,
looking into things like key rotation, signature copying, and security scans for
IzzyOnDroid, not vulnerabilities in `fdroidserver`.  The first one was
independently discovered and reported a year earlier, and subsequently ignored.

The latest vulnerability, the incorrect regex, was not something we specifically
predicted.  But we warned F-Droid that their approach to handling certificate
pinning with custom code independent of the signature verification using
`apksigner` was full of mistakes and fundamentally flawed, which proved to be
correct again and again.

We recommended "using the official `apksig` library (used by `apksigner`) to
both verify APK signatures and return the first signer's certificate to avoid
these kind of implementation inconsistencies and thus further vulnerabilities
like this one".  We even provided a Python implementation for that.  All of our
recommendations were ignored.  We find this careless approach to security far
more worrying than the impact of the individual vulnerabilities described here.

We sincerely wish this document didn't have to exist.  We implore F-Droid to do
better, to live up to its potential, and do right by its community.

### Update (2025-01-08)

F-Droid now claims PoC 5a is not an "actionable security vulnerability" because
"APKs signed by v1-only are not even installable on latest Android versions".
This is false.  As long as `targetSdk < 30` (and e.g. the official F-Droid
client has 29) they will install just fine.  We even confirmed this by
installing the PoC APK on Android 13-15 just in case, something they apparently
neglected to bother with before making that claim.

### Update (2025-01-09)

F-Droid now claims they can't use the patches as-is because of "code quality
issues" (private APIs).  Which applies to exactly one patch: the one they
already merged 8 months ago (`fdroidserver.patch`).

Because the only way to fix the vulnerability was to monkey-patch `androguard`
(and an updated version is still not available in Debian, nor has the Debian
stable `fdroidserver` package received any patches, despite those packages being
maintained by the F-Droid team, so that monkey patch is still needed).

They are also downplaying the impact by insisting these vulnerabilities are only
a problem for third party repositories relying on `fdroidserver`; which, even if
true, is showing a concerning disregard for the security of the repositories of
other projects relying on `fdroidserver`.

Again, we find F-Droid's reaction and the security and code review processes on
display here to be highly concerning, far more than the vulnerabilities we
reported.

### Update (2025-01-19)

Quoting the response of F-Droid's Technical Lead [12]:

> fdroidserver is fully safe for the tasks it was built for. It has been
> independently audited as well (we have two more audits coming up). If you have
> a trusted collection of APKs, then fdroidserver provides the entry point to a
> trustworthy pipe to the F-Droid client. It cannot protect against malicious
> upstreams, upstreams losing their signing keys, etc. It cannot fix the
> deprecated v1 signatures. Require v2+ signatures, and AllowedAPKSigningKeys
> works with no known weaknesses.

Based on the above, we cannot but conclude that despite earlier claims that the
"goal of AllowedAPKSigningKeys is to make it easy for non-technical people to
manage binary APK repos securely", certificate pinning is in fact not expected
to provide any security against e.g. updates from compromised upstream
repositories as it assumes a "trusted collection of APKs".

We wonder what exactly the intended purpose of certificate pinning is if not to
ensure APKs can only be provided by someone in control of the upstream signing
key, as this is the kind of security repositories like IzzyOnDroid expected it
to provide.  We also observe that the 2018 audit predates the implementation of
`AllowedAPKSigningKeys` certificate pinning.

Another quote [13]:

> [...] why #fdroidserver implements somethings in #Python rather than scraping
> #apksigner output. Reliably and securely parsing CLI output over the long term
> is really hard to get right because deployed fdroidserver code has to be
> future proof, in that it has to support newer apksigner versions that might
> have changed its output. For example, #fdroidserver is coded against apksigner
> from build-tools version vX.0.0. Someone does `pip install fdroidserver`. Then
> at some point, the user upgrades apksigner to version vY.0.0 which breaks the
> parsing before fdroidserver supports apksigner vY.0.0. That breakage needs to
> fail gracefully, and that is really hard to do. Much harder than just writing
> pure Python code to extract the certificates which is tested against the
> apksigner test suite. [...]

We agree that parsing `apksigner` CLI output would be unreliable.  Which is why
we recommended using the underlying `apksig` library which has a stable API and
even provided code to do exactly that [14].  This suggestion has been
consistently ignored with zero rationale given, other than clearly irrelevant
objections to parsing CLI output.

We vehemently disagree that the chosen approach of using custom Python code that
does not verify the signatures and relies on matching specific *behaviour* of
specific versions of `apksigner` (e.g. whether or not and how it verifies v3.1
signatures) to extract the correct certificates is reliable or secure.  This is
evidenced by the 6th PoC, which works because `fdroidserver` completely ignores
the APK Signature Scheme v3.1 block (and does not use any v1 signatures).

We find it concerning that F-Droid constantly chooses to move the goalposts and
continues to rely on a fundamentally broken approach for certificate pinning,
merely patching [15] known vulnerabilities without ever addressing the
underlying cause.

We reiterate once again that we recommended "using the official `apksig` library
(used by `apksigner`) to both verify APK signatures and return the first
signer's certificate to avoid these kind of implementation inconsistencies and
thus further vulnerabilities [...]".

Until a proper reliable implementation of certificate pinning using `apksig` is
provided (if ever), we recommend repositories using `AllowedAPKSigningKeys`
perform their own audit and assess whether the security they wish to provide
requires performing certificate pinning themselves or switching to e.g.
`apkrepotool`.

### Update (2025-01-21)

Quoting F-Droid's Technical Lead 8 months ago [16]:

> This highlights one hazard of using multiple implementations of verification:
> different implementations can open up exploit vectors.

And yet this is exactly what he did despite our repeated warnings against doing
so, which were ignored.

> There is a public API in the Java apksig library, but fdroidserver is written
> in Python.

Which is exactly what we recommended using, even providing an example
implementation of using `apksig` from Python one month earlier, which was
ignored.

> For repos made with collections of binary APKs, this more of a concern.
> AllowedAPKSigningKeys was designed with these kinds of repos in mind.  Our
> goal is to make it as simple as possible to safely run app repos.
> AllowedAPKSigningKeys is a feature along those lines.  So this page is about
> documenting what needs to happen to make AllowedAPKSigningKeys as reliable as
> possible.

Which contradicts recent statements that certificate pinning is in fact not
expected to provide any such security as it assumes a "trusted collection of
APKs".  And no further action was taken to actually make `AllowedAPKSigningKeys`
"as reliable as possible" despite the shortcomings identified.

## PoC

NB: you currently need the `signing` branch of `apksigtool` [9].

NB: the "fake" signer shown here is from the official F-Droid client (its APK
has a v1+v2+v3 signature), the one `apksigner` sees is randomly generated by
`make-key.sh`; the `app.apk` used for testing had `minSdk 26` and a v2 signature
only.  Using APKs with other signature scheme combinations is certainly
possible, but might require adjusting the PoC code accordingly.

```bash
$ ./make-key.sh             # generates a dummy key
$ python3 make-poc-v1.py    # uses app.apk (needs minSdk >= 24) as base, adds fake.apk .RSA
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
$ python3 make-poc-v2.py    # uses app.apk as base, adds signing block from fake.apk
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
$ apksigner verify -v --print-certs poc.apk | grep -E '^Verified using|Signer #1 certificate (DN|SHA-256)'
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme (APK Signature Scheme v4): false
Signer #1 certificate DN: CN=oops
Signer #1 certificate SHA-256 digest: 029df1354735e81eb97c9bbef2185c8ead3bc78ae874c03a6e96e1e1435ac519
```

```bash
$ mkdir fakesigner
$ cd fakesigner
$ fdroid init -d oops --repo-keyalias fakesigner
$ mkdir metadata
$ printf 'Name: MyApp\nAllowedAPKSigningKeys: 43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab\n' > metadata/some.app.id.yml
$ cp /path/to/poc.apk repo/
$ fdroid update
$ jq '.packages[].versions[].manifest.signer.sha256' < repo/index-v2.json
[
  "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab"
]
```

### Update (2024-04-14)

NB: version A, for `fdroidserver` using the first v1 certificate.

```bash
$ python3 make-poc-v3a.py   # uses app2.apk (needs targetSdk < 30) as base, adds fake.apk .RSA cert
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
```

### Update (2024-04-20)

NB: version B, for `fdroidserver` using the last v1 certificate.

```bash
$ python3 make-poc-v3b.py   # uses app2.apk (needs targetSdk < 30) as base, adds fake.apk .RSA cert
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
```

### Update (2024-12-30 #1)

NB: for convenience we generate our own key for the spoofed certificate as well;
for a real exploit we'd have a v1-signed APK to use here instead of signing one
ourselves.

```bash
$ ./make-key-v4.sh          # generates a dummy key
$ sha256sum cert-rsa-fake.der cert-rsa-orig.der
29c6fc6cfa20c2726721944a659a4293c5ac7e8090ab5faa8e26f64ba007bea4  cert-rsa-fake.der
1e8a45fa677f82755b63edee209fee92081ba822d4f425c3792a1980bfa3fca9  cert-rsa-orig.der
$ python3 make-poc-v4.py    # uses app3.apk (needs minSdk >= 24 & targetSdk < 30)
$ python3 fdroid.py         # verifies and has the wrong signer according to F-Droid
True
ERROR:root:"Signature is invalid", skipping:
  1e8a45fa677f82755b63edee209fee92081ba822d4f425c3792a1980bfa3fca9
  Common Name: Foo Bar
1e8a45fa677f82755b63edee209fee92081ba822d4f425c3792a1980bfa3fca9
$ apksigner verify -v --print-certs poc.apk | grep -E '^Verified using|Signer #1 certificate (DN|SHA-256)'
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v4 scheme (APK Signature Scheme v4): false
Signer #1 certificate DN: CN=Foo        Bar
Signer #1 certificate SHA-256 digest: 29c6fc6cfa20c2726721944a659a4293c5ac7e8090ab5faa8e26f64ba007bea4
```

### Update (2024-12-30 #2)

NB: version A uses newlines, version B NUL bytes (which makes it fail to
actually install on Android devices despite verifying with `apksigner`).

```bash
$ python3 make-poc-v5a.py   # uses app3.apk (needs targetSdk < 30) as base, adds fake.apk .RSA
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
```

```bash
$ python3 make-poc-v5b.py   # uses app3.apk (needs targetSdk < 30) as base, adds fake.apk .RSA
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
```

### Update (2025-01-19)

NB: see code comments for requirements.

```bash
$ python3 make-poc-v6.py    # uses app4.apk, adds signing block from fake.apk
$ python3 fdroid.py         # verifies and has fake.apk as signer according to F-Droid
True
43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab
```

## Patch

The `fdroidserver.patch` changes the order so it matches Android's v3 before v2
before v1, and monkey-patches `androguard` to see the first block instead of the
last one if there are duplicates.  This is still likely to be incomplete, but
prevents the known bypasses described here.

### Update (2024-04-14)

The `fdroidserver-multicert.patch` simply rejects any v1 signatures with
multiple certificates.  This may reject some valid APKs, but handling those
properly is nontrivial and there should be few APKs with multiple certificates
and no v2/v3 signatures in the wild (e.g. the IzzyOnDroid repository found none
in its catalog).  We recommend using the official `apksig` library (used by
`apksigner`) to both verify APK signatures and return the first signer's
certificate to avoid these kind of implementation inconsistencies and thus
further vulnerabilities like this one.

### Update (2024-12-30)

The `fdroidserver-regex.patch` fixes the regex to correctly handle newlines.

The `fdroidserver-null-v1.patch` (for `fdroidserver` before the changes we
recommended against) and `fdroidserver-null-v2.patch` (for current
`fdroidserver`) use `ZipInfo.orig_filename` to handle NUL bytes properly (and
avoid other potential issues).

## Scanner (2024-04-15, 2024-04-20)

The `scan.py` script can check APKs for *possible* signature issues: it will
flag APKs that are not clearly signed with a single unambiguous certificate,
which *could* result in the kind of accidental misidentification of the signer
-- despite successful verification by `apksigner` -- that we've demonstrated
here.  Unfortunately, such misidentification can easily happen as even the
official documentation of the various signature schemes does not completely
cover how Android/`apksigner` handles such cases.

NB: this will flag some valid APKs too, e.g. those with certificate chains,
those having used key rotation, or those with multiple signers; as the
IzzyOnDroid repository found none in its catalog, these cases luckily seem to be
relatively rare.

```bash
$ python3 scan.py poc*.apk
'poc1.apk': Mismatch between v1 and v2/v3 certificates
'poc2.apk': Duplicate block IDs
'poc3a.apk': Multiple certificates in signature block file
'poc3b.apk': Multiple certificates in signature block file
```

### Update (2024-12-30)

The `scan.py` script has been updated to check for APK Signature Scheme v3.1
blocks (which will likely give false positives needing manual inspection as
those are expected to differ with key rotation) as well as NUL/LF/CR in
filenames and to use `ZipInfo.orig_filename`.

NB: currently, neither `fdroidserver` nor `androguard` will see APK Signature
Scheme v3.1 blocks.

```bash
$ python3 scan.py poc[45]*.apk
'poc4.apk': Multiple certificates in signature block file
'poc5a.apk': NUL, LF, or CR in filename
'poc5b.apk': NUL, LF, or CR in filename
```

### Update (2025-01-19)

```bash
$ python3 scan.py poc6.apk
'poc6.apk': No v3 certs even though v3.1 cert is present
```

## References

* [1] https://salsa.debian.org/reproducible-builds/diffoscope/-/issues/246
* [2] https://gitlab.com/fdroid/fdroidserver/-/issues/1056
* [3] https://github.com/obfusk/sigblock-code-poc
* [4] https://lists.reproducible-builds.org/pipermail/rb-general/2023-January/002825.html
* [5] https://gitlab.com/fdroid/fdroidserver/-/issues/1128
* [6] https://source.android.com/docs/security/features/apksigning/v3
* [7] https://android.izzysoft.de/articles/named/iod-scan-apkchecks
* [8] https://www.kuketz-blog.de/android-apps-auf-dem-seziertisch-eine-vertiefte-betrachtung/
* [9] https://github.com/obfusk/apksigtool
* [10] https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1466
* [11] https://github.com/androguard/androguard/pull/1038
* [12] https://floss.social/@IzzyOnDroid/113765504171758318
* [13] https://social.librem.one/@eighthave/113820301078034374
* [14] https://gist.github.com/obfusk/cfab950649631c3ece723b9eb277304b
* [15] https://gitlab.com/fdroid/fdroidserver/-/issues/1251
* [16] https://gitlab.com/fdroid/wiki/-/wikis/Internal/AllowedAPKSigningKeys

## Links

* https://github.com/obfusk/apksigcopier
* https://github.com/obfusk/apkrepotool
