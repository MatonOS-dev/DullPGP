# gpgme-lite vectors and tests

`vectors/flathub.gpg`, `vectors/summary`, and `vectors/summary.sig` are the
files fetched from `https://dl.flathub.org/repo/`. The detached OpenPGP packet
passed by OSTree to GPGME is stored as `summary.gpgsig`; it is the first
complete packet in the serialized OSTree signature metadata file. The
original `summary.sig` is kept beside it so the test fixtures retain the
fetched repository artifact.

`ed.gpg`, `ed.sig`, and `ed.data` are a small legacy Ed25519 v4 verification
vector generated with GnuPG. `wrong-key.gpg` is an unrelated RSA public key
used to check key-missing handling.

`flatpark-key.gpg`, `flatpark-summary.idx`, and `flatpark-idx.sig` are the
FlatPark remote fixtures that exposed concatenated OSTree signatures. The
signature file is the serialized `ostree.gpgsigs` `aay` value; the test
extracts its two v4 RSA/SHA-512 packets at offsets 16 and 582, as Flatpak does
when concatenating the child byte arrays. It checks both signatures in one
GPGME verify operation, then flips the first signature and checks that the
second valid signature remains in the result list.

Build the library against the pinned BoringSSL checkout, then run:

```sh
BSSL_SRC=/path/to/boringssl BSSL_LIBDIR=/path/to/boringssl-build \
  SCRATCH=/tmp/gpgme-lite-tests ./tests/run.sh
```

The runner checks GOOD Flathub RSA-subkey and Ed25519 signatures, flipped
message/signature bits, an unrelated key, SHA-1 rejection, truncated packet
rejection, binary key export/import, keyring persistence across contexts, and
multiple concatenated FlatPark signatures including a bad-first/good-second
case.
