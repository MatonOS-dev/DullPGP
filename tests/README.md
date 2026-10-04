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

Build the library against the pinned BoringSSL checkout, then run:

```sh
BSSL_SRC=/path/to/boringssl BSSL_LIBDIR=/path/to/boringssl-build \
  SCRATCH=/tmp/gpgme-lite-tests ./tests/run.sh
```

The runner checks GOOD Flathub RSA-subkey and Ed25519 signatures, flipped
message/signature bits, an unrelated key, SHA-1 rejection, truncated packet
rejection, binary key export/import, and keyring persistence across contexts.
