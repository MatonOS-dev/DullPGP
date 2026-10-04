#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SCRATCH=${SCRATCH:-/mnt/data/aosp/out/pc-logs/gpgme-lite}
BSSL_SRC=${BSSL_SRC:-$SCRATCH/boringssl-src}
BSSL_LIBDIR=${BSSL_LIBDIR:-$SCRATCH/build-static/boringssl-unprefixed}
CC=${CC:-cc}
LDFLAGS=${LDFLAGS:-}
RUN=$(mktemp -d "$SCRATCH/security.XXXXXX")
GNUPGHOME=$RUN/gnupg
KEY_HOME=$GNUPGHOME
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
trap 'gpgconf --homedir "$KEY_HOME" --kill all >/dev/null 2>&1 || true; gpgconf --homedir "$RUN/primary-revoke-home" --kill all >/dev/null 2>&1 || true; rm -rf "$RUN"' EXIT HUP INT TERM

# Word splitting is intentional for optional sanitizer/linker flags.
# shellcheck disable=SC2086
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	"$ROOT/tests/verify-case.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread $LDFLAGS -o "$RUN/verify-case"

gpg --batch --pinentry-mode loopback --passphrase '' \
	--quick-generate-key 'gpgme-lite regression <regression@example.invalid>' \
	ed25519 sign 0 >/dev/null 2>&1
FPR=$(gpg --batch --with-colons --list-secret-keys |
	awk -F: '$1 == "fpr" { print $10; exit }')
gpg --batch --pinentry-mode loopback --passphrase '' \
	--quick-add-key "$FPR" rsa2048 sign 0 >/dev/null 2>&1
SUBFPR=$(gpg --batch --with-colons --list-secret-keys |
	awk -F: '$1 == "fpr" && ++n == 2 { print $10; exit }')
gpg --batch --export "$FPR" > "$RUN/key.gpg"
printf 'gpgme-lite generated fixture\n' > "$RUN/data"

# The Ed25519 primary creates the binding and embedded 0x19 proof for its RSA
# signing subkey. Verification exercises primary/subkey material separation.
gpg --batch --pinentry-mode loopback --passphrase '' --local-user "$FPR!" \
	--detach-sign --output "$RUN/ed-primary.sig" "$RUN/data"
"$RUN/verify-case" "$RUN/key.gpg" "$RUN/ed-primary.sig" "$RUN/data" \
	"$RUN/home-ed-primary" 0 3 0
printf 'test-primary-ed25519-subkey-material: PASS\n'

# Keep signing until the RSA MPI omits a leading zero octet, then verify it.
n=0
while :; do
	n=$((n + 1))
	printf 'gpgme-lite generated RSA fixture %s\n' "$n" > "$RUN/data-rsa"
	gpg --batch --pinentry-mode loopback --passphrase '' \
		--yes --local-user "$SUBFPR!" --detach-sign --output "$RUN/rsa.sig" "$RUN/data-rsa"
	if python3 - "$RUN/rsa.sig" <<'PY'
import sys
p = open(sys.argv[1], 'rb').read()
if not p or p[0] & 0x80 == 0:
    raise SystemExit(1)
if p[0] & 0x40:
    if p[0] & 0x3f != 2:
        raise SystemExit(1)
    i = 1
    first = p[i]
    i += 1
    if first < 192:
        size = first
    elif first < 224:
        size, i = ((first - 192) << 8) + p[i] + 192, i + 1
    elif first == 255:
        size = int.from_bytes(p[i:i+4], 'big')
        i += 4
    else:
        raise SystemExit(1)
else:
    if (p[0] >> 2) & 0x0f != 2:
        raise SystemExit(1)
    kind = p[0] & 3
    i = 1
    if kind == 0:
        size = p[i]
        i += 1
    elif kind == 1:
        size = int.from_bytes(p[i:i+2], 'big')
        i += 2
    elif kind == 2:
        size = int.from_bytes(p[i:i+4], 'big')
        i += 4
    else:
        raise SystemExit(1)
body = p[i:i+size]
hashed_len = int.from_bytes(body[4:6], 'big')
unhashed_at = 6 + hashed_len
unhashed_len = int.from_bytes(body[unhashed_at:unhashed_at+2], 'big')
mpi_at = unhashed_at + 2 + unhashed_len + 2
bits = int.from_bytes(body[mpi_at:mpi_at+2], 'big')
octets = (bits + 7) // 8
raise SystemExit(0 if octets < 256 else 1)
PY
	then
		break
	fi
	[ "$n" -lt 2000 ] || { echo 'failed to generate short RSA MPI' >&2; exit 1; }
done
	"$RUN/verify-case" "$RUN/key.gpg" "$RUN/rsa.sig" "$RUN/data-rsa" \
	"$RUN/home-rsa-short-mpi" 0 3 0
printf 'test-rsa-leading-zero-mpi-padding: PASS (%s attempts)\n' "$n"

python3 "$ROOT/tests/mutate-openpgp.py" strip-crosscert \
	"$RUN/key.gpg" "$RUN/key-no-crosscert.gpg"
"$RUN/verify-case" "$RUN/key-no-crosscert.gpg" "$RUN/rsa.sig" \
	"$RUN/data-rsa" "$RUN/home-no-crosscert" 0 128 9
printf 'test-signing-subkey-requires-embedded-0x19: PASS\n'

python3 "$ROOT/tests/mutate-openpgp.py" append-signature-tail \
	"$RUN/ed-primary.sig" "$RUN/ed-primary-trailing.sig"
"$RUN/verify-case" "$RUN/key.gpg" "$RUN/ed-primary-trailing.sig" \
	"$RUN/data" "$RUN/home-ed-trailing" 0 4 8
printf 'test-ed25519-rejects-trailing-mpi-bytes: PASS\n'

python3 "$ROOT/tests/mutate-openpgp.py" strip-hashed-creation \
	"$RUN/ed-primary.sig" "$RUN/no-created-time.sig"
"$RUN/verify-case" "$RUN/key.gpg" "$RUN/no-created-time.sig" \
	"$RUN/data" "$RUN/home-no-created-time" 0 4 8
printf 'test-signature-requires-hashed-creation-time: PASS\n'

python3 "$ROOT/tests/mutate-openpgp.py" zero-created \
	"$RUN/ed-primary.sig" "$RUN/created-before-key.sig"
"$RUN/verify-case" "$RUN/key.gpg" "$RUN/created-before-key.sig" \
	"$RUN/data" "$RUN/home-before-key" 0 4 8
printf 'test-signature-created-before-key-rejected: PASS\n'

python3 "$ROOT/tests/mutate-openpgp.py" wrong-algorithm \
	"$RUN/ed-primary.sig" "$RUN/wrong-algorithm.sig"
"$RUN/verify-case" "$RUN/key.gpg" "$RUN/wrong-algorithm.sig" \
	"$RUN/data" "$RUN/home-wrong-algorithm" 0 4 8
printf 'test-signature-public-key-algorithm-match: PASS\n'

# Revoke the signing subkey after producing its signature. The revocation is a
# primary-made 0x28 signature that follows an already accepted 0x18 binding.
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' |
	gpg --batch --pinentry-mode loopback --passphrase '' --command-fd 0 \
		--edit-key "$FPR" >/dev/null 2>&1
gpg --batch --export-options export-local-sigs --export "$FPR" > \
	"$RUN/key-revoked-subkey-original.gpg"
python3 "$ROOT/tests/mutate-openpgp.py" move-revocation-after-binding \
	"$RUN/key-revoked-subkey-original.gpg" "$RUN/key-revoked-subkey.gpg"
"$RUN/verify-case" "$RUN/key-revoked-subkey.gpg" "$RUN/rsa.sig" \
	"$RUN/data-rsa" "$RUN/home-revoked-subkey" 0 16 94
printf 'test-late-signing-subkey-revocation: PASS\n'

# A revoked primary invalidates signatures made by an otherwise valid subkey.
GNUPGHOME=$RUN/primary-revoke-home
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' \
	--quick-generate-key 'primary revoke <primary@example.invalid>' \
	ed25519 sign 0 >/dev/null 2>&1
PRIMARY_FPR=$(gpg --batch --with-colons --list-secret-keys |
	awk -F: '$1 == "fpr" { print $10; exit }')
gpg --batch --pinentry-mode loopback --passphrase '' \
	--quick-add-key "$PRIMARY_FPR" rsa2048 sign 0 >/dev/null 2>&1
PRIMARY_SUBFPR=$(gpg --batch --with-colons --list-secret-keys |
	awk -F: '$1 == "fpr" && ++n == 2 { print $10; exit }')
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
	--local-user "$PRIMARY_SUBFPR!" --detach-sign \
	--output "$RUN/primary-revoke.sig" "$RUN/data"
printf 'revkey\ny\n0\n\ny\nsave\n' |
	gpg --batch --pinentry-mode loopback --passphrase '' --command-fd 0 \
		--edit-key "$PRIMARY_FPR" >/dev/null 2>&1
gpg --batch --export-options export-local-sigs --export "$PRIMARY_FPR" > "$RUN/key-revoked-primary.gpg"
"$RUN/verify-case" "$RUN/key-revoked-primary.gpg" \
	"$RUN/primary-revoke.sig" "$RUN/data" \
	"$RUN/home-revoked-primary" 0 16 94
printf 'test-subkey-signature-rejects-revoked-primary: PASS\n'
