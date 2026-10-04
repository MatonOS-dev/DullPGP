#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VECTORS=$ROOT/tests/vectors
SCRATCH=${SCRATCH:-/tmp/gpgme-lite-tests}
BSSL_SRC=${BSSL_SRC:-/usr/include}
BSSL_LIBDIR=${BSSL_LIBDIR:-/usr/lib}
CC=${CC:-cc}
TEST_CFLAGS=${TEST_CFLAGS:-}
LDFLAGS=${LDFLAGS:-}

mkdir -p "$SCRATCH"
RUN=$(mktemp -d "$SCRATCH/run.XXXXXX")
# Word splitting is intentional for optional sanitizer/compiler flags.
# shellcheck disable=SC2086
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	$TEST_CFLAGS \
	"$ROOT/tests/verify-case.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread $LDFLAGS -o "$RUN/verify-case"
# shellcheck disable=SC2086
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	$TEST_CFLAGS \
	"$ROOT/tests/transfer.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread $LDFLAGS -o "$RUN/transfer"
# shellcheck disable=SC2086
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	$TEST_CFLAGS \
	"$ROOT/tests/parser-errors.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread $LDFLAGS -o "$RUN/parser-errors"

python3 - "$RUN" "$VECTORS" <<'PY'
from pathlib import Path
import sys
scratch = Path(sys.argv[1])
vectors = Path(sys.argv[2])
sig = (vectors / "summary.sig").read_bytes()
prefix = b"ostree.gpgsigs\0\0"
if sig.startswith(prefix):
    sig = sig[len(prefix):]
# OSTree's metadata may include trailing fields; verify its first packet only.
if not sig or sig[0] & 0x80 == 0:
    raise SystemExit("invalid signature packet in summary.sig")
if sig[0] & 0x40:
    first = sig[1]
    if first < 192:
        packet_len = 2 + first
    elif first < 224:
        packet_len = 3 + ((first - 192) << 8) + sig[2] + 192
    elif first == 255:
        packet_len = 6 + int.from_bytes(sig[2:6], "big")
    else:
        raise SystemExit("partial signature packet is unsupported")
else:
    length_type = sig[0] & 3
    if length_type == 0:
        packet_len = 2 + sig[1]
    elif length_type == 1:
        packet_len = 3 + int.from_bytes(sig[1:3], "big")
    elif length_type == 2:
        packet_len = 5 + int.from_bytes(sig[1:5], "big")
    else:
        raise SystemExit("indeterminate signature packet is unsupported")
sig = sig[:packet_len]
data = (vectors / "summary").read_bytes()
changed_sig = bytearray(sig)
changed_sig[-1] ^= 1
changed_data = bytearray(data)
changed_data[100] ^= 1
sha1 = bytearray(sig)
sha1[6] = 2
(scratch / "summary.gpgsig").write_bytes(sig)
(scratch / "signature-flipped.gpgsig").write_bytes(changed_sig)
(scratch / "summary-flipped").write_bytes(changed_data)
(scratch / "signature-sha1.gpgsig").write_bytes(sha1)
(scratch / "signature-truncated.gpgsig").write_bytes(sig[:24])
PY

"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$RUN/summary.gpgsig" "$VECTORS/summary" \
	"$RUN/home-good" 0 3 0
"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$RUN/signature-flipped.gpgsig" "$VECTORS/summary" \
	"$RUN/home-signature" 0 4 8
"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$RUN/summary.gpgsig" "$RUN/summary-flipped" \
	"$RUN/home-data" 0 4 8
"$RUN/verify-case" "$VECTORS/wrong-key.gpg" \
	"$RUN/summary.gpgsig" "$VECTORS/summary" \
	"$RUN/home-wrong-key" 0 128 9
"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$RUN/signature-sha1.gpgsig" "$VECTORS/summary" \
	"$RUN/home-sha1" 5 0 0
"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$RUN/signature-truncated.gpgsig" "$VECTORS/summary" \
	"$RUN/home-truncated" 89 0 0
"$RUN/verify-case" "$VECTORS/ed.gpg" "$VECTORS/ed.sig" \
	"$VECTORS/ed.data" "$RUN/home-ed25519" 0 3 0
"$RUN/transfer" "$VECTORS" "$RUN"
"$RUN/parser-errors"

printf 'all gpgme-lite verification cases passed\n'
