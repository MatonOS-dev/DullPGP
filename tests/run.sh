#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VECTORS=$ROOT/tests/vectors
SCRATCH=${SCRATCH:-/tmp/gpgme-lite-tests}
BSSL_SRC=${BSSL_SRC:-/usr/include}
BSSL_LIBDIR=${BSSL_LIBDIR:-/usr/lib}
CC=${CC:-cc}

mkdir -p "$SCRATCH"
RUN=$(mktemp -d "$SCRATCH/run.XXXXXX")
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	"$ROOT/tests/verify-case.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread -o "$RUN/verify-case"
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	"$ROOT/tests/transfer.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread -o "$RUN/transfer"
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	"$ROOT/tests/parser-errors.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread -o "$RUN/parser-errors"

python3 - "$RUN" "$VECTORS" <<'PY'
from pathlib import Path
import sys
scratch = Path(sys.argv[1])
vectors = Path(sys.argv[2])
sig = (vectors / "summary.gpgsig").read_bytes()
data = (vectors / "summary").read_bytes()
changed_sig = bytearray(sig)
changed_sig[-1] ^= 1
changed_data = bytearray(data)
changed_data[100] ^= 1
sha1 = bytearray(sig)
sha1[6] = 2
(scratch / "signature-flipped.gpgsig").write_bytes(changed_sig)
(scratch / "summary-flipped").write_bytes(changed_data)
(scratch / "signature-sha1.gpgsig").write_bytes(sha1)
(scratch / "signature-truncated.gpgsig").write_bytes(sig[:24])
PY

"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$VECTORS/summary.gpgsig" "$VECTORS/summary" \
	"$RUN/home-good" 0 3 0
"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$RUN/signature-flipped.gpgsig" "$VECTORS/summary" \
	"$RUN/home-signature" 0 4 8
"$RUN/verify-case" "$VECTORS/flathub.gpg" \
	"$VECTORS/summary.gpgsig" "$RUN/summary-flipped" \
	"$RUN/home-data" 0 4 8
"$RUN/verify-case" "$VECTORS/wrong-key.gpg" \
	"$VECTORS/summary.gpgsig" "$VECTORS/summary" \
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
