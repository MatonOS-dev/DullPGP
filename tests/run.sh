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
# shellcheck disable=SC2086
"$CC" -I"$ROOT/include" -I"$BSSL_SRC/src/include" \
	$TEST_CFLAGS \
	"$ROOT/tests/multi-verify.c" "$ROOT/libgpgme-lite.a" \
	"$BSSL_LIBDIR/libcrypto.a" -pthread $LDFLAGS -o "$RUN/multi-verify"

python3 - "$RUN" "$VECTORS" <<'PY'
from pathlib import Path
import sys
scratch = Path(sys.argv[1])
vectors = Path(sys.argv[2])
# summary.gpgsig is the raw first OpenPGP packet from OSTree's serialized
# summary.sig metadata. Check it against the source artifact before use.
serialized_sig = (vectors / "summary.sig").read_bytes()
sig = (vectors / "summary.gpgsig").read_bytes()
prefix = b"ostree.gpgsigs\0\0"
if not serialized_sig.startswith(prefix):
    raise SystemExit("summary.sig lacks OSTree gpgsigs metadata prefix")
serialized_sig = serialized_sig[len(prefix):]
if not sig or sig[0] & 0x80 == 0 or not serialized_sig.startswith(sig):
    raise SystemExit("summary.gpgsig is not the raw packet from summary.sig")
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

python3 - "$VECTORS/flatpark-idx.sig" "$RUN/flatpark-signatures.pgp" \
	"$RUN/flatpark-first-bad.pgp" <<'PY'
from pathlib import Path
import sys

serialized = Path(sys.argv[1]).read_bytes()
prefix = b"ostree.gpgsigs\0\0"
if not serialized.startswith(prefix):
    raise SystemExit("FlatPark fixture lacks OSTree gpgsigs metadata prefix")

# Flatpak concatenates the two ay children from the OSTree aay value before
# handing their OpenPGP packets to OSTree's verifier. Decode the definite-size
# old-format signature packets and leave the GVariant offset table out.
stream = serialized[len(prefix):]
offset = 0
packets = []
packet_offsets = []
while offset < len(stream) and stream[offset] & 0x80:
    start = offset
    ctb = stream[offset]
    if ctb & 0x40 or (ctb >> 2) & 0x0f != 2:
        raise SystemExit("unexpected packet in FlatPark signature fixture")
    length_type = ctb & 3
    if length_type == 0:
        header_size, length = 2, stream[offset + 1]
    elif length_type == 1:
        header_size = 3
        length = int.from_bytes(stream[offset + 1:offset + 3], "big")
    elif length_type == 2:
        header_size = 5
        length = int.from_bytes(stream[offset + 1:offset + 5], "big")
    else:
        raise SystemExit("indeterminate signature packet length")
    end = start + header_size + length
    if end > len(stream):
        raise SystemExit("truncated signature packet in fixture")
    packet_offsets.append(len(prefix) + start)
    packets.append(stream[start:end])
    offset = end
if packet_offsets != [16, 582] or len(packets) != 2:
    raise SystemExit(f"unexpected signature packet offsets: {packet_offsets}")

combined = b"".join(packets)
Path(sys.argv[2]).write_bytes(combined)
first_bad = bytearray(combined)
first_bad[len(packets[0]) - 1] ^= 1
Path(sys.argv[3]).write_bytes(first_bad)
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
"$RUN/multi-verify" "$VECTORS/flatpark-key.gpg" \
	"$RUN/flatpark-signatures.pgp" "$VECTORS/flatpark-summary.idx" \
	"$RUN/home-flatpark" 2
"$RUN/multi-verify" "$VECTORS/flatpark-key.gpg" \
	"$RUN/flatpark-first-bad.pgp" "$VECTORS/flatpark-summary.idx" \
	"$RUN/home-flatpark-first-bad" 1

printf 'all DullPGP verification cases passed\n'
