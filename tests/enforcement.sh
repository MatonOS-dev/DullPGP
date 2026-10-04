#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${OSTREE_LITE_BIN:-/mnt/data/aosp/out/pc-logs/musl-static-116/output-gpgme-lite/matonos-flatpak}
SCRATCH=${SCRATCH:-/mnt/data/aosp/out/pc-logs/gpgme-lite}
FLATHUB_URL=${FLATHUB_URL:-https://dl.flathub.org/repo/}
FLATHUB_REF=${FLATHUB_REF:-app/org.gnome.Calculator/x86_64/stable}

if [ ! -x "$BIN" ]; then
	printf 'SKIP: static MatonOS Flatpak binary not found: %s\n' "$BIN"
	exit 0
fi

mkdir -p "$SCRATCH"
RUN=$(mktemp -d "$SCRATCH/enforcement.XXXXXX")
mkdir "$RUN/bin"
OSTREE=$RUN/bin/ostree
ln -s "$BIN" "$OSTREE"
ostree() { "$OSTREE" "$@"; }

SEED=$RUN/seed
BAD_STAGE=$RUN/tampered-stage
GOOD_STAGE=$RUN/clean-stage
BAD_TARGET=$RUN/tampered-target
GOOD_TARGET=$RUN/clean-target
KEY=$ROOT/tests/vectors/flathub.gpg

if [ -n "${FLATHUB_SOURCE_REPO:-}" ]; then
	cp -a "$FLATHUB_SOURCE_REPO" "$SEED"
else
	ostree init --repo="$SEED" --mode=archive-z2
	ostree remote add --repo="$SEED" --no-gpg-verify flathub "$FLATHUB_URL"
	ostree pull --repo="$SEED" --depth=0 flathub "$FLATHUB_REF"
fi
COMMIT=$(ostree rev-parse --repo="$SEED" "$FLATHUB_REF")
COMMITMETA=$SEED/objects/${COMMIT%${COMMIT#??}}/${COMMIT#??}.commitmeta
if [ ! -f "$COMMITMETA" ]; then
	printf 'ERROR: pulled Flathub commit has no detached commitmeta: %s\n' "$COMMIT" >&2
	exit 1
fi

cp -a "$SEED" "$BAD_STAGE"
cp -a "$SEED" "$GOOD_STAGE"
ostree refs --repo="$BAD_STAGE" --create="$FLATHUB_REF" "$COMMIT"
ostree refs --repo="$GOOD_STAGE" --create="$FLATHUB_REF" "$COMMIT"
BAD_COMMITMETA=$BAD_STAGE/objects/${COMMIT%${COMMIT#??}}/${COMMIT#??}.commitmeta
python3 - "$BAD_COMMITMETA" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
marker = data.find(b"ostree.gpgsigs")
if marker < 0:
    raise SystemExit("commitmeta does not contain ostree.gpgsigs")

def packet_end(data, start):
    ctb = data[start]
    if not ctb & 0x80:
        return None
    if ctb & 0x40:
        if ctb & 0x3f != 2 or start + 2 > len(data):
            return None
        first = data[start + 1]
        if first < 192:
            header, size = 2, first
        elif first < 224 and start + 3 <= len(data):
            header = 3
            size = ((first - 192) << 8) + data[start + 2] + 192
        elif first == 255 and start + 6 <= len(data):
            header = 6
            size = int.from_bytes(data[start + 2:start + 6], "big")
        else:
            return None
    else:
        if (ctb >> 2) & 0x0f != 2:
            return None
        length_type = ctb & 3
        if length_type == 0 and start + 2 <= len(data):
            header, size = 2, data[start + 1]
        elif length_type == 1 and start + 3 <= len(data):
            header, size = 3, int.from_bytes(data[start + 1:start + 3], "big")
        elif length_type == 2 and start + 5 <= len(data):
            header, size = 5, int.from_bytes(data[start + 1:start + 5], "big")
        else:
            return None
    body = start + header
    end = body + size
    if end <= len(data) and size > 8 and data[body] in (4, 5, 6):
        return end
    return None

for offset in range(marker + len(b"ostree.gpgsigs"), len(data)):
    end = packet_end(data, offset)
    if end is not None:
        data[end - 1] ^= 1
        path.write_bytes(data)
        print(f"tampered one byte in OpenPGP signature packet at offset {end - 1}")
        break
else:
    raise SystemExit("could not locate an OpenPGP signature packet in commitmeta")
PY

ostree init --repo="$BAD_TARGET" --mode=archive-z2
ostree remote add --repo="$BAD_TARGET" --gpg-import="$KEY" \
	--set=gpg-verify=true flathub "$FLATHUB_URL"
if ostree pull-local --repo="$BAD_TARGET" --gpg-verify --remote=flathub \
	"$BAD_STAGE" "$FLATHUB_REF"; then
	printf 'ERROR: pull-local accepted a tampered Flathub commit signature\n' >&2
	exit 1
fi
if ostree rev-parse --repo="$BAD_TARGET" "$FLATHUB_REF" >/dev/null 2>&1; then
	printf 'ERROR: tampered commit has a target ref after failed verification\n' >&2
	exit 1
fi
python3 - "$BAD_TARGET" "$COMMIT" <<'PY'
from pathlib import Path
import sys
repo, commit = Path(sys.argv[1]), sys.argv[2]
obj = repo / "objects" / commit[:2] / (commit[2:] + ".commit")
if obj.exists():
    raise SystemExit(f"tampered commit object unexpectedly exists: {obj}")
PY

ostree init --repo="$GOOD_TARGET" --mode=archive-z2
ostree remote add --repo="$GOOD_TARGET" --gpg-import="$KEY" \
	--set=gpg-verify=true flathub "$FLATHUB_URL"
ostree pull-local --repo="$GOOD_TARGET" --gpg-verify --remote=flathub \
	"$GOOD_STAGE" "$FLATHUB_REF"
GOOD_COMMIT=$(ostree rev-parse --repo="$GOOD_TARGET" "$FLATHUB_REF")
if [ "$GOOD_COMMIT" != "$COMMIT" ]; then
	printf 'ERROR: untampered pull resolved to %s, expected %s\n' "$GOOD_COMMIT" "$COMMIT" >&2
	exit 1
fi
printf 'enforcement passed for Flathub ref %s at %s\n' "$FLATHUB_REF" "$COMMIT"
