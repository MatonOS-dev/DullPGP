#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VECTORS=$ROOT/tests/vectors
SCRATCH=${SCRATCH:-/mnt/data/aosp/out/pc-logs/gpgme-lite}
BSSL_SRC=${BSSL_SRC:-$SCRATCH/boringssl-src}
BSSL_LIBDIR=${BSSL_LIBDIR:-$SCRATCH/boringssl-build}
CLANG=${CLANG:-/mnt/data/aosp/prebuilts/clang/host/linux-x86/clang-r596125/bin/clang}
LLVM_BIN=${LLVM_BIN:-$(dirname "$CLANG")}
RUNS=${RUNS:-$SCRATCH/fuzz}
TIME_LIMIT=${TIME_LIMIT:-610}
mkdir -p "$RUNS/corpus/import" "$RUNS/corpus/verify" "$RUNS/corpus/armor" "$RUNS/artifacts"
export HOME="$RUNS/home"
export GPGME_LITE_FUZZ_HOME_ROOT="$RUNS/home"
mkdir -p "$HOME/.local/share/gpgme-lite"
cp "$VECTORS"/flathub.gpg "$VECTORS"/ed.gpg "$VECTORS"/wrong-key.gpg "$RUNS/corpus/import/"
cp "$VECTORS"/summary.gpgsig "$VECTORS"/ed.sig "$VECTORS"/summary.sig "$RUNS/corpus/verify/"
cp "$VECTORS"/flathub.gpg "$VECTORS"/summary.sig "$RUNS/corpus/armor/"
{
	printf '%s\n\n' '-----BEGIN PGP PUBLIC KEY BLOCK-----'
	base64 "$VECTORS/flathub.gpg"
	printf '%s\n' '-----END PGP PUBLIC KEY BLOCK-----'
} > "$RUNS/corpus/armor/flathub.gpg.asc"
{
	printf '%s\n\n' '-----BEGIN PGP SIGNATURE-----'
	base64 "$VECTORS/summary.gpgsig"
	printf '%s\n' '-----END PGP SIGNATURE-----'
} > "$RUNS/corpus/armor/summary.gpgsig.asc"
for f in "$RUNS/corpus/import"/*; do
	case "$f" in *.gpg) ;; *) continue ;; esac
	armor="$RUNS/corpus/import/$(basename "$f").asc"
	base64 "$f" | awk 'BEGIN { print "-----BEGIN PGP PUBLIC KEY BLOCK-----"; print "" } { print } END { print "-----END PGP PUBLIC KEY BLOCK-----" }' > "$armor"
done
COMMON="-std=c11 -D_GNU_SOURCE -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -fprofile-instr-generate -fcoverage-mapping -I$ROOT/include -I$BSSL_SRC/src/include"
SOURCES="$ROOT/api.c $ROOT/packet.c $ROOT/key.c $ROOT/keyring.c $ROOT/verify.c"
# Shell word splitting is intentional for compiler flag/source lists.
# shellcheck disable=SC2086
"$CLANG" $COMMON -I"$ROOT" $SOURCES "$ROOT/tests/fuzz-import.c" "$BSSL_LIBDIR/libcrypto.a" -pthread -o "$RUNS/fuzz-import"
# shellcheck disable=SC2086
"$CLANG" $COMMON -I"$ROOT" -DFUZZ_VECTOR_DIR='"'"$VECTORS"'"' $SOURCES "$ROOT/tests/fuzz-verify.c" "$BSSL_LIBDIR/libcrypto.a" -pthread -o "$RUNS/fuzz-verify"
# shellcheck disable=SC2086
"$CLANG" $COMMON -I"$ROOT" $SOURCES "$ROOT/tests/fuzz-armor.c" "$BSSL_LIBDIR/libcrypto.a" -pthread -o "$RUNS/fuzz-armor"
for target in import verify armor; do
	case "$target" in
		import) limit=8388608 ;;
		verify) limit=1048576 ;;
		armor) limit=8388608 ;;
	esac
	LLVM_PROFILE_FILE="$RUNS/$target-%p.profraw" \
		"$RUNS/fuzz-$target" -max_total_time="$TIME_LIMIT" -max_len="$limit" \
		-print_final_stats=1 -print_coverage=1 \
		-artifact_prefix="$RUNS/artifacts/$target-" \
		"$RUNS/corpus/$target" 2>&1 | tee "$RUNS/$target.log"
	"$LLVM_BIN/llvm-profdata" merge -sparse "$RUNS"/"$target"-*.profraw -o "$RUNS/$target.profdata"
	"$LLVM_BIN/llvm-cov" report "$RUNS/fuzz-$target" -instr-profile="$RUNS/$target.profdata" > "$RUNS/$target-coverage.txt"
done
