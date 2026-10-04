# gpgme-lite contract for OSTree 2025.7

SPDX-License-Identifier: LGPL-2.1-or-later

This spec is derived from the checked-out OSTree sources under
`/mnt/data/aosp/out/pc-logs/musl-static-116/build/ostree/`:

- `src/libostree/ostree-gpg-verifier.c`
- `src/libostree/ostree-gpg-verify-result.c`
- `src/libostree/ostree-repo.c` (remote key import around lines 2189–2412)
- `src/libotutil/ot-gpg-utils.c`

It describes the ABI surface OSTree calls or reads, and the semantics that
affect signature trust decisions. The implementation target is the
GPGME 2.0.1 / libgpg-error 1.61 ABI used by Alpine 3.24, with only the
OpenPGP verification and public-key import/export subset implemented.

## OSTree decision rules

`gpgme_op_verify()` must return success after processing a well-formed
detached signature set, even if a cryptographic signature is bad, its key is
unknown, expired, or revoked. Those are per-signature results. A malformed
or unsupported packet set may return a GPGME error instead. For every
processed signature, `gpgme_op_verify_result()` provides a linked list in
`gpgme_verify_result.signatures`.

OSTree counts a signature as valid when **any** of these are true:

1. `summary & GPGME_SIGSUM_VALID`;
2. `summary & GPGME_SIGSUM_GREEN`; or
3. `summary == 0 && status == GPG_ERR_NO_ERROR`.

Thus a cryptographically correct signature from an untrusted/uncertified key
is valid to OSTree. Do not set a valid bit on a digest mismatch, unknown key,
expired signature/key, or revoked signing key. Expired and revoked results
must preserve their error status and summary flags so the UI can describe
them. If no public key is found, OSTree expects a signature record with
`GPGME_SIGSUM_KEY_MISSING`; it does not treat missing key lookup in result
formatting as fatal. A bad signature must not be represented as
`status == GPG_ERR_NO_ERROR` with zero summary, because that combination is
explicitly accepted as valid.

Revocation formatting checks `GPGME_SIGSUM_KEY_REVOKED`, or the historical
GPGME combination `GPGME_SIGSUM_SYS_ERROR` plus
`gpgme_err_code(status) == GPG_ERR_CERT_REVOKED`. Implementations should set
the direct revoked bit and a revoked status consistently.

The signature result fields OSTree reads are `fpr`, `summary`, `status`,
`timestamp`, `exp_timestamp`, `pubkey_algo`, `hash_algo`, and `next`.
`fpr` is the actual signing key/subkey fingerprint. Timestamps are Unix
seconds; zero means absent/no expiry. Algorithm-name accessors return
`"RSA"` (or a recognized RSA variant), `"EdDSA"`, `"SHA256"`, `"SHA384"`,
`"SHA512"`, or `NULL` for unknown algorithms.

For key display and key matching, OSTree reads public linked records:

- `gpgme_key.subkeys`, iterated through each `gpgme_subkey.next`;
- each subkey's `fpr` and `expires`;
- `gpgme_key.uids`, iterated through each `gpgme_user_id.next`;
- first UID's `name` and `email`;
- first subkey is the primary key, and `gpgme_get_key()` returns a key for
  full fingerprint, key ID, or unambiguous suffix queries.

Failure to find a key for a signature is non-fatal when reporting result
attributes: OSTree returns empty/placeholder primary fingerprint, zero
expiry, and `[unknown name]` / `[unknown email]`. For requested key IDs in
key-list/import operations, lookup failure is fatal to that operation.

## Engine and homedir flow

`gpgme_new()` creates an OpenPGP context. `gpgme_ctx_get_engine_info()` must
return a stable OpenPGP engine record. OSTree passes its `protocol` back to
`gpgme_ctx_set_engine_info(ctx, protocol, NULL, homedir)`: a null executable
means keep the existing executable while changing only homedir. Contexts
using the same homedir must share the persistent public keyring. The shim
does not launch `gpg` or use an agent. `gpgme_get_engine_info()` is used
only by OSTree's optional GnuPG version diagnostic; its engine version may
be an explanatory fixed string.

OSTree constructs temporary homes, concatenates keyring files into
`pubring.gpg`, imports ASCII-armored key files, and removes those homes after
use. `gpgme_set_armor(ctx, 1)` is set around text-key imports and then
restored with `gpgme_get_armor()`. Armor therefore controls accepted input
or is an ignored compatibility setting; **OSTree's export call uses flags
zero and requires binary output**, so `gpgme_op_export_keys()` always emits
binary OpenPGP packets. No OSTree path needs armored export.

## Function and data ABI inventory

### Lifecycle and configuration

- `gpgme_check_version(const char *) -> const char *`: called at process
  initialization; return a non-null compatible version string.
- `gpgme_set_locale(gpgme_ctx_t, int category, const char *) -> gpgme_error_t`:
  called process-wide with null context for `LC_CTYPE`; accept as a no-op.
- `gpgme_new(gpgme_ctx_t *)`, `gpgme_release(gpgme_ctx_t)`: allocate/free
  context; release must tolerate null.
- `gpgme_ctx_get_engine_info(gpgme_ctx_t) -> gpgme_engine_info_t` and
  `gpgme_get_engine_info(gpgme_engine_info_t *) -> gpgme_error_t`: expose
  `protocol`, `file_name`, `version`, `req_version`, `home_dir`, and
  `next`; protocol is `GPGME_PROTOCOL_OpenPGP`.
- `gpgme_ctx_set_engine_info(ctx, protocol, file_name, home_dir)`: handles
  `file_name == NULL`, sets persistent keyring directory. For the null
  `homedir` default use an isolated per-user default such as
  `$HOME/.local/share/gpgme-lite`; never silently share a temporary keyring.
- `gpgme_set_armor(ctx, int)` / `gpgme_get_armor(ctx)`: store/read boolean.

### Data objects

- `gpgme_data_new()`, `gpgme_data_release()`: create/free a seekable buffer;
  release tolerates null.
- `gpgme_data_new_from_mem(out, buffer, size, copy)`: expose or copy memory
  and preserve the requested ownership behavior.
- `gpgme_data_new_from_fd(out, fd)`: reads from the descriptor without
  taking ownership of the caller's fd.
- `gpgme_data_new_from_cbs(out, cbs, handle)`: stores callbacks and handle;
  release invokes `cbs->release` once when supplied.
- `gpgme_data_seek(data, offset, whence) -> off_t` and
  `gpgme_data_read(data, buffer, size) -> ssize_t` and
  `gpgme_data_write(data, buffer, size) -> ssize_t`: required by OSTree's
  stream adapters and by remote key export/import rewind. Preserve ordinary
  `SEEK_SET/CUR/END`, EOF, and errno behavior.
- `struct gpgme_data_cbs` fields read, write, seek, release have the real
  GPGME ABI order and callback types. OSTree supplies read/seek/release for
  input and write/seek/release for output.

### Import, export and key listing

- `gpgme_op_import(ctx, data)` and `gpgme_op_import_result(ctx)`: parse
  binary or ASCII-armored public keys; merge/persist them in the context's
  homedir; preserve primary/subkey/UID metadata and revocations. A success
  return means the import operation ran; each key outcome appears in the
  import result list.
- `gpgme_import_result.imports` (linked via `gpgme_import_status.next`),
  `gpgme_import_status.fpr`, and `gpgme_import_status.result` are read by
  OSTree. `gpgme_import_result.imported` sets `out_imported`. Every requested
  key should have an import-status node; result must be
  `GPG_ERR_NO_ERROR` for success. Re-importing an existing key may report
  unchanged but remains successful.
- `gpgme_op_keylist_start(ctx, pattern, secret_only)` and
  `gpgme_op_keylist_next(ctx, gpgme_key_t *)`: OSTree calls with null
  pattern and false; iterate imported public keys then return `GPG_ERR_EOF`.
- `gpgme_get_key(ctx, pattern, out_key, secret)`: OSTree uses false for
  public lookups, matching full fingerprints and 8/16-hex key IDs; return
  `GPG_ERR_EOF` when absent and `GPG_ERR_AMBIGUOUS_NAME` if multiple keys
  match. `secret` is true only in signing code, which is unsupported by this
  library.
- `gpgme_key_unref()` and `gpgme_key_t`: reference-counted or otherwise
  safely owned key object; unref tolerates null (OSTree relies on it for
  null-terminated arrays).
- `gpgme_op_export_keys(ctx, keys, flags, out_data)`: serialize selected
  public keys as binary packets into `out_data`, allowing a subsequent
  `gpgme_data_seek(..., 0, SEEK_SET)` and import into another context. It
  must include enough original public packet metadata for equivalent
  fingerprints, UIDs, subkeys and binding signatures.
- OSTree checks `gpgme_err_code(err) == GPG_ERR_EOF` after list completion,
  and checks each imported key's result. It does not inspect other import
  result counters.

### Detached verification and result lifetime

- `gpgme_op_verify(ctx, sig_data, signed_data, plaintext_data)`: OSTree uses
  a detached OpenPGP signature and signed bytes; plaintext output is null.
  Return success with a result record for ordinary invalid signatures.
- `gpgme_op_verify_result(ctx) -> gpgme_verify_result_t`: context-owned
  result containing `signatures`.
- `gpgme_result_ref()` / `gpgme_result_unref()`: reference/unreference the
  verify result; OSTree holds one reference until result-object finalization.
- `struct gpgme_signature` fields consumed are `next`, `summary`, `fpr`,
  `status`, `timestamp`, `exp_timestamp`, `pubkey_algo`, `hash_algo`.
- Summary constants consumed: `GPGME_SIGSUM_VALID`, `GREEN`, `SYS_ERROR`,
  `SIG_EXPIRED`, `KEY_EXPIRED`, `KEY_REVOKED`, `KEY_MISSING`. ABI values
  must match GPGME 2.0.1.
- `gpgme_pubkey_algo_name()` and `gpgme_hash_algo_name()` provide display
  names used in result variants.

### Error API and exact checked codes

- `gpgme_err_code(error)` extracts the libgpg-error code from the encoded
  `gpgme_error_t`; source bits may be zero or the shim's source.
- `gpgme_strerror(error)`, `gpgme_strerror_r(error, buf, size)`,
  `gpgme_strsource(error)` provide non-null stable human-readable text.
- `gpg_strerror_r(error, buf, size)` is called directly by
  `ot_gpgme_throw()` (from libgpg-error's public header), alongside
  `gpgme_strsource()`; it must also be exported by the shim so the static
  OSTree link has no libgpg-error dependency.
- OSTree explicitly checks `GPG_ERR_NO_ERROR`, `GPG_ERR_EOF`,
  `GPG_ERR_ENOMEM`, `GPG_ERR_INV_VALUE`, `GPG_ERR_AMBIGUOUS_NAME`, and
  `GPG_ERR_CERT_REVOKED`. `GPG_ERR_NOT_SUPPORTED` is returned for the
  unsupported signing calls. Other parser/crypto failures must use a
  non-success code and must never alias success after `gpgme_err_code()`.
- `GPG_ERR_EOF` is normal only at key-list completion. `GPG_ERR_ENOMEM`
  causes OSTree to abort, consistent with allocation failure. `INV_VALUE`
  maps to `G_IO_ERROR_INVALID_ARGUMENT`; all other errors map to generic
  I/O failure through `ot_gpgme_throw()`.

### Explicitly unsupported OSTree-adjacent APIs

- `gpgme_op_sign()` and `gpgme_signers_add()` return
  `GPG_ERR_NOT_SUPPORTED`; they are used only for repository commit signing,
  outside the required verification/import task.
- Secret-key lookup and signing are unsupported.

## OpenPGP and crypto subset

Accept bounded v4 public primary keys, user IDs, public subkeys, key
expiration and revocation packets, and detached v4 signatures. Verify RSA
2048–4096 bit keys and legacy EdDSA Ed25519 (algorithm 22) with SHA-256,
SHA-384, or SHA-512. Reject SHA-1/MD5 signatures, unsupported algorithms,
v6 keys/signatures, malformed/truncated packets, invalid MPI encodings,
unknown critical signature subpackets, and keys without valid self or
subkey-binding signatures. Subkeys are signing candidates only when their
valid binding signature includes signing-capable key flags. Apply signature
and key creation/expiry times at verification time; process key and subkey
revocations (0x20/0x28). Never infer trust from UID text or key ID.

Packet parsing is strict, bounded, iterative, and uses BoringSSL CBS for all
input parsing. Build signature hash suffixes, export packets, and packet
headers with CBB. Armor uses BoringSSL base64 helpers. Hashes, RSA,
Ed25519, MPI conversion and constant-time comparison use BoringSSL APIs.
Fingerprints are v4 SHA-1 only as mandated by OpenPGP fingerprinting; SHA-1
is never accepted for a signature digest. BoringSSL is pinned to
`0cd1f6a94b670e6b61af95a06e71e690ae8e3262`; its license and source archive
hash are recorded separately in the implementation lock file.

## Header provenance and ABI

Public declarations may be adapted from GPGME 2.0.1 and libgpg-error 1.61
headers under LGPL-2.1-or-later. Preserve upstream copyright and SPDX
notices on reused declaration blocks and add a provenance note identifying
the original header/version. All implementation files use SPDX
`LGPL-2.1-or-later`. The exported ABI must use real GPGME enum values,
field order, field types, and function signatures; compile-time ABI checks
should compare size/offsets against the pinned/upstream headers where
available.
