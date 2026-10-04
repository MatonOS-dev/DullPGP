# DullPGP

Minimal gpgme-compatible OpenPGP verification on BoringSSL.

DullPGP does one dull job: import OpenPGP public keys and verify detached
signatures, behind the subset of the gpgme API that OSTree and Flatpak use.
It installs as `libgpgme` (`gpgme.pc`), so they link it unchanged — no `gpg`
process, no GnuPG libraries. All crypto and byte parsing comes from
BoringSSL; DullPGP is packet layout plus API glue. Independent project, not
affiliated with Google or the BoringSSL project.

Scope: v4 keys and detached signatures (RFC 9580 subset), RSA 2048–4096 and
Ed25519, SHA-256/384/512. Signing, encryption and v6 are not supported.

See `SPEC.md` for the exact gpgme surface and `PROVENANCE.md` for copied
headers. Licence: LGPL-2.1-or-later (`COPYING`).

**Status: work in progress.** The 2026-10-04 security review findings are
fixed with regression tests (`tests/security-regressions.sh`): signing-subkey
revocation, primary/subkey material separation, embedded back-signature
(0x19) requirement, RSA signature left-padding, primary-key expiry/revocation
for subkey signatures, and signature sanity checks. Fuzz targets live in
`tests/` (libFuzzer + ASan/UBSan).
