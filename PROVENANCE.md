# Header provenance

`include/gpgme.h` is copied from the Alpine 3.24 build root's GPGME 2.0.1
public header (`/mnt/data/aosp/out/pc-logs/musl-static-116/rootfs/usr/include/gpgme.h`).
`include/gpg-error.h` is copied from that root's libgpg-error 1.61 public
header. They retain the upstream copyright and LGPL-2.1-or-later SPDX text.
The generated target declaration is x86_64-alpine-linux-musl, matching the
requested static target ABI. No implementation code from either library is
copied.

BoringSSL is pinned in `boringssl.lock`; its upstream `LICENSE` at that
commit is Apache-2.0. The pinned source archive SHA-256 is recorded there.
