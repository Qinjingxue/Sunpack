# Licensing and third-party compliance

This document summarizes how licenses are scoped in the SunPack repository and
what must be preserved when distributing SunPack. The original license texts
control if this summary differs from them.

## SunPack-original code

Source code written for SunPack is licensed under the MIT License in the
repository root [LICENSE](../LICENSE).

The root MIT License does **not** relicense third-party source code vendored in
this repository. Third-party files remain under the licenses identified by
their upstream projects and by [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Vendored 7-Zip 26.03 source

The repository vendors 7-Zip 26.03 source code at:

`native/sevenzip_bridge/7z2603-src/`

That subtree is governed by the upstream 7-Zip source license, not by SunPack's
MIT License. The authoritative copy bundled with the source tree is:

`native/sevenzip_bridge/7z2603-src/DOC/License.txt`

A convenience copy is also kept at:

`licenses/7zip-source-license.txt`

The upstream license identifies these file-specific terms:

- `CPP/7zip/Compress/Rar*`: GNU LGPL plus the unRAR license restriction.
- `CPP/7zip/Compress/LzfseDecoder.cpp`: BSD 3-Clause.
- `C/ZstdDec.c`: BSD 3-Clause.
- `C/Xxh64.c`: BSD 2-Clause.
- Files explicitly marked public domain retain that status.
- Other 7-Zip source files are under the GNU LGPL, version 2.1 or later.

The complete GNU LGPL 2.1 text is stored at
`licenses/LGPL-2.1.txt`.

### Modifying vendored 7-Zip files

Changes to files governed by the LGPL must continue to satisfy the LGPL.
In particular, when an LGPL-covered file is modified, preserve upstream
copyright/license notices and add the change notices required by the LGPL,
including that the file was changed and the date of the change.

The unRAR-restricted RAR decompression sources must also retain the upstream
restriction: they may not be used to recreate the proprietary RAR compression
algorithm. See the upstream 7-Zip license text for the exact terms.

Prefer keeping SunPack-specific integration code outside the vendored
`7z2603-src/` tree where practical. This keeps upstream provenance and license
boundaries easy to audit and reduces merge friction when updating 7-Zip.

## Vendored zlib-ng 2.3.3 source

The native ZIP Deflate fast path vendors the required zlib-ng 2.3.3 build
sources at:

`native/sevenzip_bridge/zlib-ng-2.3.3/`

Those files are pinned to upstream commit
`12731092979c6d07f42da27da673a9f6c7b13586` and remain under the upstream
zlib license. The release copy is stored at:

`licenses/zlib-ng-license.txt`

Keep the upstream copyright and permission notice with redistributed source and
binary packages.

## 7-Zip runtime binaries and development assets

Some development or release workflows can also stage or redistribute 7-Zip
runtime binaries such as `7z.dll`, `7z.exe`, `7z.sfx`, `7zCon.sfx`,
`7-zip.dll`, or `7-zip32.dll`. Those binaries remain subject to the 7-Zip
binary distribution terms summarized in `licenses/7zip-license.txt`.

## Release packaging requirements

Windows release packages must include the following license material:

- SunPack MIT license (`LICENSE`).
- `THIRD_PARTY_NOTICES.md`.
- `licenses/7zip-license.txt`.
- `licenses/7zip-source-license.txt`.
- `licenses/LGPL-2.1.txt`.
- `licenses/zlib-ng-license.txt`.

If a release compiles or links LGPL-covered 7-Zip source into a SunPack binary,
the release process must also satisfy the applicable LGPL requirements for the
exact source used to build that binary and for recipients' ability to modify
the LGPL-covered code and rebuild/relink the combined work. Do not remove the
corresponding source or build materials from a release workflow without a
license review.

## Updating 7-Zip

When updating the vendored 7-Zip version:

1. Import the upstream license file together with the source.
2. Refresh `licenses/7zip-source-license.txt` from that exact upstream version.
3. Review upstream license changes, especially the RAR, BSD, and public-domain
   exceptions.
4. Update `THIRD_PARTY_NOTICES.md` and this document if paths, versions, or
   license terms change.
5. Keep release-package tests verifying that all required license files ship.

