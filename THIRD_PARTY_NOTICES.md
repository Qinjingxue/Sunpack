# Third-Party Notices

SunPack-original source code is licensed under the MIT License. Third-party
source code and binaries included in this repository or staged by SunPack's
development and release workflows remain subject to their original licenses.

See [docs/licensing.md](docs/licensing.md) for the repository's license scope
and release-compliance guidance.

## 7-Zip source code

SunPack vendors the 7-Zip 26.04 source tree at:

`native/sevenzip_bridge/7z2604-src/`

This is SunPack's trimmed and modified source subset. The 26.04 update imports
the ZIP64, XZ, vector and limited-stream runtime fixes, while preserving
SunPack's codec and CPU-budget patches. Compiler-only annotations and changes
outside the supported runtime paths are omitted. See
[the synchronization record](docs/zh-CN/sevenzip_26_04_sync_review.md) for the
upstream provenance and exact scope.

That subtree is not covered by SunPack's MIT License. It remains under the
upstream 7-Zip source license. The authoritative license file imported with the
source is:

`native/sevenzip_bridge/7z2604-src/DOC/License.txt`

A convenience copy is distributed at
[licenses/7zip-source-license.txt](licenses/7zip-source-license.txt).

7-Zip Copyright (C) 1999-2026 Igor Pavlov and other respective copyright
holders.

The upstream 7-Zip 26.04 source license identifies the following file-specific
terms:

- `CPP/7zip/Compress/Rar*`: GNU LGPL plus the unRAR license restriction.
- `CPP/7zip/Compress/LzfseDecoder.cpp`: BSD 3-Clause.
- `C/ZstdDec.c`: BSD 3-Clause.
- `C/Xxh64.c`: BSD 2-Clause.
- Files explicitly marked public domain retain that status.
- Other 7-Zip source files are licensed under GNU LGPL version 2.1 or later.

The complete GNU LGPL 2.1 text is included at
[licenses/LGPL-2.1.txt](licenses/LGPL-2.1.txt).

The unRAR-restricted source code may not be used to recreate the proprietary
RAR compression algorithm. The exact restriction and redistribution terms are
reproduced in the 7-Zip source license file referenced above.

## zlib-ng 2.3.3

SunPack vendors the runtime build subset of zlib-ng 2.3.3 at:

`native/sevenzip_bridge/zlib-ng-2.3.3/`

The imported files are pinned to upstream commit
`12731092979c6d07f42da27da673a9f6c7b13586` and are used for selected ZIP
Deflate decoding paths. They remain under the upstream zlib license. A copy is
distributed at [licenses/zlib-ng-license.txt](licenses/zlib-ng-license.txt).

zlib-ng source and releases are available from
[github.com/zlib-ng/zlib-ng](https://github.com/zlib-ng/zlib-ng/).

## 7-Zip runtime binaries and development assets

Depending on the build context, SunPack can also stage or redistribute 7-Zip
runtime binaries and development assets, including:

- 7z.dll
- 7z.exe
- 7z.sfx
- 7zCon.sfx
- 7-zip.dll
- 7-zip32.dll (x64 development assets)

Those components remain subject to the 7-Zip binary distribution terms
reproduced in [licenses/7zip-license.txt](licenses/7zip-license.txt).

7-Zip source code and official releases are available from
[7-zip.org](https://www.7-zip.org/).

## License boundary

The repository-root MIT License applies to SunPack-original code. It does not
relicense the vendored 7-Zip source tree or other third-party components.

If SunPack modifies LGPL-covered 7-Zip files, the applicable upstream copyright
and license notices must be preserved and the change notices required by the
LGPL must be added.

If a release compiles or links LGPL-covered 7-Zip source into a SunPack binary,
that release must also satisfy the applicable LGPL source, modification, and
rebuild/relink requirements for the exact code used to produce the binary.

## LZ4 1.10.0 and xxHash

SunPack vendors the unmodified LZ4 1.10.0 library sources and bundled xxHash at
`native/third_party/lz4/`. They are compiled into the Rust extension and the
archive worker for LZ4 Frame decoding. The library remains under
the BSD 2-Clause license. The full notice is distributed at
[licenses/lz4-license.txt](licenses/lz4-license.txt).

Source: https://github.com/lz4/lz4/tree/v1.10.0/lib

## RustCrypto Twofish

The Twofish-256 key schedule and q permutations in
`native/sunpack_enc/src/twofish.rs` are adapted from RustCrypto twofish 0.7.1
by Alexander Krotov (2017), under the MIT license. SunPack expands the keyed
S-box/MDS tables during key setup and shares them across CTR tasks.
The full notice is distributed at [licenses/twofish-license.txt](licenses/twofish-license.txt).

Source: https://github.com/RustCrypto/block-ciphers/tree/twofish-v0.7.1/twofish

## RustCrypto Serpent

The Serpent-256 key schedule and Boolean S-box circuits in
`native/sunpack_enc/src/serpent.rs` are adapted from RustCrypto serpent 0.6.0,
Copyright (c) 2019-2024 The RustCrypto Project Developers and
Copyright (c) 2019 Jonathan Serra, under the MIT license. SunPack uses the same
circuits for scalar blocks and eight-block AVX2 encryption, sharing one expanded
key across CTR tasks. The full notice is distributed at
[licenses/serpent-license.txt](licenses/serpent-license.txt).

Source: https://github.com/RustCrypto/block-ciphers/tree/serpent-v0.6.0/serpent

## RustCrypto Threefish

The Threefish-1024 key schedule and round constants in
`native/sunpack_enc/src/threefish.rs` are adapted from RustCrypto threefish 0.5.2,
Copyright (c) 2016-2017 Christian Barcenas, Artyom Pavlov, under the MIT license.
SunPack uses a zero tweak, constant-rotation round cycles, and four-block AVX2
encryption with scalar tails. The full notice is distributed at
[licenses/threefish-license.txt](licenses/threefish-license.txt).

Source: https://github.com/RustCrypto/block-ciphers/tree/threefish-v0.5.2/threefish

## RustCrypto Magma/GOST

The GOST 28147-89 TestSbox constants and key ordering in
`native/sunpack_enc/src/gost.rs` are adapted from RustCrypto magma 0.9.0,
Copyright (c) 2017 Artyom Pavlov, under the MIT license. SunPack shares
compile-time substitution/rotation tables and interleaves independent blocks.
The full notice is distributed at
[licenses/magma-license.txt](licenses/magma-license.txt).

Source: https://github.com/RustCrypto/block-ciphers/tree/magma-v0.9.0/magma

## RustCrypto RC6

The RC6-32/20/32 key expansion and rounds in `native/sunpack_enc/src/rc6.rs`
are adapted from RustCrypto rc6 0.1.0, Copyright (c) 2017 Damian Czaja,
under the MIT license. SunPack uses an AVX2 backend with eight blocks per
vector state, interleaved states, and scalar tails. The full notice is
distributed at [licenses/rc6-license.txt](licenses/rc6-license.txt).

Source: https://github.com/RustCrypto/block-ciphers/tree/rc6-v0.1.0/rc6

## RustCrypto Blowfish

The Blowfish key expansion and initial P/S constants in
`native/sunpack_enc/src/blowfish.rs` and `blowfish_init.rs` are adapted from
RustCrypto blowfish 0.9.1, Copyright (c) 2006-2009 Graydon Hoare and
Copyright (c) 2009-2013 Mozilla Foundation, under the MIT license.
SunPack interleaves independent blocks and shares one expanded key across
CTR tasks. The full notice is distributed at
[licenses/blowfish-license.txt](licenses/blowfish-license.txt).

Source: https://github.com/RustCrypto/block-ciphers/tree/blowfish-v0.9.1/blowfish
