# Third-Party Notices

SunPack-original source code is licensed under the MIT License. Third-party
source code and binaries included in this repository or staged by SunPack's
development and release workflows remain subject to their original licenses.

See [docs/licensing.md](docs/licensing.md) for the repository's license scope
and release-compliance guidance.

## 7-Zip source code

SunPack vendors the 7-Zip 26.03 source tree at:

`native/sevenzip_bridge/7z2603-src/`

That subtree is not covered by SunPack's MIT License. It remains under the
upstream 7-Zip source license. The authoritative license file imported with the
source is:

`native/sevenzip_bridge/7z2603-src/DOC/License.txt`

A convenience copy is distributed at
[licenses/7zip-source-license.txt](licenses/7zip-source-license.txt).

7-Zip Copyright (C) 1999-2026 Igor Pavlov and other respective copyright
holders.

The upstream 7-Zip 26.03 source license identifies the following file-specific
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
