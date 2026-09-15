# Third-Party Notices

SunPack source code is licensed under the MIT License. This file covers
third-party components included or staged by SunPack's Windows development and
release workflows.

## 7-Zip

SunPack redistributes components from 7-Zip. Depending on the build context,
these can include:

- 7z.dll, the runtime component used by SunPack
- 7z.exe
- 7z.sfx
- 7zCon.sfx
- 7-zip.dll
- 7-zip32.dll (x64 development assets)

7-Zip Copyright (C) Igor Pavlov and other respective copyright holders. The
distributed 7-Zip components are primarily licensed under the GNU Lesser
General Public License version 2.1 or later, with BSD 2-Clause and BSD 3-Clause
portions and an unRAR license restriction, as described in
[licenses/7zip-license.txt](licenses/7zip-license.txt).

The complete GNU LGPL 2.1 text is included at
[licenses/LGPL-2.1.txt](licenses/LGPL-2.1.txt).

The 7-Zip source code and release downloads are available from
[7-zip.org](https://www.7-zip.org/). The build currently follows the official
Windows download page for the 7-Zip installer without pinning a version; for a
particular distributed build, use the corresponding source archive for the
7-Zip release shown on that page.

SunPack loads 7z.dll through a runtime shared-library boundary. The 7-Zip
components and their licenses are separate from SunPack's MIT-licensed source
code.
