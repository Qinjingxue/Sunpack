# 授權條款與發行

[English](../licensing.md) | **繁體中文** | [日本語](../ja/licensing.md) | [한국어](../ko/licensing.md)

本文說明 SunPack 儲存庫中各授權條款的適用範圍，以及發行時要保留的文件。摘要如與授權原文不同，以原文為準。

## SunPack 原創程式碼

為 SunPack 編寫的原始碼採用專案根目錄中的 [MIT 授權條款](../../LICENSE)。隨附的第三方原始碼仍適用上游專案及 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) 記載的授權條款。

## 隨附的 7-Zip 26.05 原始碼

SunPack 選用部分 7-Zip 26.05 原始碼並進行修改，沿用 `sunpack/sevenzip_bridge/7z2604-src/` 路徑。該目錄適用上游 7-Zip 原始碼授權條款。原文位於[來源目錄的 License.txt](../../sunpack/sevenzip_bridge/7z2604-src/DOC/License.txt)，供發行使用的副本位於 [licenses/7zip-source-license.txt](../../licenses/7zip-source-license.txt)。

| 檔案 | 適用條款 |
| --- | --- |
| `CPP/7zip/Compress/Rar*` | GNU LGPL 與 unRAR 授權限制 |
| `CPP/7zip/Compress/LzfseDecoder.cpp` | BSD 3-Clause |
| `C/ZstdDec.c` | BSD 3-Clause |
| `C/Xxh64.c` | BSD 2-Clause |
| 明確標註為公有領域的檔案 | 保留公有領域地位 |
| 其他 7-Zip 原始碼 | GNU LGPL 2.1 或更新版本 |

另附 [GNU LGPL 2.1 全文](../../licenses/LGPL-2.1.txt)。修改受 LGPL 規範的檔案時，請保留上游著作權和授權聲明，並註明修改事實與日期。受 unRAR 限制的解壓縮程式碼仍須保留上游限制，不得用於重建專有的 RAR 壓縮演演算法。確切條款見上游原文。

在可行的情況下，將 SunPack 專用整合程式碼放在 `7z2604-src/` 之外，便於核對出處和授權範圍，也可減少更新上游版本時的合併工作。

## 隨附的 zlib-ng 2.3.3 與開發工具

ZIP Deflate 快速路徑使用的建置原始碼位於 `sunpack/sevenzip_bridge/zlib-ng-2.3.3/`，固定於上游提交 `12731092979c6d07f42da27da673a9f6c7b13586` 並遵循上游 zlib 授權條款。再發行原始碼或二進位套件時請保留上游著作權與授權聲明。[發行用授權條款副本](../../licenses/zlib-ng-license.txt)。

開發環境下載的 `7z.exe`、`7z.dll` 和 `7zCon.sfx` 用於產生測試資料，適用 [7-Zip 二進位發行條款](../../licenses/7zip-license.txt)。

## 發行套件

Windows 發行套件會安裝 `scripts/generate_license_bundle.ps1` 產生的 `THIRD_PARTY_LICENSES.txt`。內容包括 SunPack 的 MIT 授權、第三方元件概覽、儲存庫的 `licenses/` 原文、GUI 相依項目的聲明（如 FreeType 和 stb），以及所選 Windows 目標鎖定的 Cargo 相依項目授權與聲明。也可能包含建置及測試相依項目的聲明。各元件的適用範圍依原始聲明而定。

授權原文仍保留在儲存庫和 GUI 相依項目原始碼中。安裝程式顯示根目錄的 MIT 授權條款，並且不另行安裝授權原始目錄。缺少必要資料時，整合檔案會產生失敗。新增相依項目時仍須審查其授權條款。

如果發行版編譯或連結受 LGPL 規範的 7-Zip 程式碼，發行流程須符合適用的 LGPL 要求，包括提供建置所用的確切原始碼，並讓接收者能修改相關程式碼及重新建置、連結合併後的成果。從發行流程移除相關原始碼或建置資料前，請先審查授權要求。

## 更新 7-Zip

1. 匯入上游原始碼時一併匯入其授權檔案。
2. 用同一版本的原文更新 `licenses/7zip-source-license.txt`。
3. 審查上游授權變更，特別是 RAR、BSD 與公有領域例外。
4. 路徑、版本或授權變更時，更新第三方聲明和本文。
5. 在發行套件測試中驗證整合文件仍包含所有必要授權文字和出處聲明。
