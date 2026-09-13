import os
import re
from typing import List, Optional, Tuple, Dict, Any

from sunpack_native import scan_zip_central_directory_names as _NATIVE_SCAN_ZIP_NAMES
from sunpack.i18n import I18nContext

class ArchiveMetadataScanResult:
    def __init__(self, archive_path: str, archive_type: str, reasons: List[str] = None):
        self.archive_path = archive_path
        self.archive_type = archive_type
        self.warnings: List[str] = []
        self.reasons: List[str] = reasons or []
        self.selected_codepage: Optional[str] = None
        self.decoded_names: List[str] = []
        self.error: Optional[str] = None
        self.confidence: float = 0.0
        self.sample_count: int = 0

class ArchiveMetadataScanner:
    TASK_CACHE_FACT = "extraction.filename_metadata"
    MAX_ZIP_SAMPLES = 200000
    MAX_FILENAME_BYTES = 64 * 1024 * 1024
    LIST_TIMEOUT_SECONDS = 5

    CODEPAGE_CANDIDATES = (
        ("cp437", None, "ZIP default cp437"),
        ("utf-8", "65001", "UTF-8"),
        ("cp936", "936", "GBK/CP936"),
        ("cp950", "950", "Big5/CP950"),
        ("cp932", "932", "Shift-JIS/CP932"),
    )
    SIMPLIFIED_COMMON_CHARS = set("的一是在不了有和人这中大为上个国我以要他中文说明资料第一章压缩文件测试")
    TRADITIONAL_COMMON_CHARS = set("的一是在不了有和人這中大為上個國我以要他繁體中文說明資料檔案測試")
    JAPANESE_COMMON_KANJI = set(
        "日本語説明書第一章画像映像音声写真漫画小説資料設定保存読込名前新旧上下左右"
        "大小年月日時分秒人子女男学校会社仕事場所東京大阪京都北海道"
    )

    def __init__(self, language: str = "en"):
        self.cache = {}
        self.i18n = I18nContext(language)

    def scan(
        self,
        archive_path: str,
        password: Optional[str] = None,
        part_paths: list[str] | None = None,
        format_hint: str = "",
    ) -> ArchiveMetadataScanResult:
        archive_path = os.path.normpath(archive_path)
        normalized_hint = str(format_hint or "").lower().lstrip(".")
        cache_key = (*self._build_cache_key(archive_path, part_paths=part_paths), normalized_hint)
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        result = self._scan_uncached(
            archive_path,
            password=password,
            part_paths=part_paths,
            format_hint=normalized_hint,
        )
        self.cache[cache_key] = result
        return result

    def scan_for_task(
        self,
        task,
        archive_path: str,
        password: Optional[str] = None,
        part_paths: list[str] | None = None,
        format_hint: str = "",
    ) -> ArchiveMetadataScanResult:
        """Reuse filename metadata across detection/extraction/worker retries."""
        normalized_hint = str(format_hint or "").lower().lstrip(".")
        signature = self._build_cache_key(os.path.normpath(archive_path), part_paths=part_paths)
        cached = task.fact_bag.get(self.TASK_CACHE_FACT) if task is not None else None
        if isinstance(cached, dict) and cached.get("signature") == signature and cached.get("format_hint") == normalized_hint:
            return self._result_from_dict(cached.get("result"), archive_path)
        result = self.scan(archive_path, password=password, part_paths=part_paths, format_hint=normalized_hint)
        if task is not None:
            task.fact_bag.set(self.TASK_CACHE_FACT, {
                "signature": signature,
                "format_hint": normalized_hint,
                "result": self._result_to_dict(result),
            })
        return result

    @staticmethod
    def _result_to_dict(result: ArchiveMetadataScanResult) -> dict:
        return {
            "archive_type": result.archive_type, "warnings": list(result.warnings),
            "reasons": list(result.reasons), "selected_codepage": result.selected_codepage,
            "decoded_names": list(result.decoded_names), "error": result.error,
            "confidence": result.confidence, "sample_count": result.sample_count,
        }

    @staticmethod
    def _result_from_dict(payload: dict, archive_path: str) -> ArchiveMetadataScanResult:
        payload = payload if isinstance(payload, dict) else {}
        result = ArchiveMetadataScanResult(archive_path, str(payload.get("archive_type") or "unknown"), list(payload.get("reasons") or []))
        result.warnings = list(payload.get("warnings") or [])
        result.selected_codepage = payload.get("selected_codepage")
        result.decoded_names = list(payload.get("decoded_names") or [])
        result.error = payload.get("error")
        result.confidence = float(payload.get("confidence", 0.0) or 0.0)
        result.sample_count = int(payload.get("sample_count", 0) or 0)
        return result

    def _build_cache_key(self, archive_path: str, part_paths: list[str] | None = None) -> tuple:
        part_keys = []
        for path in list(dict.fromkeys(part_paths or [archive_path])):
            try:
                stat = os.stat(path)
                part_keys.append((path, stat.st_size, stat.st_mtime_ns))
            except OSError:
                part_keys.append((path, 0, 0))
        try:
            stat = os.stat(archive_path)
            return (archive_path, stat.st_size, stat.st_mtime_ns, tuple(part_keys))
        except OSError:
            return (archive_path, 0, 0, tuple(part_keys))

    def _scan_uncached(
        self,
        archive_path: str,
        password: Optional[str] = None,
        part_paths: list[str] | None = None,
        format_hint: str = "",
    ) -> ArchiveMetadataScanResult:
        ext = f".{format_hint}" if format_hint else os.path.splitext(archive_path)[1].lower()
        if ext == ".zip":
            return self._scan_zip_central_directory(archive_path)
        if ext in {".7z", ".rar"}:
            return ArchiveMetadataScanResult(
                archive_path=archive_path,
                archive_type=ext.lstrip("."),
                reasons=[self.i18n.t("metadata.no_correction_needed", archive_type=ext.lstrip(".").upper())],
            )
        return ArchiveMetadataScanResult(
            archive_path=archive_path,
            archive_type=ext.lstrip(".") or "unknown",
            reasons=[self.i18n.t("metadata.unsupported_type")],
        )

    def _scan_zip_central_directory(self, archive_path: str) -> ArchiveMetadataScanResult:
        result = ArchiveMetadataScanResult(archive_path=archive_path, archive_type="zip")
        try:
            raw_names, utf8_flags, unicode_names, truncated, warning = self._scan_zip_name_samples(archive_path)
            if warning:
                result.warnings.append(warning)
                return result
            result.sample_count = len(raw_names)
            if truncated:
                result.error = self.i18n.t("metadata.too_many_names")
                result.warnings.append(result.error)
                return result
            if not raw_names:
                result.reasons.append(self.i18n.t("metadata.no_names"))
                return result
            authoritative_names = [
                self._authoritative_zip_name(raw_name, utf8, unicode_name)
                for raw_name, utf8, unicode_name in zip(raw_names, utf8_flags, unicode_names)
            ]
            if all(name is not None for name in authoritative_names):
                result.decoded_names = list(authoritative_names)
                unicode_count = sum(name is not None for name in unicode_names)
                result.confidence = 1.0
                if unicode_count:
                    result.reasons.append(self.i18n.t("metadata.valid_unicode_fields", count=unicode_count))
                else:
                    result.reasons.append(self.i18n.t("metadata.utf8_flagged"))
                return result
            if all(self._is_ascii_name(raw_name) for raw_name in raw_names):
                result.reasons.append(self.i18n.t("metadata.ascii_names"))
                return result

            unresolved_names = [
                raw_name for raw_name, authoritative in zip(raw_names, authoritative_names)
                if authoritative is None
            ]
            selected = self._select_codepage(unresolved_names)
            result.confidence = selected["confidence"]
            result.reasons.extend(selected["reasons"])
            if selected["codepage"]:
                result.selected_codepage = selected["codepage"]
                result.decoded_names = self._decode_names(
                    raw_names,
                    utf8_flags,
                    unicode_names,
                    selected["encoding"],
                )
                result.reasons.append(self.i18n.t("metadata.high_confidence", label=selected["label"], codepage=selected["codepage"]))
            else:
                result.warnings.append(self.i18n.t("metadata.low_confidence"))
                result.reasons.append(self.i18n.t("metadata.no_override"))
            return result
        except Exception as exc:
            result.warnings.append(self.i18n.t("metadata.scan_failed", error=exc))
            return result

    def _scan_zip_name_samples(self, archive_path: str) -> Tuple[List[bytes], List[bool], List[Optional[bytes]], bool, str]:
        return self._scan_zip_name_samples_native(archive_path)

    def _scan_zip_name_samples_native(self, archive_path: str) -> Tuple[List[bytes], List[bool], List[Optional[bytes]], bool, str]:
        result = _NATIVE_SCAN_ZIP_NAMES(
            archive_path,
            self.MAX_ZIP_SAMPLES,
            self.MAX_FILENAME_BYTES,
        )
        if not isinstance(result, dict):
            raise TypeError("Native ZIP name scanner returned a non-dict result")

        status = result.get("status")
        warning = self._zip_native_status_warning(status)
        if warning:
            return [], [], [], False, warning
        if status != "ok":
            raise RuntimeError(f"Native ZIP name scanner returned unsupported status: {status}")

        raw_names = result.get("raw_names")
        utf8_flags = result.get("utf8_flags")
        unicode_path_names = result.get("unicode_path_names", [None] * len(raw_names or []))
        truncated = result.get("truncated")
        if not isinstance(raw_names, list) or not isinstance(truncated, bool):
            raise TypeError("Native ZIP name scanner returned invalid raw_names/truncated")
        if not isinstance(utf8_flags, list) or len(utf8_flags) != len(raw_names):
            raise TypeError("Native ZIP name scanner returned invalid utf8_flags")
        if not isinstance(unicode_path_names, list) or len(unicode_path_names) != len(raw_names):
            raise TypeError("Native ZIP name scanner returned invalid unicode_path_names")
        normalized_names = []
        normalized_flags = []
        normalized_unicode_names = []
        for raw_name, utf8_flag, unicode_name in zip(raw_names, utf8_flags, unicode_path_names):
            if not isinstance(raw_name, bytes):
                raise TypeError("Native ZIP name scanner returned a non-bytes name")
            if not isinstance(utf8_flag, bool):
                raise TypeError("Native ZIP name scanner returned a non-bool UTF-8 flag")
            if unicode_name is not None and not isinstance(unicode_name, bytes):
                raise TypeError("Native ZIP name scanner returned an invalid Unicode path name")
            if unicode_name is not None:
                unicode_name.decode("utf-8", errors="strict")
            normalized_names.append(raw_name)
            normalized_flags.append(utf8_flag)
            normalized_unicode_names.append(unicode_name)
        return normalized_names, normalized_flags, normalized_unicode_names, truncated, ""

    @staticmethod
    def _decode_names(raw_names: List[bytes], utf8_flags: List[bool], unicode_names: List[Optional[bytes]], encoding: str) -> List[str]:
        decoded = []
        for raw_name, utf8_flag, unicode_name in zip(raw_names, utf8_flags, unicode_names):
            authoritative = ArchiveMetadataScanner._authoritative_zip_name(raw_name, utf8_flag, unicode_name)
            if authoritative is not None:
                decoded.append(authoritative)
            else:
                decoded.append(raw_name.decode(encoding, errors="strict").replace("\\", "/"))
        return decoded

    @staticmethod
    def _authoritative_zip_name(raw_name: bytes, utf8_flag: bool, unicode_name: Optional[bytes]) -> Optional[str]:
        if utf8_flag:
            try:
                return raw_name.decode("utf-8", errors="strict").replace("\\", "/")
            except UnicodeDecodeError:
                return None
        if unicode_name is not None:
            return unicode_name.decode("utf-8", errors="strict").replace("\\", "/")
        return None

    def _zip_native_status_warning(self, status) -> str:
        warnings = {
            "file_too_small": "metadata.file_too_small",
            "eocd_not_found": "metadata.eocd_not_found",
            "eocd_incomplete": "metadata.eocd_incomplete",
            "zip64": "metadata.zip64",
            "central_range_invalid": "metadata.central_range_invalid",
        }
        key = warnings.get(status)
        return self.i18n.t(key) if key else ""

    def _select_codepage(self, raw_names: List[bytes]) -> Dict[str, Any]:
        scores = []
        for encoding, codepage, label in self.CODEPAGE_CANDIDATES:
            score, decoded_count, reasons = self._score_encoding(raw_names, encoding)
            scores.append(
                {
                    "encoding": encoding,
                    "codepage": codepage,
                    "label": label,
                    "score": score,
                    "decoded_count": decoded_count,
                    "reasons": reasons,
                }
            )

        scores.sort(key=lambda item: item["score"], reverse=True)
        best = scores[0]
        second = scores[1] if len(scores) > 1 else {"score": 0, "label": "-"}
        lead = best["score"] - second["score"]
        # Confidence mirrors the admission rule: a high absolute score cannot
        # conceal an ambiguous margin over the runner-up.
        score_confidence = max(0.0, min(1.0, best["score"] / 24.0))
        lead_confidence = max(0.0, min(1.0, lead / 12.0))
        confidence = min(score_confidence, lead_confidence)
        reasons = [
            self.i18n.t(
                "metadata.score_summary",
                best_label=best["label"],
                best_score=best["score"],
                second_label=second["label"],
                second_score=second["score"],
                lead=lead,
            ),
        ]
        reasons.extend(best["reasons"][:3])

        if best["codepage"] and best["score"] >= 12 and lead >= 6 and best["decoded_count"] > 0:
            return {
                "encoding": best["encoding"],
                "codepage": best["codepage"],
                "confidence": round(confidence, 3),
                "label": best["label"],
                "reasons": reasons,
            }
        return {
            "encoding": best["encoding"],
            "codepage": None,
            "confidence": round(confidence, 3),
            "label": best["label"],
            "reasons": reasons,
        }

    def _score_encoding(self, raw_names: List[bytes], encoding: str) -> Tuple[int, int, List[str]]:
        score = 0
        decoded_count = 0
        total_cjk = 0
        total_kana = 0
        total_halfwidth_kana = 0
        total_latin_symbols = 0
        reasons = []
        decoded_components = set()

        for raw_name in raw_names:
            try:
                decoded = raw_name.decode(encoding, errors="strict")
            except UnicodeDecodeError:
                score -= 12
                continue
            decoded_count += 1
            # Parent directories are repeated in every ZIP entry. Decode before
            # splitting because a DBCS trail byte can have the value of a
            # backslash, then score each logical path component only once.
            decoded_components.update(
                component for component in re.split(r"[\\/]+", decoded) if component
            )

        for component in decoded_components:
            name_score, stats = self._score_decoded_name(component, encoding)
            score += name_score
            total_cjk += stats["cjk"]
            total_kana += stats["kana"]
            total_halfwidth_kana += stats["halfwidth_kana"]
            total_latin_symbols += stats["latin_symbols"]

        # CP932, GBK and Big5 deliberately overlap: the same byte pairs can be
        # valid in more than one codec while producing entirely different Han
        # characters.  Their standard/common code areas do not overlap in the
        # same way, though.  Use that byte-level evidence before falling back
        # to the much weaker decoded-character heuristics below.
        score += self._score_legacy_code_units(raw_names, encoding)

        if decoded_count == len(raw_names):
            score += 4
        if total_cjk:
            reasons.append(self.i18n.t("metadata.cjk_count", count=total_cjk))
        if total_kana:
            reasons.append(self.i18n.t("metadata.kana_count", count=total_kana))
        if total_halfwidth_kana:
            reasons.append(self.i18n.t("metadata.halfwidth_kana_count", count=total_halfwidth_kana))
        if total_latin_symbols:
            reasons.append(self.i18n.t("metadata.latin_noise_count", count=total_latin_symbols))
        return score, decoded_count, reasons

    @staticmethod
    def _score_legacy_code_units(raw_names: List[bytes], encoding: str) -> int:
        """Score unique DBCS units by their codec's standard/common area.

        Strict decoding only proves that a byte sequence is possible.  In
        particular, ordinary CP932 pairs frequently decode as rare GBK
        extension characters.  Ranking unique units avoids repeated parent
        directories dominating archives with many entries.
        """
        if encoding not in {"cp932", "cp936", "cp950"}:
            return 0

        units: set[tuple[int, int]] = set()
        for raw_name in raw_names:
            index = 0
            while index + 1 < len(raw_name):
                lead = raw_name[index]
                if encoding == "cp932":
                    is_lead = 0x81 <= lead <= 0x9F or 0xE0 <= lead <= 0xFC
                else:
                    is_lead = 0x81 <= lead <= 0xFE
                if is_lead:
                    units.add((lead, raw_name[index + 1]))
                    index += 2
                else:
                    index += 1

        score = 0
        for lead, trail in units:
            if encoding == "cp932":
                # Windows-31J extensions occupy the NEC/IBM and user-defined
                # rows.  Other valid pairs are in the standard JIS area.
                extension = (
                    (lead == 0x87 and 0x40 <= trail <= 0x9C)
                    or 0xED <= lead <= 0xEE
                    or 0xF0 <= lead <= 0xFC
                )
                score += 0 if extension else 2
            elif encoding == "cp936":
                # GB2312 is the common core of CP936.  GBK pairs outside it
                # are valid but substantially weaker evidence for Chinese.
                in_common_core = 0xA1 <= lead <= 0xF7 and 0xA1 <= trail <= 0xFE
                score += 2 if in_common_core else 0
            else:
                # The original Big5 rows form CP950's common core; lower and
                # upper extension rows are valid but uncommon in filenames.
                valid_trail = 0x40 <= trail <= 0x7E or 0xA1 <= trail <= 0xFE
                in_common_core = 0xA1 <= lead <= 0xF9 and valid_trail
                score += 2 if in_common_core else 0
        return score

    def _score_decoded_name(self, decoded: str, encoding: str) -> Tuple[int, Dict[str, int]]:
        score = 0
        stats = {"cjk": 0, "kana": 0, "halfwidth_kana": 0, "latin_symbols": 0}
        if not decoded:
            return -5, stats

        if "\x00" in decoded or any(ord(ch) < 32 for ch in decoded if ch not in "\t\n\r"):
            score -= 20
        if re.search(r'[<>:"|?*]', decoded):
            score -= 10
        if any(part in {"", ".", ".."} for part in re.split(r"[\\/]+", decoded) if part != ""):
            score -= 3
        # CP932 maps vendor/user-defined byte ranges into Unicode private-use
        # characters. They are technically decodable but are very unlikely in
        # archive paths and are a strong mojibake signal for GBK input.
        score -= sum(1 for ch in decoded if "\ue000" <= ch <= "\uf8ff") * 8

        cjk_chars = sum(1 for ch in decoded if "\u4e00" <= ch <= "\u9fff")
        kana_chars = sum(1 for ch in decoded if "\u3040" <= ch <= "\u30ff")
        halfwidth_kana_chars = sum(1 for ch in decoded if "\uff66" <= ch <= "\uff9f")
        latin_symbols = sum(1 for ch in decoded if "\u00a0" <= ch <= "\u00ff" or "\u2500" <= ch <= "\u259f")
        stats["cjk"] = cjk_chars
        stats["kana"] = kana_chars
        stats["halfwidth_kana"] = halfwidth_kana_chars
        stats["latin_symbols"] = latin_symbols

        if encoding == "cp932":
            # Han characters alone do not distinguish Chinese from Japanese.
            # Give every CJK candidate the same neutral Han weight and let kana
            # plus language-specific common characters provide the evidence.
            score += cjk_chars * 3 + kana_chars * 6 + halfwidth_kana_chars * 6
            score += sum(1 for ch in decoded if ch in self.JAPANESE_COMMON_KANJI) * 4
            if halfwidth_kana_chars and not kana_chars:
                score -= halfwidth_kana_chars * 3
        elif encoding == "cp936":
            score += cjk_chars * 3
            score -= (kana_chars + halfwidth_kana_chars) * 2
            score += sum(1 for ch in decoded if ch in self.SIMPLIFIED_COMMON_CHARS) * 3
            score -= sum(1 for ch in decoded if ch in self.TRADITIONAL_COMMON_CHARS - self.SIMPLIFIED_COMMON_CHARS)
            score -= sum(1 for ch in decoded if ch in self.JAPANESE_COMMON_KANJI - self.SIMPLIFIED_COMMON_CHARS)
        elif encoding == "cp950":
            score += cjk_chars * 3
            score -= (kana_chars + halfwidth_kana_chars) * 2
            score += sum(1 for ch in decoded if ch in self.TRADITIONAL_COMMON_CHARS) * 3
            score -= sum(1 for ch in decoded if ch in self.SIMPLIFIED_COMMON_CHARS - self.TRADITIONAL_COMMON_CHARS)
        elif encoding == "utf-8":
            score += (cjk_chars + kana_chars) * 4
        elif encoding == "cp437":
            score -= latin_symbols * 2

        score -= latin_symbols
        return score, stats

    def _is_ascii_name(self, raw_name: bytes) -> bool:
        return all(byte < 128 for byte in raw_name)
