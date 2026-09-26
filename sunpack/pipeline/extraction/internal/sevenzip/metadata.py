import os
from typing import Any, Optional

from sunpack_native import analyze_zip_filename_encoding as _NATIVE_ANALYZE_ZIP_ENCODING

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.i18n import I18nContext


class ArchiveMetadataScanResult:
    def __init__(self, archive_path: str, archive_type: str, reasons: list[str] | None = None):
        self.archive_path = archive_path
        self.archive_type = archive_type
        self.warnings: list[str] = []
        self.reasons: list[str] = reasons or []
        self.selected_codepage: Optional[str] = None
        self.error: Optional[str] = None
        self.confidence: float = 0.0
        self.sample_count: int = 0


class ArchiveMetadataScanner:
    TASK_CACHE_KEY = "filename_metadata"
    MAX_ZIP_SAMPLES = 200000
    MAX_FILENAME_BYTES = 64 * 1024 * 1024

    def __init__(self, language: str = "en"):
        self.i18n = I18nContext(language)

    def scan(
        self,
        archive_path: str,
        password: Optional[str] = None,
        part_paths: list[str] | None = None,
        format_hint: str = "",
        archive_input: dict[str, Any] | ArchiveInputDescriptor | None = None,
    ) -> ArchiveMetadataScanResult:
        del password
        descriptor = self._descriptor(
            archive_path,
            part_paths=part_paths,
            format_hint=format_hint,
            archive_input=archive_input,
        )
        return self._scan_descriptor(descriptor)

    def scan_for_task(
        self,
        task,
        archive_path: str,
        password: Optional[str] = None,
        part_paths: list[str] | None = None,
        format_hint: str = "",
    ) -> ArchiveMetadataScanResult:
        """Reuse native filename metadata across extraction retries for one task."""
        del password
        descriptor = (
            task.archive_input()
            if task is not None
            else self._descriptor(
                archive_path,
                part_paths=part_paths,
                format_hint=format_hint,
                archive_input=None,
            )
        )
        generation = self._task_cache_generation(task, descriptor)
        cached = task.runtime.get(self.TASK_CACHE_KEY) if task is not None else None
        if (
            isinstance(cached, dict)
            and cached.get("generation") == generation
            and cached.get("format_hint") == descriptor.format_hint
        ):
            return self._result_from_dict(cached.get("result"), descriptor.entry_path)

        result = self._scan_descriptor(descriptor)
        if task is not None:
            task.runtime[self.TASK_CACHE_KEY] = {
                "generation": generation,
                "format_hint": descriptor.format_hint,
                "result": self._result_to_dict(result),
            }
        return result

    @staticmethod
    def _descriptor(
        archive_path: str,
        *,
        part_paths: list[str] | None,
        format_hint: str,
        archive_input: dict[str, Any] | ArchiveInputDescriptor | None,
    ) -> ArchiveInputDescriptor:
        if isinstance(archive_input, ArchiveInputDescriptor):
            return archive_input
        return ArchiveInputDescriptor.from_any(
            archive_input if isinstance(archive_input, dict) else None,
            archive_path=os.path.normpath(archive_path),
            part_paths=part_paths,
            format_hint=str(format_hint or "").lower().lstrip("."),
        )

    @staticmethod
    def _task_cache_generation(task, descriptor: ArchiveInputDescriptor) -> tuple:
        source_generation = (
            task.runtime.get("source_generation")
            if task is not None and isinstance(getattr(task, "runtime", None), dict)
            else None
        )
        return (
            "source" if source_generation else "task",
            source_generation,
            id(descriptor),
        )

    @staticmethod
    def _result_to_dict(result: ArchiveMetadataScanResult) -> dict:
        return {
            "archive_type": result.archive_type,
            "warnings": list(result.warnings),
            "reasons": list(result.reasons),
            "selected_codepage": result.selected_codepage,
            "error": result.error,
            "confidence": result.confidence,
            "sample_count": result.sample_count,
        }

    @staticmethod
    def _result_from_dict(payload: dict, archive_path: str) -> ArchiveMetadataScanResult:
        payload = payload if isinstance(payload, dict) else {}
        result = ArchiveMetadataScanResult(
            archive_path,
            str(payload.get("archive_type") or "unknown"),
            list(payload.get("reasons") or []),
        )
        result.warnings = list(payload.get("warnings") or [])
        result.selected_codepage = payload.get("selected_codepage")
        result.error = payload.get("error")
        result.confidence = float(payload.get("confidence", 0.0) or 0.0)
        result.sample_count = int(payload.get("sample_count", 0) or 0)
        return result

    def _scan_descriptor(self, descriptor: ArchiveInputDescriptor) -> ArchiveMetadataScanResult:
        archive_type = descriptor.format_hint
        if archive_type == "zip":
            return self._scan_zip(descriptor)
        if archive_type in {"7z", "rar"}:
            return ArchiveMetadataScanResult(
                archive_path=descriptor.entry_path,
                archive_type=archive_type,
                reasons=[
                    self.i18n.t(
                        "metadata.no_correction_needed",
                        archive_type=archive_type.upper(),
                    )
                ],
            )
        return ArchiveMetadataScanResult(
            archive_path=descriptor.entry_path,
            archive_type=archive_type or "unknown",
            reasons=[self.i18n.t("metadata.unsupported_type")],
        )

    def _scan_zip(self, descriptor: ArchiveInputDescriptor) -> ArchiveMetadataScanResult:
        result = ArchiveMetadataScanResult(
            archive_path=descriptor.entry_path,
            archive_type="zip",
        )
        try:
            native = _NATIVE_ANALYZE_ZIP_ENCODING(
                descriptor.to_dict(),
                self.MAX_ZIP_SAMPLES,
                self.MAX_FILENAME_BYTES,
            )
            if not isinstance(native, dict):
                raise TypeError("Native ZIP filename analyzer returned a non-dict result")

            status = str(native.get("status") or "")
            warning = self._zip_native_status_warning(status)
            if warning:
                result.warnings.append(warning)
                return result
            if status != "ok":
                raise RuntimeError(f"Native ZIP filename analyzer returned unsupported status: {status}")

            result.sample_count = int(native.get("sample_count", 0) or 0)
            if bool(native.get("truncated")):
                result.error = self.i18n.t("metadata.too_many_names")
                result.warnings.append(result.error)
                return result
            if result.sample_count == 0:
                result.reasons.append(self.i18n.t("metadata.no_names"))
                return result

            if bool(native.get("authoritative_all")):
                result.confidence = 1.0
                unicode_count = int(native.get("unicode_count", 0) or 0)
                if unicode_count:
                    result.reasons.append(
                        self.i18n.t("metadata.valid_unicode_fields", count=unicode_count)
                    )
                else:
                    result.reasons.append(self.i18n.t("metadata.utf8_flagged"))
                return result

            if bool(native.get("ascii_only")):
                result.reasons.append(self.i18n.t("metadata.ascii_names"))
                return result

            result.confidence = float(native.get("confidence", 0.0) or 0.0)
            self._append_native_evidence(result, native.get("evidence"))
            selected_codepage = native.get("selected_codepage")
            if selected_codepage:
                result.selected_codepage = str(selected_codepage)
                result.reasons.append(
                    self.i18n.t(
                        "metadata.high_confidence",
                        label=str(native.get("selected_label") or ""),
                        codepage=result.selected_codepage,
                    )
                )
            else:
                result.warnings.append(self.i18n.t("metadata.low_confidence"))
                result.reasons.append(self.i18n.t("metadata.no_override"))
            return result
        except Exception as exc:
            result.warnings.append(self.i18n.t("metadata.scan_failed", error=exc))
            return result

    def _append_native_evidence(self, result: ArchiveMetadataScanResult, evidence: Any) -> None:
        if not isinstance(evidence, dict):
            return
        result.reasons.append(
            self.i18n.t(
                "metadata.score_summary",
                best_label=str(evidence.get("best_label") or ""),
                best_score=int(evidence.get("best_score", 0) or 0),
                second_label=str(evidence.get("second_label") or ""),
                second_score=int(evidence.get("second_score", 0) or 0),
                lead=int(evidence.get("lead", 0) or 0),
            )
        )
        added = 0
        for key, i18n_key in (
            ("cjk_count", "metadata.cjk_count"),
            ("kana_count", "metadata.kana_count"),
            ("halfwidth_kana_count", "metadata.halfwidth_kana_count"),
            ("latin_symbols", "metadata.latin_noise_count"),
        ):
            count = int(evidence.get(key, 0) or 0)
            if count:
                result.reasons.append(self.i18n.t(i18n_key, count=count))
                added += 1
                if added == 3:
                    break

    def _zip_native_status_warning(self, status: str) -> str:
        warnings = {
            "file_too_small": "metadata.file_too_small",
            "eocd_not_found": "metadata.eocd_not_found",
            "eocd_incomplete": "metadata.eocd_incomplete",
            "zip64": "metadata.zip64",
            "central_range_invalid": "metadata.central_range_invalid",
        }
        key = warnings.get(status)
        return self.i18n.t(key) if key else ""
