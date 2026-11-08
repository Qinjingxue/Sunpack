"""Mutable coordinator state for one pipeline execution."""

import threading
from dataclasses import replace
from collections.abc import Iterable

from sunpack.core.contracts.failures import FailureInfo
from sunpack.core.contracts.results import ArchiveCleanupResult, RunSummary, TargetRunResult
from sunpack.core.support.filesystem_scan_errors import (
    DIRECTORY_ERROR_REPORT_LIMIT, directory_error_key, directory_error_count,
    filesystem_scan_failure, is_filesystem_scan_failure,
)
from sunpack.core.i18n import I18nContext
from sunpack.core.support.path_map import PathMap


class RunState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self._scan_failures: list[FailureInfo] = []
        self.processed_keys: set[str] = set()
        self.target_results: list[TargetRunResult] = []
        self._target_slots: dict[int, int] = {}
        self._target_outputs = PathMap()
        self._cleanup_results = PathMap()
        self.policy_skips: list[dict] = []
        self._scan_error_keys: set[tuple[str, str, str]] | None = None
        self._omitted_scan_errors = 0
        self._scan_language = "en"

    def add_target_result(self, result: TargetRunResult) -> None:
        slot = len(self.target_results)
        self.target_results.append(result)
        self._index_target_result(slot, result)

    def _index_target_result(self, slot: int, result: TargetRunResult) -> None:
        self._target_slots[id(result)] = slot
        if result.output_dir:
            self._target_outputs.setdefault(result.output_dir, []).append(slot)

    def replace_target_result(self, old: TargetRunResult, new: TargetRunResult) -> None:
        slot = self._target_slots.pop(id(old), None)
        if slot is None:
            return
        if old.output_dir:
            slots = self._target_outputs.get(old.output_dir)
            if slots is not None:
                slots.remove(slot)
                if not slots:
                    del self._target_outputs[old.output_dir]
        self.target_results[slot] = new
        self._index_target_result(slot, new)

    @property
    def cleanup_results(self) -> tuple[ArchiveCleanupResult, ...]:
        return tuple(self._cleanup_results.values())

    def add_cleanup_result(self, result: ArchiveCleanupResult) -> None:
        self._cleanup_results[result.path] = result

    def relocate_outputs(self, result) -> None:
        for _path, slots in self._target_outputs.pop_under(result.path):
            for slot in slots:
                old = self.target_results[slot]
                path = result.relocate(old.output_dir)
                failure = old.failure
                if failure is not None and failure.details.get("retry_output_dir"):
                    from sunpack.core.contracts.input_plan import InputRecovery

                    failure = replace(failure, details={
                        **failure.details, "retry_output_dir": result.relocate(failure.details["retry_output_dir"]),
                        "input_recovery": InputRecovery.from_failure(failure).relocate_outputs(result.relocate).to_dict(),
                    })
                if path != old.output_dir or failure is not old.failure:
                    self._target_slots.pop(id(old), None)
                    self.target_results[slot] = replace(old, output_dir=path, failure=failure)
                self._index_target_result(slot, self.target_results[slot])
        for _path, old in self._cleanup_results.pop_under(result.path):
            path = result.relocate(old.path)
            self.add_cleanup_result(replace(old, path=path) if path != old.path else old)

    @property
    def scan_failures(self) -> list[FailureInfo]:
        if not self._omitted_scan_errors:
            return self._scan_failures
        return [*self._scan_failures, filesystem_scan_failure(
            ("report_omitted", "", str(self._omitted_scan_errors)), self._scan_language,
        )]

    def record_scan_errors(self, errors: Iterable[tuple[str, str, str]], language: str) -> None:
        for error in errors:
            self._record_scan_error(error, language)

    def _record_scan_error(self, error: tuple[str, str, str], language: str,
                           failure: FailureInfo | None = None) -> None:
        key = directory_error_key(error)
        with self.lock:
            self._scan_language = language
            if error[0] == "report_omitted":
                self._omitted_scan_errors += directory_error_count(error)
                return
            if self._scan_error_keys is None:
                self._scan_error_keys = set()
            if key in self._scan_error_keys:
                return
            if len(self._scan_error_keys) >= DIRECTORY_ERROR_REPORT_LIMIT:
                self._omitted_scan_errors += directory_error_count(error)
                return
            self._scan_error_keys.add(key)
            self._scan_failures.append(failure if failure is not None else filesystem_scan_failure(error, language))

    def record_failures(self, failures: Iterable[FailureInfo], language: str) -> None:
        i18n = None
        for failure in failures:
            if is_filesystem_scan_failure(failure):
                self._record_scan_error((
                    failure.details["operation"], failure.details["path"], failure.message_params["error"],
                ), language, failure)
                continue
            if failure.message_key:
                i18n = i18n or I18nContext(language)
                failure = replace(failure, message=i18n.t(failure.message_key, **failure.message_params))
            with self.lock:
                if failure not in self._scan_failures:
                    self._scan_failures.append(failure)

    def snapshot(self) -> RunSummary:
        return RunSummary(
            target_results=tuple(self.target_results),
            scan_failures=tuple(self.scan_failures),
            policy_skips=tuple(self.policy_skips),
            cleanup_results=self.cleanup_results,
        )
