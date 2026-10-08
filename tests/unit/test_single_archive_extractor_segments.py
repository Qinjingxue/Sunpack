from types import SimpleNamespace

import pytest

from sunpack_native import worker_manifest_from_rows

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.verification import ASSESSMENT_COMPLETE, CONTENT_INTEGRITY_VERIFIED_COMPLETE, DECISION_ACCEPT
from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.core.support.archive_input_projection import (
    write_source_extractable_segments,
)
from sunpack.pipeline.extraction.internal.sevenzip.metadata import (
    ArchiveMetadataScanner,
)
from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import (
    SingleArchiveExtractor,
)
from sunpack.pipeline.verification.scheduler import VerificationScheduler
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.config_factory import make_config


class _FakePasswordStore:
    def has_candidates(self):
        return False


class _FakePasswordResolver:
    password_tester = SimpleNamespace(passwords=[])


class _CandidatePasswordStore:
    def has_candidates(self, **_kwargs):
        return True


class _NeverPasswordResolver:
    password_tester = SimpleNamespace(passwords=[])

    def resolve(self, *_args, **_kwargs):
        raise AssertionError("boundary-proven embedded password must not be searched again")


class _RecordingPasswordResolver:
    password_tester = SimpleNamespace(passwords=[])

    def __init__(self):
        self.calls = []

    def resolve(self, _archive_path, task, *, archive_key, **_kwargs):
        knowledge = task.knowledge()
        self.calls.append((archive_key, dict(knowledge.get("source.password_probe_input") or {})))
        return PasswordResolution(
            password="",
            status=PasswordResolutionStatus.UNENCRYPTED,
            archive_key=archive_key,
            encrypted=False,
        )


class _FakeRetryPolicy:
    max_retries = 1

    def can_retry(self, *_args, **_kwargs):
        return False

    def append_retry_count(self, error, _retry_count):
        return error


class _FakeSevenZipRunner:
    def __init__(self, *, include_output_counts: bool = True):
        self.sources = []
        self.include_output_counts = bool(include_output_counts)

    def emit_semantic_event(self, _task, _event, **_payload):
        pass

    def extract_attempt(self, *, out_dir, task, **_kwargs):
        source = task.archive_input().to_dict()
        self.sources.append(source)
        name = str(source.get("format_hint") or "archive")
        import os

        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"{name}.txt"), "wb") as handle:
            handle.write(b"ok")
        result = {
            "status": "ok",
            "item_count": 1 if self.include_output_counts else 0,
            "archive_type": name,
            "verified_manifest": {
                "validated": True,
                "file_count": 1,
                "item_count": 1,
                "inventory": {
                    "complete": True,
                    "file_count": 1,
                    "dir_count": 0,
                    "total_size": 2,
                    "identity_paths": True,
                },
                "native_rows": worker_manifest_from_rows(
                    [[0, f"{name}.txt", "", 2, 2, 0, 0, 0, 0, 1, 1, 1, 1, "6f6b"]],
                    True, 1, 0, 2, True,
                ),
            },
        }
        if self.include_output_counts:
            result.update({
                "files_written": 1,
                "bytes_written": 2,
            })
        return SimpleNamespace(
            returncode=0,
            worker_diagnostics={"result": result},
        )


def _task(path):
    return make_archive_task(path, logical_name="case")


def test_unknown_zip_without_passwords_uses_direct_empty_worker_candidate(tmp_path):
    archive = tmp_path / "carrier.zip"
    archive.write_bytes(b"unknown-password-state")
    task = make_archive_task(archive, format_hint="zip")

    class Resolver:
        password_tester = SimpleNamespace(passwords=[])

        def resolve(self, *_args, **_kwargs):
            raise AssertionError("unknown/no-password ZIP must go directly to worker")

    extractor = SingleArchiveExtractor(
        password_store=_FakePasswordStore(),
        password_resolver=Resolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        retry_policy=_FakeRetryPolicy(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )

    resolution = extractor._resolve_password(task, str(archive), [str(archive)])

    assert resolution.password == ""
    assert resolution.candidate_passwords == ("",)
    assert resolution.candidate_evidence == "zip_empty_password_direct"


def test_embedded_password_probe_and_session_key_follow_active_segment(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"prefix-first-gap-second-tail")
    task = _task(carrier)
    segments = []
    for index, (start, end) in enumerate(((7, 12), (17, 23)), start=1):
        segments.append({
            "segment_id": f"embedded_{index:02d}",
            "format": "zip",
            "logical_name": "case",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "zip",
                "logical_name": "case",
                "parts": [{"path": str(carrier), "role": "main", "start": start, "end": end}],
            },
        })
    write_source_extractable_segments(task, segments)
    resolver = _RecordingPasswordResolver()
    extractor = SingleArchiveExtractor(
        password_store=_CandidatePasswordStore(),
        password_resolver=resolver,
        metadata_scanner=ArchiveMetadataScanner(),
        retry_policy=_FakeRetryPolicy(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert task.archive_input().open_mode == "file"
    assert len({key for key, _ in resolver.calls}) == 2
    assert all(key.startswith(f"{task.key}#zip:") for key, _ in resolver.calls)
    assert [call[1]["parts"][0]["start"] for call in resolver.calls] == [7, 17]


def test_embedded_boundary_password_is_reused_without_second_search(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"prefix-rar-tail")
    task = _task(carrier)
    task.runtime["embedded_segment_passwords"] = {"7": "segment-secret"}
    write_source_extractable_segments(task, [{
        "segment_id": "embedded_01_rar",
        "index": 1,
        "format": "rar",
        "logical_name": "case_01_rar",
        "start_offset": 7,
        "end_offset": 10,
        "archive_input": {
            "kind": "archive_input",
            "entry_path": str(carrier),
            "open_mode": "file_range",
            "format_hint": "rar",
            "logical_name": "case_01_rar",
            "parts": [{"path": str(carrier), "role": "main", "start": 7, "end": 10}],
            "analysis": {"password_required": True},
        },
    }])
    extractor = SingleArchiveExtractor(
        password_store=_CandidatePasswordStore(),
        password_resolver=_NeverPasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        retry_policy=_FakeRetryPolicy(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert result.password_used == "segment-secret"
    assert task.knowledge().get("archive.password") is None


def test_single_embedded_segment_exposes_logical_input_for_verification(tmp_path):
    carrier = tmp_path / "carrier.exe"
    carrier.write_bytes(b"stub-zip-tail")
    task = _task(carrier)
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "zip",
        "logical_name": "payload",
        "parts": [{"path": str(carrier), "role": "main", "start": 5, "end": 8}],
    }
    write_source_extractable_segments(task, [{
        "segment_id": "embedded_01_zip",
        "format": "zip",
        "logical_name": "payload",
        "archive_input": archive_input,
    }])
    extractor = SingleArchiveExtractor(
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        retry_policy=_FakeRetryPolicy(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / "zip.txt").exists()
    assert not (tmp_path / "out" / "embedded_01_zip").exists()
    assert len(result.embedded_results) == 1
    segment, segment_result = result.embedded_results[0]
    assert segment["archive_input"] == archive_input
    assert segment_result.diagnostics["verification_archive_input"] == archive_input
    assert segment_result.diagnostics["result"]["verified_manifest"]["validated"] is True
    assert task.archive_input().open_mode == "file"


    verification = VerificationScheduler(make_config({"verification": {"enabled": True, "methods": [{"name": "archive_test_crc"}]}})).verify(task, result)
    assert verification.decision_hint == DECISION_ACCEPT
    assert verification.assessment_status == ASSESSMENT_COMPLETE
    assert verification.content_integrity == CONTENT_INTEGRITY_VERIFIED_COMPLETE
    assert verification.archive_coverage.complete_files == 1


@pytest.mark.parametrize("count", [1, 2])
def test_multiple_embedded_failures_keep_aggregate_diagnosis(count):
    extractor = SingleArchiveExtractor(
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        retry_policy=_FakeRetryPolicy(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )
    failures = [
        FailureInfo(
            kind=FailureKind.DAMAGED,
            stage="extraction",
            message="damaged",
            message_key="failure.damaged",
        ),
        FailureInfo(
            kind=FailureKind.MISSING_VOLUME,
            stage="extraction",
            message="missing",
            message_key="failure.missing_volume",
        ),
    ]

    failures = failures[:count]
    aggregate = extractor._aggregate_embedded_failure(failures, segment_count=count)

    assert aggregate.kind is FailureKind.EMBEDDED_SEGMENTS_FAILED
    assert aggregate.message_key == ("failure.damaged" if count == 1 else "failure.embedded_extract_failed")
    assert aggregate.causes == tuple(failures)
    assert aggregate.contains(FailureKind.DAMAGED)
    assert aggregate.contains(FailureKind.MISSING_VOLUME) is (count == 2)


def test_extractor_fills_success_output_counts_when_worker_omits_them(tmp_path):
    archive = tmp_path / "case.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    task = _task(archive)
    runner = _FakeSevenZipRunner(include_output_counts=False)
    extractor = SingleArchiveExtractor(
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        retry_policy=_FakeRetryPolicy(),
        sevenzip_runner=runner,
        best_effort=True,
        write_progress_manifest=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"), allow_embedded_segments=False)

    assert result.success is True
    assert result.files_written == 1
    assert result.bytes_written == 2
    assert result.diagnostics["result"]["files_written"] == 1
    assert result.diagnostics["result"]["bytes_written"] == 2
    assert result.progress_manifest_payload.files_written == 1
    assert result.progress_manifest_payload.bytes_written == 2
