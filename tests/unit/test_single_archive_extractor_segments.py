from types import SimpleNamespace

from sunpack.support.archive_input_projection import write_source_extractable_segments
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner
from sunpack.verification.scheduler import VerificationScheduler
from sunpack.contracts.verification import (
    ASSESSMENT_COMPLETE,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    CONTAINER_INTEGRITY_UNKNOWN,
    DECISION_ACCEPT,
)
from sunpack_native import worker_manifest_from_rows


class _FakePasswordStore:
    def has_candidates(self):
        return False


class _FakePasswordResolver:
    password_tester = SimpleNamespace(passwords=[])


class _CandidatePasswordStore:
    def has_candidates(self, **_kwargs):
        return True


class _RecordingPasswordResolver:
    password_tester = SimpleNamespace(passwords=[])

    def __init__(self):
        self.calls = []

    def resolve(self, _archive_path, fact_bag, *, archive_key, **_kwargs):
        knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
        self.calls.append((archive_key, dict(knowledge.get("source.password_probe_input") or {})))
        return PasswordResolution(
            password="",
            status=PasswordResolutionStatus.UNENCRYPTED,
            archive_key=archive_key,
            encrypted=False,
        )


class _FakeRenameScheduler:
    def normalize_archive_paths(self, archive, all_parts, **_kwargs):
        return SimpleNamespace(archive=archive, run_parts=list(all_parts), cleanup_parts=list(all_parts))

    def cleanup_normalized_split_group(self, _staged):
        return None


class _FakeRetryPolicy:
    max_retries = 1

    def can_retry(self, *_args, **_kwargs):
        return False

    def append_retry_count(self, error, _retry_count):
        return error


class _FakeSplitEntryResolver:
    def resolve(self, archive, all_parts, split_info):
        return archive, list(all_parts), split_info


class _FakeSevenZipRunner:
    def __init__(self, *, include_output_counts: bool = True):
        self.sources = []
        self.include_output_counts = bool(include_output_counts)

    def emit_semantic_event(self, _task, _event, **_payload):
        pass

    def extract_attempt(self, *, out_dir, task, **_kwargs):
        state = task.archive_state()
        source = state.to_archive_input_descriptor().to_dict()
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
                "version": 3,
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
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    return ArchiveTask(
        fact_bag=bag,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name="case",
        split_info=SplitArchiveInfo(archive_input=ArchiveInputDescriptor.from_parts(archive_path=str(path))),
    )


def test_extractor_runs_analysis_segments_inside_same_task_and_restores_source(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"prefix-zip-rar-tail")
    task = _task(carrier)
    write_source_extractable_segments(task, [
        {
            "segment_id": "embedded_01_zip",
            "format": "zip",
            "logical_name": "case_01_zip",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "zip",
                "logical_name": "case_01_zip",
                "parts": [{"path": str(carrier), "role": "main", "start": 7, "end": 10}],
            },
        },
        {
            "segment_id": "embedded_02_rar",
            "format": "rar",
            "logical_name": "case_02_rar",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "rar",
                "logical_name": "case_02_rar",
                "parts": [{"path": str(carrier), "role": "main", "start": 11, "end": 14}],
            },
        },
    ])
    runner = _FakeSevenZipRunner()
    extractor = SingleArchiveExtractor(
        seven_z_path="7z",
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
        sevenzip_runner=runner,
        best_effort=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert [source["format_hint"] for source in runner.sources] == ["zip", "rar"]
    assert runner.sources[0]["open_mode"] == "file_range"
    assert (tmp_path / "out" / "embedded_01_zip" / "zip.txt").exists()
    assert (tmp_path / "out" / "embedded_02_rar" / "rar.txt").exists()
    assert len(result.diagnostics["embedded_segments"]) == 2
    assert task.archive_state().to_archive_input_descriptor().open_mode == "file"


def test_embedded_password_probe_and_session_key_follow_active_segment(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"prefix-first-gap-second-tail")
    task = _task(carrier)
    segments = []
    for index, (name, start, end) in enumerate((("first", 7, 12), ("second", 17, 23)), start=1):
        segments.append({
            "segment_id": f"embedded_{index:02d}_zip",
            "format": "zip",
            "logical_name": name,
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "zip",
                "logical_name": name,
                "parts": [{"path": str(carrier), "role": "main", "start": start, "end": end}],
            },
        })
    write_source_extractable_segments(task, segments)
    resolver = _RecordingPasswordResolver()
    extractor = SingleArchiveExtractor(
        seven_z_path="7z",
        password_store=_CandidatePasswordStore(),
        password_resolver=resolver,
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert [key for key, _ in resolver.calls] == [f"{task.key}#first", f"{task.key}#second"]
    assert [call[1]["parts"][0]["start"] for call in resolver.calls] == [7, 17]


def test_verifier_accepts_carrier_when_every_embedded_payload_is_complete(tmp_path):
    carrier = tmp_path / "carrier.exe"
    carrier.write_bytes(b"arbitrary-stub-and-overlay")
    task = _task(carrier)
    write_source_extractable_segments(task, [
        {
            "segment_id": "embedded_01_zip",
            "format": "zip",
            "logical_name": "payload_zip",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "zip",
                "logical_name": "payload_zip",
                "parts": [{"path": str(carrier), "role": "main", "start": 3, "end": 8}],
            },
        },
        {
            "segment_id": "embedded_02_rar",
            "format": "rar",
            "logical_name": "payload_rar",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "rar",
                "logical_name": "payload_rar",
                "parts": [{"path": str(carrier), "role": "main", "start": 12, "end": 20}],
            },
        },
    ])
    extractor = SingleArchiveExtractor(
        seven_z_path="7z",
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
        sevenzip_runner=_FakeSevenZipRunner(),
        best_effort=True,
    )

    extraction = extractor.extract(task, str(tmp_path / "out"))
    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "archive_test_crc"}],
        },
    }).verify(task, extraction)

    assert verification.decision_hint == DECISION_ACCEPT
    assert verification.assessment_status == ASSESSMENT_COMPLETE
    assert verification.content_integrity == CONTENT_INTEGRITY_VERIFIED_COMPLETE
    assert verification.container_integrity == CONTAINER_INTEGRITY_UNKNOWN
    assert verification.archive_coverage.expected_files == 2
    assert verification.archive_coverage.complete_files == 2
    assert verification.decision_hint == DECISION_ACCEPT


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
        seven_z_path="7z",
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
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
    assert task.archive_state().to_archive_input_descriptor().open_mode == "file"


def test_extractor_fills_success_output_counts_when_worker_omits_them(tmp_path):
    archive = tmp_path / "case.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    task = _task(archive)
    runner = _FakeSevenZipRunner(include_output_counts=False)
    extractor = SingleArchiveExtractor(
        seven_z_path="7z",
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
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
    assert result.progress_manifest_payload["files_written"] == 1
    assert result.progress_manifest_payload["bytes_written"] == 2
