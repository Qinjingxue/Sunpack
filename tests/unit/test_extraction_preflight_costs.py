import json
from types import SimpleNamespace

from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureKind
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.resource_preflight import ResourcePreflightInspector
from sunpack.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus


def test_successful_first_attempt_does_not_query_python_free_space(tmp_path):
    archive = tmp_path / "input.7z"
    archive.write_bytes(b"dummy")
    output = tmp_path / "out"
    task = ArchiveTask(FactBag(), 1, main_path=str(archive), all_parts=[str(archive)], detected_ext=".7z")
    task.fact_bag.set("archive.encrypted", False)
    runner = SimpleNamespace(
        extract_attempt=lambda **_kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr="", worker_diagnostics={"result": {"status": "ok"}}
        ),
        emit_semantic_event=lambda *_args, **_kwargs: None,
    )
    rename = SimpleNamespace(
        normalize_archive_paths=lambda archive, parts, **_kwargs: SimpleNamespace(archive=archive, run_parts=parts, cleanup_parts=parts),
        cleanup_normalized_split_group=lambda _staged: None,
    )
    extractor = SingleArchiveExtractor(
        seven_z_path="", password_store=SimpleNamespace(has_candidates=lambda: False),
        password_resolver=SimpleNamespace(password_tester=SimpleNamespace(passwords=[])),
        metadata_scanner=SimpleNamespace(scan_for_task=lambda *_args, **_kwargs: SimpleNamespace(selected_codepage=None, decoded_names=[], error=None)),
        rename_scheduler=rename,
        retry_policy=SimpleNamespace(max_retries=1),
        split_entry_resolver=SimpleNamespace(resolve=lambda archive, parts, split: (archive, parts, split)),
        sevenzip_runner=runner,
    )
    output.mkdir()

    result = extractor.extract(task, str(output))

    assert result.success


def test_validated_encrypted_rar_skips_empty_password_resource_analysis(tmp_path, monkeypatch):
    archive = tmp_path / "encrypted.rar"
    archive.write_bytes(b"synthetic-rar4-header")
    task = ArchiveTask(FactBag(), 1, main_path=str(archive), all_parts=[str(archive)], detected_ext=".rar")
    task.fact_bag.set("rar.structure", {
        "plausible": True,
        "strong_accept": True,
        "header_crc_ok": True,
        "header_encrypted": True,
        "password_required": True,
    })

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("encrypted RAR must not be analyzed with an empty password")

    monkeypatch.setattr(
        "sunpack.coordinator.resource_preflight.cached_analyze_archive_resources",
        fail_if_called,
    )

    ResourcePreflightInspector(precise_resource_min_size_mb=0).inspect(task)

    analysis = task.fact_bag.get("resource.analysis")
    assert analysis["is_encrypted"] is True
    assert analysis["message"] == "archive structure requires password resolution"


def test_crc_proven_zipcrypto_password_is_confirmed_before_reporting_later_damage(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"dummy")
    output = tmp_path / "out"
    task = ArchiveTask(FactBag(), 1, main_path=str(archive), all_parts=[str(archive)], detected_ext=".zip")
    task.fact_bag.set("zip.eocd_structure", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    worker_result = {
        "type": "result",
        "status": "failed",
        "operation_result_name": "crc_error",
        "failure_kind": "checksum_error",
        "password_rejected": False,
        "password_crc_proven": True,
        "password_crc_proven_items": 1,
    }
    completed = SimpleNamespace(
        returncode=2,
        stdout=json.dumps(worker_result),
        stderr="",
        worker_diagnostics={"result": worker_result},
    )
    confirmed = []

    class Resolver:
        password_tester = SimpleNamespace(passwords=["secret"])

        def resolve(self, *_args, **_kwargs):
            return PasswordResolution(
                password="secret",
                status=PasswordResolutionStatus.RESOLVED,
                archive_key=task.key,
                requires_extraction_confirmation=True,
                fingerprint_key="fingerprint",
                candidate_evidence="zipcrypto_header_byte",
            )

        def confirm_extraction(self, resolution, password=None):
            confirmed.append(resolution.password)

    extractor = SingleArchiveExtractor(
        seven_z_path="",
        password_store=SimpleNamespace(has_candidates=lambda **_kwargs: True),
        password_resolver=Resolver(),
        metadata_scanner=SimpleNamespace(scan_for_task=lambda *_args, **_kwargs: SimpleNamespace(
            selected_codepage=None,
            decoded_names=[],
            error=None,
        )),
        rename_scheduler=SimpleNamespace(),
        retry_policy=SimpleNamespace(
            max_retries=1,
            can_retry=lambda *_args: False,
            append_retry_count=lambda error, *_args: error,
        ),
        split_entry_resolver=SimpleNamespace(resolve=lambda selected, parts, split: (selected, parts, split)),
        sevenzip_runner=SimpleNamespace(
            extract_attempt=lambda **_kwargs: completed,
            emit_semantic_event=lambda *_args, **_kwargs: None,
        ),
    )

    result = extractor.extract(task, str(output))

    assert confirmed == ["secret"]
    assert result.failure.kind == FailureKind.DAMAGED
    assert result.password_used == "secret"
