import json
from types import SimpleNamespace

from sunpack.core.contracts.failures import FailureKind
from tests.helpers.archive_tasks import make_archive_task, merge_task_knowledge
from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus


def test_successful_first_attempt_does_not_query_python_free_space(tmp_path):
    archive = tmp_path / "input.7z"
    archive.write_bytes(b"dummy")
    output = tmp_path / "out"
    task = make_archive_task(archive, format_hint="7z")
    runner = SimpleNamespace(
        extract_attempt=lambda **_kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr="", worker_diagnostics={"result": {"status": "ok"}}
        ),
        emit_semantic_event=lambda *_args, **_kwargs: None,
    )
    extractor = SingleArchiveExtractor(
        password_store=SimpleNamespace(has_candidates=lambda: False),
        password_resolver=SimpleNamespace(password_tester=SimpleNamespace(passwords=[])),
        metadata_scanner=SimpleNamespace(scan_for_task=lambda *_args, **_kwargs: SimpleNamespace(selected_codepage=None, decoded_names=[], error=None)),
        retry_policy=SimpleNamespace(max_retries=1),
        sevenzip_runner=runner,
    )
    output.mkdir()

    result = extractor.extract(task, str(output))

    assert result.success


def test_crc_proven_zipcrypto_password_is_confirmed_before_reporting_later_damage(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"dummy")
    output = tmp_path / "out"
    task = merge_task_knowledge(make_archive_task(archive, format_hint="zip"), {"format": {"zip": {"structure": {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    }}}})
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
        retry_policy=SimpleNamespace(
            max_retries=1,
            can_retry=lambda *_args: False,
            append_retry_count=lambda error, *_args: error,
        ),
        sevenzip_runner=SimpleNamespace(
            extract_attempt=lambda **_kwargs: completed,
            emit_semantic_event=lambda *_args, **_kwargs: None,
        ),
    )

    result = extractor.extract(task, str(output))

    assert confirmed == ["secret"]
    assert result.failure.kind == FailureKind.DAMAGED
    assert result.password_used == "secret"
