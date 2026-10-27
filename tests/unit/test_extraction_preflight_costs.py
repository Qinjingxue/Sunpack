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
        password_store=SimpleNamespace(has_candidates=lambda **_kwargs: False),
        password_resolver=SimpleNamespace(password_tester=SimpleNamespace(passwords=[]), confirm_extraction=lambda *a, **k: None),
        metadata_scanner=SimpleNamespace(scan_for_task=lambda *_args, **_kwargs: SimpleNamespace(selected_codepage=None, error=None)),
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
        password_store=SimpleNamespace(has_candidates=lambda **_kwargs: True),
        password_resolver=Resolver(),
        metadata_scanner=SimpleNamespace(scan_for_task=lambda *_args, **_kwargs: SimpleNamespace(
            selected_codepage=None,
            error=None,
        )),
        sevenzip_runner=SimpleNamespace(
            extract_attempt=lambda **_kwargs: completed,
            emit_semantic_event=lambda *_args, **_kwargs: None,
        ),
    )

    result = extractor.extract(task, str(output))

    assert confirmed == ["secret"]
    assert result.failure.kind == FailureKind.DAMAGED
    assert result.password_used == "secret"


def test_async_preparation_stays_in_broker_and_preserves_logical_inputs_after_failure(tmp_path, monkeypatch):
    # Existing extraction tests cannot catch filesystem work migrating onto the
    # loop. One attempt cycle also checks failure continuation and all input modes
    # at this boundary, without parsing or extracting another archive corpus.
    import asyncio
    import threading
    from dataclasses import replace
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner

    path = str(tmp_path / "disguised.data")
    second = str(tmp_path / "other.data")
    descriptors = [
        ArchiveInputDescriptor(path, format_hint="zip"),
        ArchiveInputDescriptor(path, open_mode="file_range", format_hint="zip",
                               parts=[ArchiveInputPart(InputExtent(path, 17, 200))]),
        ArchiveInputDescriptor(path, open_mode="concat_ranges", format_hint="7z",
                               extents=[InputExtent(path, 17, 200), InputExtent(second, 4, 100)]),
        ArchiveInputDescriptor(path, open_mode="native_volumes", format_hint="7z", volume_style="numeric_suffix",
                               parts=[ArchiveInputPart(InputExtent(member), volume_number=index,
                                                       canonical_name=f"payload.7z.{index:03d}")
                                      for index, member in enumerate([path, second], 1)]),
    ]
    descriptors.append(replace(descriptors[-1], open_mode="sfx_with_volumes"))

    async def scenario():
        loop_thread = threading.get_ident()
        runner = SevenZipRunner({})
        submitted = []
        build = runner._build_job

        def prepare(**request):
            assert threading.get_ident() != loop_thread
            if request["out_dir"].endswith("failed"):
                raise OSError("preparation failed")
            return build(**request)

        async def submit(job, **_context):
            assert threading.get_ident() == loop_thread
            submitted.append(job)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(runner, "_build_job", prepare)
        monkeypatch.setattr(runner, "_submit_native_job_asyncio", submit)
        extractor = object.__new__(SingleArchiveExtractor)
        extractor.sevenzip_runner = runner

        def attempts(*_args, **_kwargs):
            codes = []
            for index, descriptor in enumerate([descriptors[0], *descriptors]):
                task = ArchiveTask.from_archive_input(descriptor, discovery_source="test")
                result = yield {
                    "archive_path": path, "part_paths": descriptor.part_paths(),
                    "out_dir": str(tmp_path / (str(index) if index else "failed")),
                    "password": "secret", "password_candidates": ["wrong", "secret"],
                    "selected_codepage": "932", "startupinfo": None, "task": task,
                }
                codes.append(result.returncode)
            return codes

        extractor._extract_state_machine = attempts
        broker = AsyncWorkBroker(thread_capacity=2)
        try:
            codes = await extractor.extract_asyncio(broker, None, "unused", request_id="audit", file_id=path,
                                                   cancellation=CancellationToken())
            assert codes == [-100, 0, 0, 0, 0, 0]
            assert [job["archive_input"] for job in submitted] == [item.to_dict() for item in descriptors]
            assert all(job["password_candidates"] == ["wrong", "secret"] and job["codepage"] == "932"
                       for job in submitted)
        finally:
            await broker.close()
            await runner.aclose()

    asyncio.run(scenario())
