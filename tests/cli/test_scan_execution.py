"""One real shared-chain run covers scan's read-only and sparse-fact contract.

Discovery-only tests cannot catch accidental extraction/cleanup or candidate
passwords being published as confirmed. Tiny archives cover both cheaply.
"""
import asyncio
import io
import zipfile
from pathlib import Path

import pytest

from sunpack.runtime.cli.cli import build_cli_parser
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.commands import extract, scan
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import create_encrypted_zip_archive, create_encrypted_7z_archive


@pytest.mark.parametrize("json_mode, password", [(False, None), (False, "found-password"), (True, "found-password")])
def test_scan_shared_execution_preserves_sources_and_per_segment_passwords(tmp_path, monkeypatch, json_mode, password):
    secret = create_encrypted_zip_archive(tmp_path, "secret", password="found-password")
    hidden = create_encrypted_7z_archive(tmp_path, "hidden", password="unlisted-password")
    source = tmp_path / "inputs"
    source.mkdir()
    plain = io.BytesIO()
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("nested.zip", b"not an archive")
    prefix = b"carrier prefix" * 19
    middle = b"gap" * 17
    payload = secret.entry_path.read_bytes()
    (source / "mixed.jpg").write_bytes(prefix + plain.getvalue() + middle + payload + b"tail" * 23)
    (source / "ordinary.disguised").write_bytes(plain.getvalue())
    (source / "unknown-password.blob").write_bytes(hidden.entry_path.read_bytes())
    before = {path: path.read_bytes() for path in source.iterdir()}
    output = tmp_path / "must-not-exist"
    config = make_config({"output": {"root": str(output)}, "post_extract": {"archive_cleanup_mode": "d"}})
    monkeypatch.setattr(extract, "load_request_config", lambda _cwd: config)
    monkeypatch.setattr(extract, "pipeline_engine", PipelineEngine)
    def unexpected_prompt(prompt):
        pytest.fail(f"Scan must report unknown passwords without a retry prompt: {prompt}")

    ctx = CliContext(language="en", cwd=str(tmp_path), stdout=io.StringIO(), stderr=io.StringIO(),
                     input_reader=unexpected_prompt)
    ctx.reporter = CliReporter(json_mode=json_mode, stdout=ctx.stdout, stderr=ctx.stderr)
    args = build_cli_parser(ctx, command="scan").parse_args([
        "scan", str(source), "--deep-detect", "--no-builtin-pw",
        *(["-p", password] if password else []),
        *(["--json"] if json_mode else []),
    ])
    code, result = asyncio.run(scan.handle(args, ctx))
    assert code != 0  # Known encryption, but no matching password for hidden.
    assert not output.exists()
    assert {path: path.read_bytes() for path in source.iterdir()} == before
    items = result.items
    mixed = [item for item in items if Path(item["main_path"]).name == "mixed.jpg"]
    assert len(mixed) == 2, items
    assert mixed[0]["offset"] == len(prefix)
    assert "password_used" not in mixed[0]
    assert mixed[1]["password_used"] == password, mixed[1]
    ordinary = next(item for item in items if Path(item["main_path"]).name == "ordinary.disguised")
    assert "offset" not in ordinary and "password_used" not in ordinary
    unknown = next(item for item in items if Path(item["main_path"]).name == "unknown-password.blob")
    assert unknown["password_used"] is None and "all_parts" not in unknown
    assert all("status" not in item and "discovery_source" not in item for item in items)
    if not json_mode:
        assert all(str(path) in ctx.stdout.getvalue() for path in before)
        assert ctx.t("cli.scan.password", password=ctx.t("cli.scan.password_unknown")) in ctx.stdout.getvalue()
        assert not ctx.stderr.getvalue()


def test_scan_retains_volume_domains_and_never_confirms_empty_zipcrypto(tmp_path):
    # Ordinary scan fixtures cannot catch speculative composition selection or
    # weak empty-entry proof being cached as a confirmed password.
    import subprocess
    from sunpack_native import encode_worker_frame
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
    from sunpack.core.passwords.internal.store import PasswordStore
    from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
    from tests.helpers.async_batch import run_extract
    from tests.helpers.native_build import sevenzip_artifact
    from tests.helpers.tool_config import require_7z
    from tests.helpers.worker_events import worker_events
    from tests.integration.test_volume_attempts import _ambiguous_case

    case, paths, config, task = _ambiguous_case(tmp_path, "7z", "found-password", True)
    before = tuple(node.descriptor for node in task.inputs)
    contents = {path: path.read_bytes() for path in paths}
    output = tmp_path / "scan-output"
    extractor = ExtractionScheduler(password_store=PasswordStore.from_config(config),
                                    extraction_config={"operation": "scan"})
    result = run_extract(extractor, task, str(output))
    assert tuple(node.descriptor for node in task.inputs) == before
    assert not output.exists() and {path: path.read_bytes() for path in paths} == contents
    from sunpack.pipeline.coordinator.scan_projection import scan_items
    from sunpack.core.i18n import I18nContext
    receipts = list(scan_items(task, result, I18nContext("en")))
    assert receipts and all(item["volume_completeness"] == "pending" for item in receipts)
    assert all("volume_attempts" in item for item in receipts)
    # The conflicting layouts share one candidate line. Fixed slots are
    # irrelevant to the text, while the full plan is available in JSON.
    ctx = CliContext(language="en")
    details = list(scan._details(receipts[0], ctx))
    assert details == [
        "Format: 7z",
        "Volume candidates (2, 3): shared.build02.chunk03.opaque[0, 49152), shared.build03.chunk02.opaque[0, 49152)",
        ctx.t("cli.scan.volumes", state=ctx.t("cli.scan.volumes.pending")),
        ctx.t("cli.scan.source", source=receipts[0]["discovery_source"]),
    ]

    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    archive = tmp_path / "empty.zip"
    subprocess.run([str(require_7z()), "a", "-tzip", "-mem=ZipCrypto", "-psecret",
                    str(archive), str(empty)], check=True, capture_output=True)
    request = {"job_id": "empty-scan", "operation": "scan", "password_candidates": ["secret"],
               "archive_input": ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip").to_dict(),
               "output_dir": str(output)}
    run = subprocess.run([str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))],
                         input=encode_worker_frame(request), capture_output=True)
    final = next(event for event in worker_events(run.stdout) if event.get("type") == "result")
    assert not final["password_verified"], final
    assert final["encrypted"] and final["status"] == "failed", final
    assert not output.exists()


def test_scan_shows_movable_tail_at_its_possible_positions():
    # The shorter layout borrows the terminal domain for an earlier slot.
    from sunpack.core.contracts.archive_input import InputExtent, VolumeAttemptPlan, VolumeAttemptSlot

    plan = VolumeAttemptPlan(
        sources=tuple(InputExtent(name) for name in ("head", "middle", "tail")),
        layouts=(tuple(VolumeAttemptSlot(i, name, (i - 1,))
                       for i, name in enumerate(("head", "middle", "tail"), 1)),),
        minimum_slots=(2,),
    )
    assert list(scan._details({"volume_attempts": plan.to_dict()}, CliContext(language="en"))) == [
        "Volume candidates (2): middle, tail",
        "Volume candidates (3, may be absent): tail",
        "Volume count range: 2–3",
    ]


def test_scan_confirms_enc_password_with_damaged_recovery_framing(tmp_path, monkeypatch):
    from sunpack.pipeline.extraction.internal.sevenzip import sevenzip_runner
    from tests.helpers.native_build import sevenzip_artifact
    from tests.unit.test_enc_support import DATA

    source = tmp_path / "damaged.blob"
    content = bytearray((DATA / "recovery.enc").read_bytes())
    content[-120] ^= 1  # Same recovery trailer mutation as the Rust decoder test.
    source.write_bytes(content)
    output = tmp_path / "must-not-exist"
    monkeypatch.setattr(sevenzip_runner, "get_sevenzip_bridge_worker_path",
                        lambda: str(sevenzip_artifact("sunpack_sevenzip_worker.exe")))
    monkeypatch.setattr(extract, "load_request_config",
                        lambda _cwd: make_config({"output": {"root": str(output)}}))
    monkeypatch.setattr(extract, "pipeline_engine", PipelineEngine)

    for password, expected in (("sunpack-test", "sunpack-test"), ("wrong", None)):
        ctx = CliContext(language="en", cwd=str(tmp_path), stdout=io.StringIO(), stderr=io.StringIO())
        ctx.reporter = CliReporter(json_mode=True, stdout=ctx.stdout, stderr=ctx.stderr)
        args = build_cli_parser(ctx, command="scan").parse_args(
            ["scan", str(source), "--json", "--no-builtin-pw", "-p", password],
        )
        code, result = asyncio.run(scan.handle(args, ctx))
        assert (code == 0) == (expected is not None)
        [item] = result.items
        assert item["format"] == "enc" and item["password_used"] == expected
    assert not output.exists() and source.read_bytes() == content


@pytest.mark.parametrize("language, password_label", [("en", "Password: not in password list"), ("zh", "密码：未在密码表中")])
def test_sparse_scan_facts_stay_with_their_physical_segment(tmp_path, language, password_label):
    # Real happy-path archives miss distinct blocked segments, different source
    # files within one task, and verbose/JSON/quiet projection combinations.
    from types import SimpleNamespace
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.input_plan import LogicalArchiveInput
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
    from sunpack.core.contracts.failures import FailureInfo, FailureKind
    from sunpack.core.contracts.results import RunSummary, TargetRunResult, OutcomeKind
    from sunpack.core.i18n import I18nContext
    from sunpack.pipeline.coordinator.scan_projection import scan_items

    # Rust's password resolver can produce MISSING_VOLUME without a second
    # "confirmed" flag. It overrides the discovery-time structural conclusion.
    from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus
    from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor

    missing = SingleArchiveExtractor(None, None)._password_resolution_failure(
        PasswordResolution(None, PasswordResolutionStatus.MISSING_VOLUME),
    )
    password = FailureInfo(FailureKind.PASSWORD_REQUIRED, "embedded", "need password")
    damaged = FailureInfo(FailureKind.DAMAGED, "embedded", "damaged encrypted input")
    nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
        str(tmp_path / name), format_hint="rar", open_mode="file_range",
        parts=[ArchiveInputPart(InputExtent(str(tmp_path / name), start, end))],
        analysis={"volume_completeness": "complete"} if end is not None else {"password_required": True},
    ), position=i) for i, (name, start, end) in enumerate((
        ("first.bin", 0, 64), ("second.bin", 128, None), ("third.bin", 256, None)), 1))
    task = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="embedded", logical_inputs=nodes)
    result = ExtractionResult(False, "", failure=missing, input_results=[
        InputExecutionResult(node, ExtractionResult(False, "", failure=failure))
        for node, failure in zip(nodes, (missing, password, damaged))])
    items = tuple(scan_items(task, result, I18nContext(language)))
    assert items[0]["main_path"].endswith("first.bin") and items[0]["offset"] == 0
    assert items[0]["volume_completeness"] == "missing" and "password_used" not in items[0]
    assert items[1]["main_path"].endswith("second.bin") and items[1]["end_offset"] is None
    assert items[1]["password_used"] is None and "all_parts" not in items[1]
    assert items[0]["error"] != items[1]["error"]
    assert items[1]["error_kind"] == "password_required"
    assert items[2]["password_used"] is None and items[2]["error_kind"] == "damaged"
    declared_missing = ArchiveInputDescriptor(
        entry_path=str(tmp_path / "partial.bin"), analysis={"volume_completeness": "missing"},
    )
    task_with_gap = ArchiveTask.from_archive_input(declared_missing, discovery_source="relations")
    [gap] = scan_items(task_with_gap, ExtractionResult(True, ""), I18nContext("en"))
    assert gap["volume_completeness"] == "missing"
    for json_mode, verbose, quiet in ((True, False, False), (True, True, False), (False, False, True), (False, True, False)):
        out, err = io.StringIO(), io.StringIO()
        ctx = CliContext(language=language, reporter=CliReporter(json_mode=json_mode, quiet=quiet,
                         verbose=verbose, stdout=out, stderr=err))
        summary = RunSummary(target_results=(TargetRunResult(task.main_path, OutcomeKind.FAILURE,
                          failure=missing, error=missing.message, scan_items=tuple(dict(i) for i in items)),))
        _, projected = scan.command_result(SimpleNamespace(json=json_mode, verbose=verbose, quiet=quiet,
                                     deep_detect=False), ctx, [task.main_path], summary)
        assert all(("discovery_source" in item) == verbose for item in projected.items)
        if quiet:
            assert not out.getvalue() and "need password" in err.getvalue()
            assert items[0]["error"] in err.getvalue()
            assert items[2]["main_path"] in err.getvalue()
        elif not json_mode:
            assert out.getvalue().index("first.bin") < out.getvalue().index("second.bin")
            assert "need password" not in err.getvalue() and "need password" not in out.getvalue()
            assert password_label in out.getvalue()
            assert ctx.t("cli.scan.parts", parts="first.bin") in out.getvalue()
            assert ctx.t("cli.scan.volumes", state=ctx.t("cli.scan.volumes.missing")) in out.getvalue()
            assert err.getvalue() == (f"{items[2]['main_path']}: [256, ?): "
                                     + ctx.t("cli.scan.error", error=damaged.message) + "\n")
        if not json_mode:
            assert damaged.message in err.getvalue()
        else:
            assert projected.items[1]["error"] == "need password"


@pytest.mark.parametrize("encoding, first, last, continuation", [
    ("utf-8", "├─ ", "└─ ", "│    "),
    ("cp1252", "+---", "\\---", "|     "),
])
def test_scan_keeps_unicode_carrier_segments_together(tmp_path, encoding, first, last, continuation):
    from types import SimpleNamespace
    from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult

    carrier = str(tmp_path / "Straße.bin")
    other = str(tmp_path / "STRASSE.bin")  # Same Python casefold, different Windows path key.
    items = tuple(dict(main_path=path, offset=offset, end_offset=offset + 10)
                  for path, offset in ((carrier, 10), (other, 20), (carrier, 30)))
    items[0].update(error="missing part", error_kind="missing_volume", volume_completeness="missing")
    items[2].update(error="damaged segment", error_kind="damaged")
    summary = RunSummary(target_results=(
        TargetRunResult(carrier, OutcomeKind.SCANNED, scan_items=items),
    ))
    output, err = io.BytesIO(), io.StringIO()
    out = io.TextIOWrapper(output, encoding=encoding)
    ctx = CliContext(language="en", reporter=CliReporter(stdout=out, stderr=err))
    scan.command_result(SimpleNamespace(json=False, verbose=False, deep_detect=False), ctx, [carrier], summary)
    out.flush()
    text = output.getvalue().decode(encoding)
    assert text.count(carrier) == text.count(other) == 1
    assert first + "Segment 1: [10, 20)" in text.splitlines()
    assert last + "Segment 2: [30, 40)" in text.splitlines()
    assert continuation + "Volumes: incomplete" in text.splitlines()
    assert err.getvalue() == f"{carrier}: [30, 40): Error: damaged segment\n"


def test_rar_boundary_batch_preserves_later_success_and_truncated_password(tmp_path):
    # A first failed header previously terminated the batch and assigned its
    # error to every later segment. Real encrypted headers also check that a
    # confirmed password survives a later missing terminator.
    from sunpack_native import resolve_embedded_rar_boundaries
    from tests.unit.test_rar_7z_fast_verifier import _rar5_encryption_header_fixture
    from tests.unit.test_rar_hp_header_decryption import SINGLE_HP_HEX
    complete = bytes.fromhex(SINGLE_HP_HEX)
    first = _rar5_encryption_header_fixture()
    prefix, gap = b"prefix" * 7, b"gap" * 11
    offsets = [len(prefix), len(prefix) + len(first) + len(gap)]
    offsets.append(offsets[-1] + len(complete) + len(gap))
    path = tmp_path / "mixed.rar.carrier"
    path.write_bytes(prefix + first + gap + complete + gap + complete[:-20])
    rows = resolve_embedded_rar_boundaries(str(path), offsets, ["secret"])
    assert [row["offset"] for row in rows] == offsets
    assert [row["status"] for row in rows] == ["wrong_password", "ok", "truncated"]
    assert "password" not in rows[0]
    assert rows[1]["password"] == rows[2]["password"] == "secret"
    assert rows[1]["end_offset"] == offsets[1] + len(complete)
    assert "end_offset" not in rows[2]
