"""Cross-format regressions that small verifier/worker tests cannot cover.

These exercise orchestration through real archives: password recovery, independent
recursive payloads, and aliased input/output ownership. Tiny payloads keep the
independent end-to-end coverage cheap; existing format tests cover codec details.
"""
import asyncio
import io
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from sunpack.core.contracts.pipeline import PipelineTarget
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine, _PathLeaseRegistry
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from tests.helpers.config_factory import make_config
from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.tool_config import require_7z, get_optional_rar


def _config(**extra):
    return make_config({
        "cli": {"quiet": True},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
        "recursive_extract": 1,
        **extra,
    })


def _encrypted(root, kind):
    source = root / "payload.txt"
    source.write_bytes(b"private payload" * 64)
    archive = root / ("generated." + kind.split("-")[0])
    if kind.startswith("rar"):
        rar = get_optional_rar()
        if rar is None:
            pytest.skip("RAR generator is not configured")
        command = [str(rar), "a", "-ep1", "-idq", "-ma" + kind[3],
                   "-hpsecret" if kind.endswith("headers") else "-psecret", str(archive), str(source)]
    else:
        fmt = "7z" if kind.startswith("7z") else "zip"
        options = (["-mhe=on" if kind.endswith("headers") else "-mhe=off"]
                   if fmt == "7z" else ["-mem=AES256" if kind.endswith("aes") else "-mem=ZipCrypto"])
        command = [str(require_7z()), "a", "-t" + fmt, "-psecret", *options, str(archive), str(source)]
    subprocess.run(command, check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    disguised = root / "ordinary.blob"
    archive.rename(disguised)
    return disguised


@pytest.mark.parametrize("kind", ["7z-data", "7z-headers", "zip-crypto", "zip-aes",
                                      "rar4-data", "rar4-headers", "rar5-data", "rar5-headers", "enc"])
def test_encrypted_inputs_keep_password_failure_and_recover_in_both_origins(tmp_path, kind):
    if kind == "enc":
        archive = tmp_path / "ordinary.blob"
        shutil.copyfile(Path(__file__).resolve().parents[2] / "native/sunpack_enc/tests/data/algorithm_0.mov", archive)
        password = "sunpack-test"
    else:
        archive, password = _encrypted(tmp_path, kind), "secret"

    async def scenario():
        config = _config()
        for origin in ("foreground", "watch"):
            async with PipelineEngine(config) as engine:
                failed = await engine.run([str(archive)], origin=origin)
                assert failed.summary.target_results
                assert all(result.failure and result.failure.is_password_failure
                           for result in failed.summary.target_results)
                recovered = await engine.run([str(archive)], origin=origin,
                    request_config={**config, "user_passwords": ["wrong", password]})
                assert recovered.summary.target_results
                assert all(result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
                           for result in recovered.summary.target_results)
    asyncio.run(scenario())


@pytest.mark.parametrize("locked_kind", ["7z-data", "zip-aes"])
def test_independent_payload_recursion_survives_a_password_blocked_sibling(tmp_path, locked_kind):
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as inner:
        inner.writestr("final.txt", b"independent payload")
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as outer:
        outer.writestr("nested.disguised", content.getvalue())
    locked = _encrypted(tmp_path, locked_kind)

    async def scenario():
        for origin in ("foreground", "watch"):
            carrier = tmp_path / (origin + ".bin")
            assemble_carrier(carrier, [plain, locked])
            events = []
            config = _config(recursive_extract="*", recursive_authorization={"enabled": False},
                             embedded_scan={"enabled": True, "recursive_candidate_ratio": 1e-9})
            async with PipelineEngine(config) as engine:
                response = await engine.run([str(carrier)], origin=origin,
                    detection_options=EmbeddedOptions(force_scan=True),
                    progress_callback=lambda task, event: events.append(event))
            assert response.summary.target_results[0].failure.is_password_failure
            output = tmp_path / origin
            assert [path.read_bytes() for path in output.rglob("final.txt")] == [b"independent payload"]
            assert any(result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
                       for result in response.summary.target_results[1:])
            if origin == "watch":
                assert any(event.get("event") == "task_output_finished" and event.get("keep_output")
                           and event.get("output_dir") == str(output) for event in events)
    asyncio.run(scenario())


def test_aliases_share_leases_deduplicate_inputs_and_reserve_absent_outputs(tmp_path):
    real, alias = tmp_path / "real", tmp_path / "alias"
    real.mkdir()
    first, second = real / "archive.zip", real / "archive.7z"
    for archive in (first, second):
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr(archive.suffix + ".txt", archive.name.encode())
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
        f"New-Item -ItemType Junction -Path '{alias}' -Target '{real}' | Out-Null"],
        check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    async def scenario():
        registry = _PathLeaseRegistry()
        await registry.acquire("first", [first])
        waiting = asyncio.create_task(registry.acquire("alias", [alias / first.name]))
        await asyncio.sleep(0)
        assert not waiting.done()
        await registry.release("first")
        await asyncio.wait_for(waiting, 2)
        await registry.release("alias")
        config = _config()
        async with PipelineEngine(config) as engine:
            response = await engine.run([
                PipelineTarget(str(first), {"root": str(real / "new"), "fixed_root": True}),
                PipelineTarget(str(alias / first.name), {"root": str(alias / "new"), "fixed_root": True}),
                PipelineTarget(str(alias / second.name), {"root": str(alias / "new"), "fixed_root": True}),
            ])
        results = response.summary.target_results
        assert len(results) == 2 and all(r.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for r in results)
        assert len({os.path.realpath(r.output_dir).lower() for r in results}) == 2
        assert sorted(p.read_bytes() for r in results for p in Path(r.output_dir).rglob("*.txt")) == [b"archive.7z", b"archive.zip"]
    try:
        asyncio.run(scenario())
    finally:
        alias.rmdir()
