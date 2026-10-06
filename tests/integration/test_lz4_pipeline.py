"""Real native LZ4 fixtures through the existing coordinator and CLI paths."""
import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from tests.helpers.detection_config import with_detection_pipeline
from tests.unit.test_lz4_support import ROOT, fixtures, fingerprints  # shared native fixtures


def config_for(tmp_path, fixtures):
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "4", "cli": {"quiet": True},
        "output": {"root": str(tmp_path / "out")},
        "analysis": {"lz4": {"dictionaries": {"123": str(fixtures / "dict.raw")}}},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("name,expected,count", [
    ("frame_7_15.lz4", "expected_standard", 1),
    ("payload.tar.lz4", "expected_tar", 2),
    ("nested.lz4", "expected_standard", 2),
    ("carrier.dat", "expected_concat", 1),
    ("dictionary.lz4", "expected_dictionary", 1),
    ("legacy.lz4", "expected_standard", 1),
])
def test_pipeline_recurses_and_verifies_lz4_in_both_origins(fixtures, tmp_path, origin, name, expected, count):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    source = inputs / ("disguised.photo" if name == "frame_7_15.lz4" else name)
    shutil.copyfile(fixtures / name, source)

    async def run():
        async with PipelineEngine(config_for(tmp_path, fixtures)) as engine:
            return await engine.run([str(source)], origin=origin)

    response = asyncio.run(run())
    results = response.summary.target_results
    assert response.summary.failed_tasks == [], response.summary.failures
    assert response.summary.success_count == count, results
    assert all(r.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for r in results), results
    assert fingerprints(fixtures / expected) <= fingerprints(tmp_path / "out")
    assert source.exists()


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("split", [False, True])
def test_encrypted_outer_archive_and_native_volumes_reuse_nested_lz4(fixtures, tmp_path, origin, split):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    inner = tmp_path / "payload.lz4"
    shutil.copyfile(fixtures / "frame_7_15.lz4", inner)
    subprocess.run([str(ROOT / "tools" / "7z.exe"), "a", "-t7z", "-mx=0", "-psecret", "-mhe=on",
                    *(["-v8k"] if split else []), str(inputs / "outer.7z"), str(inner)],
                   check=True, capture_output=True, timeout=30)
    config = config_for(tmp_path, fixtures)
    config["user_passwords"] = ["wrong", "secret"]

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(inputs)], origin=origin)

    response = asyncio.run(run())
    assert not response.summary.failed_tasks, response.summary.failures
    assert response.summary.success_count == 2, response.summary.target_results
    assert fingerprints(fixtures / "expected_standard") <= fingerprints(tmp_path / "out")


@pytest.mark.parametrize("direct", [False, True])
def test_cli_extract_detects_disguised_lz4_and_returns_verified_success(fixtures, tmp_path, direct):
    source = tmp_path / "photo.photo"
    shutil.copyfile(fixtures / "frame_7_15.lz4", source)
    output = tmp_path / "out"
    result = subprocess.run([sys.executable, "-B", str(ROOT / "sunpack.py"), "extract", "--json",
        *(["--direct-file"] if direct else []), "--out-dir", str(output), "--cleanup", "k", "--recur", "1",
        str(source), "--no-pause"], capture_output=True, text=True, encoding="utf-8", timeout=45,
        creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr + result.stdout
    response = json.loads(result.stdout)
    assert response["summary"]["success_count"] == 1, response
    assert fingerprints(fixtures / "expected_standard") <= fingerprints(output)


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("name", ["dictionary.lz4", "dictionary_zero_id.lz4", "dictionary_zero_id_carrier.dat"])
def test_embedded_dictionary_dependency_is_reported_until_configured(fixtures, tmp_path, origin, name):
    source = tmp_path / name
    shutil.copyfile(fixtures / name, source)
    config = config_for(tmp_path, fixtures)
    config["analysis"]["lz4"]["dictionaries"] = {}
    config["analysis"]["lz4"]["default_dictionary"] = str(fixtures / "dict.raw")
    config["post_extract"]["archive_cleanup_mode"] = "d"

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(source)], origin=origin, detection_options=EmbeddedOptions(force_scan=True))

    response = asyncio.run(run())
    assert response.summary.success_count == 0
    assert response.summary.target_results or response.summary.scan_failures
    if name.endswith(".dat"):
        assert response.summary.scan_failures[0].kind.value == "unknown"
        assert response.summary.scan_failures[0].details["reason"] == "embedded_information_required"
    assert source.exists()


def test_cli_deep_detection_extracts_a_pe_lz4_carrier_without_modifying_it(fixtures, tmp_path):
    source = tmp_path / "carrier.exe"
    shutil.copyfile(fixtures / "carrier.exe", source)
    output = tmp_path / "out"
    result = subprocess.run([sys.executable, "-B", str(ROOT / "sunpack.py"), "extract", "--json",
        "--deep-detect", "--out-dir", str(output), "--cleanup", "k", "--recur", "1",
        str(source), "--no-pause"], capture_output=True, text=True, encoding="utf-8", timeout=45,
        creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["summary"]["success_count"] == 1
    assert fingerprints(fixtures / "expected_concat") <= fingerprints(output)
    assert source.stat().st_size == (fixtures / "carrier.exe").stat().st_size
