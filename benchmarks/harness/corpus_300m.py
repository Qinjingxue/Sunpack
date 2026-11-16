"""Additional archive layouts shared by the three 300 MiB scenarios."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from benchmarks.harness.corpus import GENERATED_FORMATS, RAR, SEVEN_ZIP, ZSTD
from benchmarks.harness.workspace import REPO_ROOT
from tests.helpers.native_fixture import create_lz4_frames, native_fixture
from tests.helpers.tool_config import require_7z_zstd
from tests.real.enc_support import ENC_PASSWORD


RAW_FORMATS = {"gz-raw": "gzip", "bz2-raw": "bzip2", "xz-raw": "xz", "zst-raw": "zstd"}
EXTRA_FORMATS = (*RAW_FORMATS, "zip-split", "zipx", "zipx-zstd", "7z-zstd", "7z-lz4",
                 "rar4", "rar4-split", "lz4", "tar.lz4", "enc")
FORMATS_300M = (*GENERATED_FORMATS, *EXTRA_FORMATS)
TAR_STREAMS = {"gz", "bz2", "xz", "zst", "tgz", "tbz2", "txz", "tzst", "tar.lz4"}


def _run(*command):
    subprocess.run([str(part) for part in command], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def _enc(staging: Path, payload_mib: int) -> Path:
    java, javac = shutil.which("java"), shutil.which("javac")
    jar = REPO_ROOT / "reference/implementations/SSEFilePC/S.S.E. File Encryptor for PC/ssefenc.jar"
    if not java or not javac or not jar.is_file():
        raise FileNotFoundError("ENC fixture requires Java, javac and reference ssefenc.jar")
    classes = staging / "classes"
    classes.mkdir()
    source = REPO_ROOT / "tests/helpers/EncV4Fixtures.java"
    _run(javac, "--release", "17", "-cp", jar, "-d", classes, source)
    _run(java, "-Xmx2g", "-cp", os.pathsep.join((str(classes), str(jar))),
         "EncV4Fixtures", staging / "enc", "0", str(payload_mib))
    return staging / "enc" / "large.enc"


def special_cases(root: Path, corpus, requested, skipped, *, large_files, large_file_mib):
    payload = root / "payloads" / "few-large"
    sources = sorted(payload.glob("*.bin"))
    staging = root / "special"
    staging.mkdir()
    payload_mib = large_files * large_file_mib
    payload_bytes = payload_mib * 1024**2
    volume_bytes = min(16 * 1024**2, max(65536, payload_bytes // 8))
    raw = staging / "stream-payload.bin"
    if requested.intersection(RAW_FORMATS):
        with raw.open("wb") as output:
            for path in sources:
                with path.open("rb") as source:
                    shutil.copyfileobj(source, output, 1024**2)

    cases = {}
    for name in sorted(requested.intersection(EXTRA_FORMATS)):
        password = None
        try:
            if name.startswith("rar4"):
                archive = staging / f"payload-{name}.rar"
                volume_args = [f"-v{volume_bytes}b"] if name.endswith("-split") else []
                _run(RAR, "a", "-idq", "-r", "-ep1", "-ma4", "-y", *volume_args, archive, payload)
                if volume_args:
                    volumes = sorted(staging.glob(f"{archive.stem}.part*.rar"))
                    if len(volumes) < 2:
                        raise RuntimeError("RAR4 fixture did not produce multiple volumes")
                    archive = volumes[0]
            elif name == "zip-split":
                archive = staging / "payload-zip-split.zip"
                _run(SEVEN_ZIP, "a", "-tzip", f"-v{volume_bytes}b", archive, payload)
                volumes = sorted(staging.glob(f"{archive.name}.*"))
                if len(volumes) < 2:
                    raise RuntimeError("ZIP fixture did not produce multiple volumes")
                archive = volumes[0]
            elif name == "zipx":
                archive = staging / "payload.zipx"
                _run(SEVEN_ZIP, "a", "-tzip", "-mm=LZMA", archive, payload)
            elif name == "zipx-zstd":
                archive = staging / "payload-zstd.zipx"
                native_fixture("zip_method", output=str(archive), method=93, paths=list(map(str, sources)))
            elif name in {"7z-lz4", "7z-zstd"}:
                method = name.split("-", 1)[1].upper()
                archive = staging / f"payload-{name}.7z"
                _run(require_7z_zstd(), "a", "-t7z", f"-m0={method}", "-mx=3", "-ms=off", archive, payload)
            elif name in {"lz4", "tar.lz4"}:
                archive = staging / f"payload.{name}"
                tar = corpus.get("few_large:tar")
                if name == "tar.lz4" and not tar:
                    raise FileNotFoundError("TAR fixture is required for tar.lz4")
                create_lz4_frames(archive, sources if name == "lz4" else [Path(tar["path"])])
            elif name in RAW_FORMATS:
                kind = RAW_FORMATS[name]
                archive = staging / f"payload.{name.removesuffix('-raw')}"
                if kind == "zstd":
                    _run(ZSTD, "-q", "-f", "-3", raw, "-o", archive)
                else:
                    _run(SEVEN_ZIP, "a", f"-t{kind}", archive, raw)
            else:
                archive = _enc(staging, payload_mib)
                password = ENC_PASSWORD
            if not archive.is_file():
                raise FileNotFoundError(archive)
            cases[f"few_large:{name}"] = {"path": archive, "format": name, "split": name.endswith("-split"),
                                          "expected_payload_bytes": payload_bytes, "password": password}
        except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
            stderr = (error.stderr or b"").decode("utf-8", "replace").strip() if isinstance(
                error, subprocess.CalledProcessError) else ""
            skipped[name] = f"fixture generator unavailable: {error}" + (f" ({stderr})" if stderr else "")
    return cases
