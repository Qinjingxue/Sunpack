"""Build and invoke opt-in probes that reuse the Rust runtime from a test build."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from benchmarks.harness.workspace import REPO_ROOT


def build_runtime_probe(profile: str, arch: str) -> Path:
    target = {"x64": "x86_64", "arm64": "aarch64"}[arch] + "-pc-windows-msvc"
    build = subprocess.run(
        ["cargo", "test", "--locked", "--manifest-path", str(REPO_ROOT / "sunpack/Cargo.toml"),
         "-p", "sunpack-runtime", "--target", target, "--profile", profile,
         "--bin", "sunpack-runtime", "--no-run", "--message-format=json"],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, encoding="utf-8",
    )
    executable = None
    for line in build.stdout.splitlines():
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        if (event["reason"] == "compiler-artifact" and event["target"]["name"] == "sunpack-runtime"
                and event["profile"]["test"] and event.get("executable")):
            executable = Path(event["executable"])
        elif event["reason"] == "compiler-message":
            rendered = event["message"].get("rendered")
            if rendered:
                print(rendered, end="")
    build.check_returncode()
    if executable is not None:
        return executable
    raise RuntimeError("Cargo did not report the runtime test executable")


def run_runtime_probe(executable, test, request, *, env=None):
    command = [str(executable), "--ignored", "--exact", "--nocapture", test]
    completed = subprocess.run(command, cwd=REPO_ROOT, input=json.dumps(request),
                               capture_output=True, encoding="utf-8", env=env)
    for line in completed.stdout.splitlines():
        if completed.returncode == 0 and line.startswith("SUNPACK_BENCH "):
            return json.loads(line.removeprefix("SUNPACK_BENCH "))
    raise RuntimeError(f"Rust benchmark {test} failed ({completed.returncode}):\n"
                       f"{completed.stdout}{completed.stderr}")
