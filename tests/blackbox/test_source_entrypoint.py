"""Source runtime uses the built native launcher, without package staging."""
import json
import shutil
import subprocess
import zipfile

import psutil

from tests.helpers.native_build import native_build_dir, rust_build_dir, selected_build


def test_source_runtime_watch_and_native_launcher_share_checkout_root(package, repo_root, tmp_path):
    arch, profile = selected_build()
    checkout = tmp_path / "source checkout"
    runtime = rust_build_dir(checkout, arch, profile) / "sunpack-runtime.exe"
    build = native_build_dir(checkout, arch, profile, "sevenzip_bridge")
    original_build = native_build_dir(repo_root, arch, profile, "sevenzip_bridge")
    launcher = build / "sunpack_launcher.exe"
    for source, destination in (
        (rust_build_dir(repo_root, arch, profile) / runtime.name, runtime),
        (original_build / launcher.name, launcher),
        (original_build / "sunpack_sevenzip_worker.exe", build / "sunpack_sevenzip_worker.exe"),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    (checkout / "sunpack").mkdir()
    (checkout / "sunpack" / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    # The ordinary config alone is sufficient, even in a development build.
    (checkout / "sunpack_config.json").write_text('{"cli":{"language":"en"},"performance":{"persistent_server_idle_seconds":60}}', encoding="utf-8")
    (checkout / "builtin_passwords.json").write_text('{"passwords":[]}', encoding="utf-8")
    observed = checkout / "input"
    observed.mkdir()
    (checkout / "sunpack_watch_roots.txt").write_text(str(observed) + "\n", encoding="utf-8")
    # A caller in another valid checkout must not redirect runtime resources,
    # writable state, watch roots, or launcher selection away from its binary.
    caller = tmp_path / "other checkout"
    (caller / "sunpack").mkdir(parents=True)
    (caller / "sunpack" / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (caller / "sunpack_config.json").write_text('{"cli":{"language":"zh"}}', encoding="utf-8")
    (caller / "sunpack_watch_roots.txt").write_text("", encoding="utf-8")
    owner = None
    try:
        for entry in (runtime, launcher):
            result = subprocess.run([str(entry), "watch", "list", "-j"], cwd=caller,
                                    env=package.env, capture_output=True, text=True, encoding="utf-8", timeout=30)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["summary"]["count"] == 1
        states = list(checkout.glob("runtime-*.state"))
        assert len(states) == 1
        first_state = states[0].read_text(encoding="utf-8")
        owner = psutil.Process(int(first_state.splitlines()[3]))
        repeated = subprocess.run([str(launcher), "watch", "list", "-j"], cwd=caller,
                                  env=package.env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        assert repeated.returncode == 0, repeated.stderr
        assert json.loads(repeated.stdout)["summary"]["count"] == 1
        assert states[0].read_text(encoding="utf-8") == first_state
        assert not runtime.with_name("sunpack.exe").exists()
        archive = tmp_path / "probe.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("probe.txt", b"source worker")
        extracted = tmp_path / "extracted"
        result = subprocess.run([str(launcher), "extract", str(archive), "-c", "k",
                                 "-o", str(extracted), "-j"], cwd=caller,
                                env=package.env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert (extracted / "probe" / "probe.txt").read_bytes() == b"source worker"
    finally:
        shutdown = subprocess.run([str(launcher), "--persistent-shutdown"], cwd=caller, env=package.env,
                                  capture_output=True, timeout=30)
        if owner is not None:
            owner.wait(timeout=10)
    assert shutdown.returncode == 0, shutdown.stderr
    assert not list(checkout.glob("runtime-*.state"))
