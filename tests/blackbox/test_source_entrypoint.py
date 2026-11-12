"""Source runtime uses the built native launcher, without package staging."""
import json
import os
import shutil
import subprocess


def test_source_runtime_watch_and_native_launcher_share_checkout_root(package, repo_root, tmp_path):
    arch = os.environ.get("SUNPACK_TEST_ARCH", "x64")
    profile = os.environ.get("SUNPACK_TEST_BUILD_PROFILE", "ci")
    target = {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}[arch]
    suffix = "-ci" if profile == "ci" else ""
    checkout = tmp_path / "source checkout"
    runtime = checkout / ".cache" / "rust-target" / arch / target / profile / "sunpack-runtime.exe"
    launcher = checkout / "native" / "sevenzip_bridge" / f"build-{arch}{suffix}" / "Release" / "sunpack_launcher.exe"
    for source, destination in (
        (repo_root / ".cache" / "rust-target" / arch / target / profile / runtime.name, runtime),
        (repo_root / "native" / "sevenzip_bridge" / f"build-{arch}{suffix}" / "Release" / launcher.name, launcher),
        (repo_root / "sunpack_advanced_config.json", checkout / "sunpack_advanced_config.json"),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    (checkout / "native" / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (checkout / "sunpack_config.json").write_text('{"cli":{"language":"en"}}', encoding="utf-8")
    (checkout / "builtin_passwords.json").write_text('{"passwords":[]}', encoding="utf-8")
    observed = checkout / "input"
    observed.mkdir()
    (checkout / "sunpack_watch_roots.txt").write_text(str(observed) + "\n", encoding="utf-8")
    caller = tmp_path / "unrelated cwd"
    caller.mkdir()
    try:
        for entry in (runtime, launcher):
            result = subprocess.run([str(entry), "watch", "list", "--json"], cwd=caller,
                                    env=package.env, capture_output=True, text=True, encoding="utf-8", timeout=30)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["summary"]["count"] == 1
        assert not runtime.with_name("sunpack.exe").exists()
    finally:
        subprocess.run([str(launcher), "--persistent-shutdown"], cwd=caller, env=package.env,
                       capture_output=True, timeout=30)
