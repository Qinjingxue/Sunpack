import sunpack.support.entrypoint as entrypoint
import sunpack.support.resources as resources
from sunpack.support import runtime_identity


def test_entrypoint_consumes_private_runtime_identity_before_cli(monkeypatch):
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\Python310\\python.exe")
    monkeypatch.setattr(
        entrypoint.sys,
        "argv",
        [
            r"C:\\package\\sunpack-runtime.exe",
            "--_sunpack-runtime-id=v2-0123456789abcdef",
            "watch",
            "start",
        ],
    )

    def fake_main():
        assert entrypoint.sys.argv[1:] == ["watch", "start"]
        assert runtime_identity.runtime_id() == "v2-0123456789abcdef"
        return 19

    import sunpack.cli.cli as cli

    monkeypatch.setattr(cli, "main", fake_main)

    assert entrypoint.main() == 19


def test_entrypoint_launches_watch_unelevated_for_installer(tmp_path, monkeypatch):
    runtime = tmp_path / "sunpack-runtime.exe"
    launcher = tmp_path / "sunpack.exe"
    captured = {}

    class FakeProcess:
        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return 0

        def close(self):
            captured["closed"] = True

    import sunpack.platform.windows.process_launch as process_launch
    import sunpack.support.process_executable as process_executable

    monkeypatch.setattr(entrypoint.sys, "argv", [str(runtime), "--launch-watch-unelevated"])
    monkeypatch.setattr(process_executable, "current_process_executable", lambda: runtime)

    def fake_launch(argv, *, cwd=None, env=None):
        captured["argv"] = argv
        captured["cwd"] = cwd
        return FakeProcess()

    monkeypatch.setattr(process_launch, "launch_unelevated", fake_launch)

    assert entrypoint.main() == 0
    assert captured == {
        "argv": [str(launcher), "watch", "start"],
        "cwd": str(tmp_path),
        "timeout": 30.0,
        "closed": True,
    }


def test_shared_runtime_uses_cli_lifecycle(monkeypatch):
    captured = {}
    import sunpack.cli.cli as cli
    import sunpack.cli.persistent_process as persistent_process

    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\package\\sunpack-runtime.exe")
    monkeypatch.setattr(entrypoint.sys, "argv", [r"C:\\package\\sunpack-runtime.exe", "--help"])
    monkeypatch.setattr(persistent_process, "handle_early_argv", lambda argv: captured.setdefault("early", argv) and None)
    monkeypatch.setattr(cli, "main", lambda: 23)

    assert entrypoint.main() == 23
    assert captured == {"early": ["--help"]}
def test_nuitka_resource_lookup_starts_at_the_executable_directory(tmp_path, monkeypatch):
    executable = tmp_path / "sunpack-runtime.exe"
    monkeypatch.setattr(resources, "current_process_executable", lambda: executable.resolve())
    monkeypatch.setattr(resources, "__compiled__", object(), raising=False)

    assert executable.parent.resolve() == resources.candidate_resource_roots()[0]
