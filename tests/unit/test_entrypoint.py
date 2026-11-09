import sunpack.runtime.entrypoint as entrypoint
import sunpack.core.support.resources as resources
from sunpack.core.support import runtime_identity


def test_entrypoint_consumes_private_runtime_identity_before_forwarding(monkeypatch):
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

    def submit(argv):
        assert argv == ["watch", "start"]
        assert entrypoint.sys.argv[1:] == ["watch", "start"]
        assert runtime_identity.runtime_id() == "v2-0123456789abcdef"
        return 19

    from sunpack.runtime.cli import persistent_process

    monkeypatch.setattr(persistent_process, "submit_request", submit)

    assert entrypoint.main() == 19


def test_shared_runtime_uses_cli_lifecycle(monkeypatch):
    captured = {}
    import sunpack.runtime.cli.cli as cli
    import sunpack.runtime.cli.persistent_process as persistent_process

    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\\package\\sunpack-runtime.exe")
    monkeypatch.setattr(entrypoint.sys, "argv", [r"C:\\package\\sunpack-runtime.exe", "--help"])
    monkeypatch.setattr(persistent_process, "handle_early_argv", lambda argv: captured.setdefault("early", argv) and None)
    monkeypatch.setattr(cli, "main", lambda: 23)

    assert entrypoint.main() == 23
    assert captured == {"early": ["--help"]}
def test_nuitka_resource_lookup_starts_at_the_executable_directory(tmp_path, monkeypatch):
    from sunpack.core.support import process_executable

    executable = tmp_path / "sunpack-runtime.exe"
    monkeypatch.setattr(resources, "current_process_executable", lambda: executable.resolve())
    monkeypatch.setattr(process_executable, "__compiled__", object(), raising=False)

    assert executable.parent.resolve() == resources.candidate_resource_roots()[0]
