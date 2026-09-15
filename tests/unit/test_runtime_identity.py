from sunpack.support import runtime_identity


def test_consume_runtime_id_strips_only_the_private_launcher_argument(monkeypatch):
    monkeypatch.setattr(runtime_identity, "_runtime_id", None)

    public = runtime_identity.consume_runtime_id(
        ["--persistent-server", "--_sunpack-runtime-id=v2-0123456789abcdef"]
    )

    assert public == ["--persistent-server"]
    assert runtime_identity.runtime_id() == "v2-0123456789abcdef"


def test_consume_runtime_id_rejects_duplicate_or_malformed_values(monkeypatch):
    monkeypatch.setattr(runtime_identity, "_runtime_id", None)

    for argv in (
        ["--_sunpack-runtime-id=v2-0123456789abcdef", "--_sunpack-runtime-id=v2-fedcba9876543210"],
        ["--_sunpack-runtime-id=short"],
    ):
        try:
            runtime_identity.consume_runtime_id(argv)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed runtime identity was accepted")


def test_runtime_id_argument_is_opaque_and_validated(monkeypatch):
    monkeypatch.setattr(runtime_identity, "_runtime_id", None)
    runtime_identity.set_runtime_id("v2-0123456789abcdef")

    assert runtime_identity.runtime_id_argument() == "--_sunpack-runtime-id=v2-0123456789abcdef"


def test_source_bootstrap_uses_reserved_namespace_without_path_calculation():
    assert runtime_identity.ensure_source_runtime_id(["extract"]) == [
        "extract",
        "--_sunpack-runtime-id=v2-0000000000000000",
    ]


def test_packaged_server_command_reexecutes_runtime_and_forwards_identity(tmp_path, monkeypatch):
    from sunpack.cli import persistent_process

    runtime = tmp_path / "sunpack-runtime.exe"
    monkeypatch.setattr(persistent_process, "is_packaged_process", lambda: True)
    monkeypatch.setattr(persistent_process, "current_process_executable", lambda: runtime)
    monkeypatch.setattr(runtime_identity, "_runtime_id", "v2-0123456789abcdef")

    assert persistent_process.server_command() == [
        str(runtime),
        "--persistent-server",
        "--_sunpack-runtime-id=v2-0123456789abcdef",
    ]
