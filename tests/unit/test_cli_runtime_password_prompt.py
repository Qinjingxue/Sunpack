from sunpack.runtime.cli.cli_runtime import prompt_for_passwords


def test_password_prompt_handles_windows_lines_and_preserves_spaces(monkeypatch, subtests):
    for terminator in ("", "\r", "\r\n"):
        with subtests.test(terminator=repr(terminator)):
            responses = iter(["secret", "crom\r", " secret ", terminator])
            monkeypatch.setattr("builtins.input", lambda _prompt: next(responses))
            assert prompt_for_passwords() == ["secret", "crom", " secret "]
