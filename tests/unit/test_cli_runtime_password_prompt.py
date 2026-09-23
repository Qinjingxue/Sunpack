from sunpack.runtime.cli.cli_runtime import prompt_for_passwords


def test_password_prompt_stops_on_empty_line(monkeypatch):
    responses = iter(["secret", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(responses))

    assert prompt_for_passwords() == ["secret"]


def test_password_prompt_treats_windows_carriage_return_as_empty_line(monkeypatch):
    responses = iter(["secret", "\r"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(responses))

    assert prompt_for_passwords() == ["secret"]


def test_password_prompt_removes_windows_carriage_return_from_password(monkeypatch):
    responses = iter(["crom\r", "\r"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(responses))

    assert prompt_for_passwords() == ["crom"]


def test_password_prompt_preserves_password_whitespace(monkeypatch):
    responses = iter([" secret ", "\r\n"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(responses))

    assert prompt_for_passwords() == [" secret "]
