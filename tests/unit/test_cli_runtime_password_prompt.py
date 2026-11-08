import asyncio
import io


def test_password_prompt_handles_windows_lines_and_preserves_spaces(monkeypatch, subtests):
    from sunpack.runtime.cli import cli

    monkeypatch.setattr(cli, "runtime_id_available", lambda: False)
    for terminator in ("", "\r", "\r\n"):
        with subtests.test(terminator=repr(terminator)):
            responses = iter(["secret", "crom\r", " secret ", terminator])
            stdout = io.StringIO()

            async def read_request_input(_prompt):
                return next(responses)

            code = asyncio.run(cli.async_main(
                ["passwords", "--ask-pw", "--no-builtin-pw"],
                stdout=stdout,
                stderr=io.StringIO(),
                input_reader=read_request_input,
            ))
            assert code == 0
            assert "['secret', 'crom', ' secret ']" in stdout.getvalue()


def test_password_file_literals_and_async_collection(tmp_path, monkeypatch):
    # Prompt-only tests cannot find changed line semantics, lost ordering, or a
    # synchronous file load on the runtime loop. One small real-file lifecycle
    # covers these together, including a line crossing the native read buffer.
    import threading
    from types import SimpleNamespace
    import sunpack.runtime.cli.cli_runtime as runtime
    from sunpack.core.passwords import read_password_file

    path = tmp_path / "passwords.txt"
    long = "长" * 30000
    text = "\ufeffbom\r\n #literal \rsecret\n\nsecret\vtab\fpage\x1cgroup\x1drecord\x1efile\x85next\u2028line\u2029para\n" + long
    expected = ["\ufeffbom", " #literal ", "secret", "secret", "tab", "page", "group", "record", "file", "next", "line", "para", long]
    path.write_bytes(text.encode("utf-8"))
    assert read_password_file(str(path)) == expected
    calls = []
    original = runtime.read_password_file

    def read(*args):
        calls.append(threading.get_ident())
        return original(*args)

    monkeypatch.setattr(runtime, "read_password_file", read)

    async def scenario():
        loop_thread = threading.get_ident()
        answers = iter(["prompt", "secret", ""])

        async def readline(_prompt):
            return next(answers)

        ctx = SimpleNamespace(cwd=str(tmp_path), work_broker=None, t=lambda key: key, readline=readline, stdout=None)
        args = SimpleNamespace(password=["first", "secret"], password_file=path.name, prompt_passwords=True)
        result = await runtime.collect_cli_passwords_async(args, ctx)
        assert result == list(dict.fromkeys(["first", "secret", *expected, "prompt"]))
        assert calls and all(thread != loop_thread for thread in calls)

    asyncio.run(scenario())
    path.unlink()  # The native reader must release its file/registry ownership.
