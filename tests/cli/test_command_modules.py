from sunpack.runtime.cli.cli import build_cli_parser
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.core.i18n.context import validate_catalog
import pytest


def test_sync_command_and_json_output_leave_the_runtime_loop_available(monkeypatch):
    # Existing command tests check values, not shared-loop liveness. Both the
    # blocking handler and serialization must admit callbacks; one tiny request
    # catches the whole class without a timing-sensitive scan benchmark.
    import asyncio
    import io
    import threading
    import contextvars
    from sunpack.runtime.cli import cli
    from sunpack.runtime.cli.commands import scan
    from sunpack.runtime.cli.cli_types import CliCommandResult
    request_context = contextvars.ContextVar("cli_test_request")

    async def scenario():
        request_context.set("this request")
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()

        def check_loop():
            assert threading.get_ident() != loop_thread
            ready = threading.Event()
            loop.call_soon_threadsafe(ready.set)
            assert ready.wait(2), "CLI work blocked the runtime loop"

        def handle(_args, _ctx):
            check_loop()
            assert request_context.get() == "this request"
            return 0, CliCommandResult("scan", {}, {}, items=[{"all_parts": ["路径😀"] * 300}])

        class Output(io.StringIO):
            def write(self, text):
                check_loop()
                return super().write(text)

        monkeypatch.setattr(scan, "handle", handle)
        monkeypatch.setattr(cli, "_should_submit_to_persistent_server", lambda _: False)
        output = Output()
        assert await cli.async_main(["scan", ".", "--json"], stdout=output, stderr=io.StringIO()) == 0
        assert '"all_parts"' in output.getvalue()

    asyncio.run(scenario())


def test_i18n_catalogs_have_matching_keys_and_placeholders():
    validate_catalog()


def test_cli_parser_registers_discovered_commands():
    ctx = CliContext(language="en")
    parser = build_cli_parser(ctx)

    command_args = {
        "extract": ["extract", "."],
        "watch": ["watch", "list"],
        "scan": ["scan", "."],
        "inspect": ["inspect", "."],
        "passwords": ["passwords"],
        "config": ["config", "show"],
        "doctor": ["doctor"],
    }

    for command, args in command_args.items():
        assert parser.parse_args(args).command == command


def test_cli_parser_uses_command_module_language_text():
    ctx = CliContext(language="zh")
    parser = build_cli_parser(ctx)
    help_text = parser.format_help()

    assert "解压压缩包" in help_text
    assert "查看或校验配置" in help_text
    assert "选项" in help_text


def test_command_help_exposes_public_options(subtests, capsys):
    """Cover all command help contracts without launching persistent clients."""
    cases = {
        "scan": ((), ("--min-size",)),
        "inspect": (("--archives-only", "--analyze"), ()),
        "extract": (
            ("--recur", "--cleanup", "--out-dir",
             "--direct-file", "--process-mode"),
            ("--color", "--worker-profile", "--min-size", "--write-manifest", "--manifest"),
        ),
        "watch": (("add", "start", "list", "startup", "rebuild-log"), ("--process-mode",)),
        "passwords": (
            ("--json", "--password"),
            ("--clipboard-pw", "--quiet", "--verbose", "--pause"),
        ),
        "config": (
            ("{show,validate}",),
            ("blacklist", "{show,validate,set", "{show,validate,rule",
             "--verbose", "--pause"),
        ),
    }
    for command, (present, absent) in cases.items():
        with subtests.test(command=command):
            parser = build_cli_parser(CliContext(language="en"), command=command)
            with pytest.raises(SystemExit) as exc:
                parser.parse_args([command, "-h"])
            assert exc.value.code == 0
            help_text = capsys.readouterr().out
            assert all(option in help_text for option in present)
            assert all(option not in help_text for option in absent)
