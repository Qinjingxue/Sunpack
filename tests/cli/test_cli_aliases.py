import asyncio
import io

import pytest

from sunpack.runtime.cli import cli
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_types import CliCommandResult


@pytest.fixture
def parser():
    return cli.build_cli_parser(CliContext(language="en"))


@pytest.mark.parametrize("short, full", [
    (["e", "."], ["extract", "."]),
    (["s", "."], ["scan", "."]),
    (["pw"], ["passwords"]),
    (["cfg", "show"], ["config", "show"]),
    (["cfg", "validate"], ["config", "validate"]),
    (["ver"], ["version"]),
    (["d"], ["doctor"]),
    (["d", "-j", "-q"], ["doctor", "--json", "--quiet"]),
    (["w", "rm", "D:\\Downloads"], ["watch", "remove", "D:\\Downloads"]),
    (["w", "ls"], ["watch", "list"]),
    (["w", "st"], ["watch", "status"]),
    (["w", "start"], ["watch", "start"]),
    (["w", "start", "--once", "--no-tray"],
     ["watch", "start", "--once", "--no-tray"]),
    (["w", "add", ".", "-o", "out", "-s", "-R"],
     ["watch", "add", ".", "--out-dir", "out", "--start", "--recursive"]),
    (["w", "startup", "status"], ["watch", "startup", "status"]),
])
def test_command_aliases_preserve_handler_inputs(parser, short, full):
    assert vars(parser.parse_args(short)) == vars(parser.parse_args(full))


@pytest.mark.parametrize("short, full", [
    (["-r", "3"], ["--recur", "3"]),
    (["-r", "*"], ["--recur", "*"]),
    (["-r", "?"], ["--recur", "?"]),
    (["-c", "r"], ["--cleanup", "r"]),
    (["-d"], ["--deep-detect"]),
    (["-R"], ["--recursive"]),
    (["-p", "first", "-p", "second"], ["--password", "first", "--password", "second"]),
    (["-P", "pw.txt"], ["--pw-file", "pw.txt"]),
    (["-a"], ["--ask-pw"]),
    (["-f"], ["--flatten"]),
    (["-F"], ["--no-flatten"]),
    (["--no-bpw"], ["--no-builtin-pw"]),
    (["--direct"], ["--direct-file"]),
])
def test_extract_aliases_preserve_handler_inputs(parser, short, full):
    assert vars(parser.parse_args(["e", ".", *short])) == vars(parser.parse_args(["extract", ".", *full]))


def test_scan_recursive_option_alias(parser):
    assert vars(parser.parse_args(["s", ".", "-R"])) == vars(
        parser.parse_args(["scan", ".", "--recursive"])
    )


def test_password_short_options(parser):
    assert vars(parser.parse_args(["pw", "-P", "pw.txt", "-a", "--no-bpw"])) == vars(
        parser.parse_args(["passwords", "--pw-file", "pw.txt", "--ask-pw", "--no-builtin-pw"])
    )


@pytest.mark.parametrize("argv", [
    ["e", ".", "-k"],
    ["e", ".", "--allow-partial"],
    ["e", ".", "--ap"],
    ["e", ".", "--deep"],
    ["i", ".", "--arch"],
    ["pw", "--no-bp"],
    ["w", "start", "--initial"],
    ["w", "add", ".", "--sta"],
    ["cfg", "show", "--qui"],
    ["e", ".", "-f", "-F"],
    ["e", ".", "-m", "h"],
    ["s", ".", "--process-mode", "normal"],
    ["e", ".", "-r", "0"],
    ["e", ".", "-c", "invalid"],
    ["ex", "."],
    ["x", "."],
    ["s", "--json"],
    ["w", "startup", "unknown"],
])
def test_invalid_and_unregistered_abbreviations_are_rejected(parser, argv):
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(argv)
    assert exc.value.code == 2


@pytest.mark.parametrize("command, canonical", [("e", "extract"), ("s", "scan")])
def test_aliases_work_with_command_specific_discovery(command, canonical):
    ctx = CliContext(language="en")
    parser = cli.build_cli_parser(ctx, command=command)
    assert parser.parse_args([command, "."]).command == canonical
    assert set(ctx.commands) == {canonical}


@pytest.mark.parametrize("argv", [
    [], ["extract"], ["e"], ["scan"], ["s"], ["watch"], ["w"],
    ["config"], ["cfg"], ["w", "add"], ["watch", "rm"], ["w", "startup"],
])
def test_missing_required_arguments_defaults_to_help(monkeypatch, tmp_path, argv):
    monkeypatch.setattr(cli, "_should_submit_to_persistent_server", lambda _argv: False)

    def run(args):
        output, error = io.StringIO(), io.StringIO()
        assert asyncio.run(cli.async_main(args, cwd=str(tmp_path), stdout=output, stderr=error)) == 0
        assert not error.getvalue()
        return output.getvalue()

    expected = run([*argv, "-h"])
    assert "-h/--help" in expected
    assert run(argv) == expected


@pytest.mark.parametrize("argv, command, action", [
    (["e", ".", "-j", "-r", "*"], "extract", None),
    (["s", ".", "-j", "-d"], "scan", None),
    (["w", "ls", "-j"], "watch", "list"),
    (["w", "st", "-j"], "watch", "status"),
    (["cfg", "show", "-j"], "config", None),
    (["d", "-j"], "doctor", None),
])
def test_async_entrypoint_dispatches_canonical_commands(monkeypatch, tmp_path, argv, command, action):
    monkeypatch.setattr(cli, "_should_submit_to_persistent_server", lambda _argv: False)
    dispatched = []

    async def dispatch(args, ctx):
        dispatched.append(args)
        return 0, CliCommandResult(command=args.command, inputs={}, summary={})

    monkeypatch.setattr(cli, "dispatch_command", dispatch)
    output = io.StringIO()
    assert asyncio.run(cli.async_main(argv, cwd=str(tmp_path), stdout=output, stderr=io.StringIO())) == 0
    assert dispatched[0].command == command
    if action is not None:
        assert dispatched[0].watch_action == action
    assert f'"command": "{command}"' in output.getvalue()
