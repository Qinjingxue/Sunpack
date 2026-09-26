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
    (["x", "."], ["extract", "."]),
    (["s", "."], ["scan", "."]),
    (["i", "."], ["inspect", "."]),
    (["pw"], ["passwords"]),
    (["cfg", "show"], ["config", "show"]),
    (["cfg", "validate"], ["config", "validate"]),
    (["ver"], ["version"]),
    (["w", "rm", "D:\\Downloads"], ["watch", "remove", "D:\\Downloads"]),
    (["w", "ls"], ["watch", "list"]),
    (["w", "st"], ["watch", "status"]),
    (["w", "start", "-i", "--once", "--no-tray"],
     ["watch", "start", "--initial-scan", "--once", "--no-tray"]),
    (["w", "add", ".", "-o", "out", "-s", "-i"],
     ["watch", "add", ".", "--out-dir", "out", "--start", "--initial-scan"]),
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
    (["-p", "first", "-p", "second"], ["--password", "first", "--password", "second"]),
    (["-P", "pw.txt"], ["--pw-file", "pw.txt"]),
    (["-a"], ["--ask-pw"]),
    (["-f"], ["--flatten"]),
    (["-F"], ["--no-flatten"]),
    (["-k"], ["--allow-partial"]),
    (["--no-bpw"], ["--no-builtin-pw"]),
    (["--no-dpw"], ["--no-dir-pw"]),
    (["--manifest"], ["--write-manifest"]),
    (["--direct"], ["--direct-file"]),
])
def test_extract_aliases_preserve_handler_inputs(parser, short, full):
    assert vars(parser.parse_args(["x", ".", *short])) == vars(parser.parse_args(["extract", ".", *full]))


@pytest.mark.parametrize("command", ["x", "s", "i"])
@pytest.mark.parametrize("short, full", [("b", "background"), ("n", "normal"), ("h", "high")])
def test_priority_values_are_normalized_before_dispatch(parser, command, short, full):
    assert vars(parser.parse_args([command, ".", "-m", short, "-d"])) == vars(
        parser.parse_args([command, ".", "--process-mode", full, "--deep-detect"])
    )


def test_inspect_and_password_short_options(parser):
    assert vars(parser.parse_args(["i", ".", "--archives", "--analysis"])) == vars(
        parser.parse_args(["inspect", ".", "--archives-only", "--analyze"])
    )
    assert vars(parser.parse_args(["pw", "-P", "pw.txt", "-a", "--no-bpw", "--no-dpw"])) == vars(
        parser.parse_args(["passwords", "--pw-file", "pw.txt", "--ask-pw", "--no-builtin-pw", "--no-dir-pw"])
    )


@pytest.mark.parametrize("argv", [
    ["x", ".", "--deep"],
    ["i", ".", "--arch"],
    ["pw", "--no-bp"],
    ["w", "start", "--initial"],
    ["w", "add", ".", "--sta"],
    ["cfg", "show", "--qui"],
    ["x", ".", "-f", "-F"],
    ["x", ".", "-m", "invalid"],
    ["x", ".", "-r", "0"],
    ["x", ".", "-c", "invalid"],
    ["ex", "."],
])
def test_invalid_and_unregistered_abbreviations_are_rejected(parser, argv):
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(argv)
    assert exc.value.code == 2


@pytest.mark.parametrize("command, canonical", [("x", "extract"), ("s", "scan")])
def test_aliases_work_with_command_specific_discovery(command, canonical):
    ctx = CliContext(language="en")
    parser = cli.build_cli_parser(ctx, command=command)
    assert parser.parse_args([command, "."]).command == canonical
    assert set(ctx.commands) == {canonical}


@pytest.mark.parametrize("argv, command, action", [
    (["x", ".", "-j", "-m", "b", "-k", "-r", "*"], "extract", None),
    (["s", ".", "-j", "-d"], "scan", None),
    (["w", "ls", "-j"], "watch", "list"),
    (["w", "st", "-j"], "watch", "status"),
    (["cfg", "show", "-j"], "config", None),
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
