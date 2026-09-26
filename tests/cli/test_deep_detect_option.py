import pytest

from sunpack.runtime.cli.cli import build_cli_parser
from sunpack.runtime.cli.cli_context import CliContext


@pytest.mark.parametrize("command", ["extract", "scan", "inspect"])
def test_detection_commands_accept_deep_detect(command):
    parser = build_cli_parser(CliContext(language="en"))

    args = parser.parse_args([command, "--deep-detect", "sample.bin"])

    assert args.deep_detect is True


def test_watch_add_accepts_deep_detect_and_leaves_omission_unspecified():
    parser = build_cli_parser(CliContext(language="en"))

    deep = parser.parse_args(["watch", "add", "sample", "--deep-detect"])
    ordinary = parser.parse_args(["watch", "add", "sample"])

    assert deep.deep_detect is True
    assert ordinary.deep_detect is None
