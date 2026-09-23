import pytest

from sunpack.runtime.cli.cli import build_cli_parser
from sunpack.runtime.cli.cli_context import CliContext


@pytest.mark.parametrize("command", ["extract", "scan", "inspect"])
def test_detection_commands_accept_deep_detect(command):
    parser = build_cli_parser(CliContext(language="en"))

    args = parser.parse_args([command, "--deep-detect", "sample.bin"])

    assert args.deep_detect is True
