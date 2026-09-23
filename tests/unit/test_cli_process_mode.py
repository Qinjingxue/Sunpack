from sunpack.runtime.cli.cli import build_cli_parser
from sunpack.runtime.cli.cli_context import CliContext


def test_workload_process_mode_defaults_to_high():
    cases = (
        ("extract", ["extract", "sample.zip"]),
        ("scan", ["scan", "."]),
        ("inspect", ["inspect", "."]),
    )
    for command, argv in cases:
        args = build_cli_parser(CliContext(language="en"), command=command).parse_args(argv)
        assert args.process_mode == "high"


def test_workload_process_mode_accepts_explicit_override():
    parser = build_cli_parser(CliContext(language="en"), command="extract")
    args = parser.parse_args(["extract", "--process-mode", "normal", "sample.zip"])
    assert args.process_mode == "normal"
