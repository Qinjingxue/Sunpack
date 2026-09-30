from sunpack.runtime.cli.cli import build_cli_parser
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.core.i18n.context import validate_catalog


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

    assert "执行预检查、扫描、解压和清理" in help_text
    assert "查看或校验 SunPack 有效配置" in help_text
    assert "选项" in help_text
