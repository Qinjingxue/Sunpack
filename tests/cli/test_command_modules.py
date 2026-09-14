from pathlib import Path

from sunpack.cli.cli import build_cli_parser
from sunpack.cli.cli_commands import discover_command_modules
from sunpack.cli.cli_context import CliContext


def test_cli_and_gui_packages_have_explicit_boundaries():
    package_root = Path(__file__).resolve().parents[2] / "sunpack"

    assert (package_root / "cli" / "__init__.py").is_file()
    assert (package_root / "gui" / "__init__.py").is_file()
    assert not (package_root / "app").exists()
from sunpack.i18n.catalog import CATALOG
from sunpack.i18n.context import validate_catalog


def test_i18n_catalogs_have_matching_keys_and_placeholders():
    validate_catalog()


def test_cli_discovers_builtin_command_modules_in_order():
    modules = discover_command_modules()

    assert [module.COMMAND for module in modules] == ["extract", "watch", "scan", "inspect", "passwords", "config", "doctor"]


def test_cli_command_modules_declare_required_contract():
    for module in discover_command_modules():
        assert isinstance(module.COMMAND, str) and module.COMMAND
        assert f"cli.{module.COMMAND}.help" in CATALOG["en"]
        assert f"cli.{module.COMMAND}.help" in CATALOG["zh"]
        assert callable(module.register)
        assert callable(module.handle)


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
