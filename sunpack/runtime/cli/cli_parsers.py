import argparse

from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_values import parse_archive_cleanup_value, parse_process_mode_value, parse_recursive_extract_value
from sunpack.core.i18n import I18nContext


class CliHelpFormatter(argparse.RawDescriptionHelpFormatter):
    language = "en"

    def __init__(self, prog: str):
        super().__init__(prog, max_help_position=44, width=120)

    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None and self.language == "zh":
            prefix = I18nContext(self.language).t("cli.usage_prefix")
        return super().add_usage(usage, actions, groups, prefix)

    def start_section(self, heading):
        if self.language == "zh":
            i18n = I18nContext(self.language)
            heading = {
                "positional arguments": i18n.t("cli.positional_arguments"),
                "options": i18n.t("cli.options"),
            }.get(heading, heading)
        return super().start_section(heading)


def localize_help_action(parser: argparse.ArgumentParser, ctx: CliContext):
    if ctx.language != "zh":
        return
    for action in parser._actions:
        if "-h" in getattr(action, "option_strings", []):
            action.help = ctx.t("cli.help")


def build_common_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-j", "--json", action="store_true", help=ctx.t("cli.json"))
    parser.add_argument("-q", "--quiet", action="store_true", help=ctx.t("cli.quiet"))
    parser.add_argument("-v", "--verbose", action="store_true", help=ctx.t("cli.verbose"))
    pause_group = parser.add_mutually_exclusive_group()
    pause_group.add_argument("--no-pause", action="store_true", help=ctx.t("cli.no_pause"))
    pause_group.add_argument("--pause", dest="pause_on_exit", action="store_true", help=ctx.t("cli.pause"))
    return parser


def build_json_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-j", "--json", action="store_true", help=ctx.t("cli.json"))
    return parser


def build_config_output_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = build_json_parser(ctx)
    parser.add_argument("-q", "--quiet", action="store_true", help=ctx.t("cli.quiet"))
    return parser


def build_password_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", "--password", action="append", default=[], help=ctx.t("cli.password"))
    parser.add_argument("-P", "--pw-file", dest="password_file", help=ctx.t("cli.password_file"))
    parser.add_argument("-a", "--ask-pw", dest="prompt_passwords", action="store_true", help=ctx.t("cli.prompt_passwords"))
    parser.add_argument("--no-builtin-pw", "--no-bpw", dest="no_builtin_passwords", action="store_true", help=ctx.t("cli.no_builtin_passwords"))
    parser.add_argument("--no-dir-pw", "--no-dpw", dest="directory_passwords", action="store_false", default=None, help=ctx.t("cli.no_directory_passwords"))
    return parser


def build_detection_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-d", "--deep-detect", dest="deep_detect", action="store_true", help=ctx.t("cli.deep_detect"))
    return parser


def build_process_mode_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-m", "--process-mode",
        dest="process_mode",
        type=parse_process_mode_value,
        choices=("background", "normal", "high"),
        default="high",
        help=ctx.t("cli.process_mode"),
    )
    return parser


def build_extract_config_override_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-r", "--recur", dest="recursive_extract", type=parse_recursive_extract_value, help=ctx.t("cli.recursive_extract"))
    parser.add_argument("-c", "--cleanup", dest="archive_cleanup_mode", type=parse_archive_cleanup_value, help=ctx.t("cli.archive_cleanup_mode"))
    parser.add_argument("-o", "--out-dir", dest="output_dir", help=ctx.t("cli.output_dir"))
    flatten_group = parser.add_mutually_exclusive_group()
    flatten_group.add_argument("-f", "--flatten", dest="flatten_single_directory", action="store_true", default=None, help=ctx.t("cli.flatten"))
    flatten_group.add_argument("-F", "--no-flatten", dest="flatten_single_directory", action="store_false", help=ctx.t("cli.no_flatten"))
    parser.add_argument("--write-manifest", "--manifest", dest="write_progress_manifest", action="store_true", help=ctx.t("cli.write_manifest"))
    parser.add_argument(
        "-k", "--allow-partial",
        "--ap",
        dest="allow_partial",
        action="store_true",
        help=ctx.t("cli.allow_partial"),
    )
    return parser
