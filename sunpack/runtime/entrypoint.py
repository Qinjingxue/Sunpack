import sys


def main() -> int:
    from sunpack.core.support.runtime_identity import consume_runtime_id

    try:
        public_argv = consume_runtime_id(sys.argv[1:])
    except ValueError as exc:
        from sunpack.core.config.cli_settings import load_cli_language_from_config
        from sunpack.core.i18n import I18nContext

        i18n = I18nContext(load_cli_language_from_config())
        print(i18n.t("cli.startup_failed", error=exc), file=sys.stderr, flush=True)
        return 2
    # Existing CLI and GUI entry points read sys.argv directly. Remove the
    # process-local private bootstrap arguments before either is entered.
    sys.argv[:] = [sys.argv[0], *public_argv]

    # Toast activation shares the Watch namespace without starting a server.
    if sys.argv[1:2] == ["--toast-activated"]:
        from sunpack.core.platform.windows.toast_host import activate_toast

        return activate_toast()

    from sunpack.runtime.cli.persistent_process import handle_early_argv

    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        return early_result
    from sunpack.runtime.cli.cli import main as cli_main

    return cli_main()
