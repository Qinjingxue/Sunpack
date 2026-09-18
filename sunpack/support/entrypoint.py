import subprocess
import sys


def _launch_unelevated_launcher(arguments: list[str]) -> int:
    from sunpack.platform.windows.process_launch import launch_unelevated
    from sunpack.support.process_executable import current_process_executable

    launcher = current_process_executable().with_name("sunpack.exe")
    process = launch_unelevated(
        [str(launcher), *arguments],
        cwd=str(launcher.parent),
    )
    try:
        try:
            exit_code = process.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            exit_code = None
        if exit_code is None:
            try:
                process.terminate()
                process.wait(timeout=5.0)
            except Exception:
                pass
            return 1
        return int(exit_code)
    finally:
        close = getattr(process, "close", None)
        if callable(close):
            close()


def _launch_watch_unelevated() -> int:
    """Installer-only bridge that restores Watch with the interactive shell token."""

    return _launch_unelevated_launcher(["watch", "start"])


def _configure_startup_current_user(action: str) -> int:
    """Apply the installer-selected startup state to the interactive user's HKCU."""

    if action not in {"enable", "disable"}:
        return 2
    return _launch_unelevated_launcher(["watch", "startup", action])


def main() -> int:
    # Installer recovery must be handled by the new runtime itself so it can
    # deliberately cross from an elevated setup process back to the
    # interactive shell's medium-integrity token.
    if sys.argv[1:2] == ["--launch-watch-unelevated"]:
        return _launch_watch_unelevated()

    if sys.argv[1:2] == ["--configure-startup-current-user"]:
        if len(sys.argv) != 3:
            return 2
        return _configure_startup_current_user(sys.argv[2])

    # Registration and COM activation enter the main runtime directly and do
    # not start an extraction engine or a watch service.
    if sys.argv[1:2] and sys.argv[1] in {"--register-toast", "--unregister-toast", "--toast-activated"}:
        from sunpack.platform.windows.toast_host import handle_toast_argv

        return handle_toast_argv(sys.argv[1:])

    from sunpack.support.runtime_identity import consume_runtime_id

    try:
        public_argv = consume_runtime_id(sys.argv[1:])
    except ValueError as exc:
        from sunpack.config.cli_settings import load_cli_language_from_config
        from sunpack.i18n import I18nContext

        i18n = I18nContext(load_cli_language_from_config())
        print(i18n.t("cli.startup_failed", error=exc), file=sys.stderr, flush=True)
        return 2
    # Existing CLI and GUI entry points read sys.argv directly. Remove the
    # process-local private bootstrap arguments before either is entered.
    sys.argv[:] = [sys.argv[0], *public_argv]

    from sunpack.cli.persistent_process import handle_early_argv

    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        return early_result
    from sunpack.cli.cli import main as cli_main

    return cli_main()
