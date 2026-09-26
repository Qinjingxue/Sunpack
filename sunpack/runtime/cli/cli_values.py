import argparse

from sunpack.core.config.schema import normalize_config_value


def parse_process_mode_value(value: str) -> str:
    return {"b": "background", "n": "normal", "h": "high"}.get(value, value)


def parse_recursive_extract_value(value: str):
    try:
        normalize_config_value(("recursive_extract",), value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return str(value).strip()


def parse_archive_cleanup_value(value: str) -> str:
    raw = str(value).strip().lower()
    try:
        normalize_config_value(("post_extract", "archive_cleanup_mode"), raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return raw
