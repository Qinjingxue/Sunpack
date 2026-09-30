from pathlib import Path

from sunpack.core.config.loader import load_raw_config_payload


def read_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict]:
    return load_raw_config_payload(request_cwd)
