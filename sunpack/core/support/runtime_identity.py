"""Runtime identity supplied by the native Windows launcher.

The packaged launcher is the only component that computes an installation
identity.  Python treats the value as an opaque, validated namespace key.
"""

from __future__ import annotations

import re


RUNTIME_ID_ARGUMENT_PREFIX = "--_sunpack-runtime-id="
RUNTIME_ID_PATTERN = re.compile(r"v2-[0-9a-f]{16}\Z")
# Source checkouts have no native install directory.  They use one explicit
# development namespace instead of deriving an identity from Python paths.
SOURCE_RUNTIME_ID = "v2-0000000000000000"

_runtime_id: str | None = None


def is_valid_runtime_id(value: str) -> bool:
    return bool(RUNTIME_ID_PATTERN.fullmatch(value))


def set_runtime_id(value: str | None) -> None:
    global _runtime_id
    if value is not None and not is_valid_runtime_id(value):
        raise ValueError(f"invalid SunPack runtime identity: {value!r}")
    _runtime_id = value


def consume_runtime_id(argv: list[str]) -> list[str]:
    """Remove the launcher's private identity argument from *argv*.

    A packaged runtime receives exactly one identity from ``sunpack.exe``.
    Duplicate or malformed values are rejected instead of silently choosing
    one namespace.
    """

    identity: str | None = None
    public_argv: list[str] = []
    for item in argv:
        if not item.startswith(RUNTIME_ID_ARGUMENT_PREFIX):
            public_argv.append(item)
            continue
        if identity is not None:
            raise ValueError("duplicate SunPack runtime identity")
        identity = item[len(RUNTIME_ID_ARGUMENT_PREFIX) :]
        if not is_valid_runtime_id(identity):
            raise ValueError(f"invalid SunPack runtime identity: {identity!r}")
    set_runtime_id(identity)
    return public_argv


def runtime_id() -> str | None:
    return _runtime_id


def runtime_id_available() -> bool:
    return _runtime_id is not None


def require_runtime_id() -> str:
    if _runtime_id is None:
        raise RuntimeError("SunPack runtime identity was not supplied by the native launcher")
    return _runtime_id


def runtime_id_argument(value: str | None = None) -> str:
    candidate = require_runtime_id() if value is None else value
    if not is_valid_runtime_id(candidate):
        raise ValueError(f"invalid SunPack runtime identity: {candidate!r}")
    return RUNTIME_ID_ARGUMENT_PREFIX + candidate


def ensure_source_runtime_id(argv: list[str]) -> list[str]:
    """Attach the reserved source namespace to a source bootstrap argv."""
    if any(item.startswith(RUNTIME_ID_ARGUMENT_PREFIX) for item in argv):
        return list(argv)
    return [*argv, runtime_id_argument(SOURCE_RUNTIME_ID)]
