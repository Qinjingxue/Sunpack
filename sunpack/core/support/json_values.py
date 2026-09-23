import hashlib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


def jsonable_value(value: Any) -> Any:
    if is_dataclass(value):
        return jsonable_value(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): jsonable_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        try:
            return jsonable_value(value.to_dict())
        except Exception:
            pass
    return str(value)


def stable_json_value(value: Any, *, bytes_digest_key: str = "sha256") -> Any:
    if is_dataclass(value):
        return stable_json_value(asdict(value), bytes_digest_key=bytes_digest_key)
    if isinstance(value, dict):
        return {
            str(key): stable_json_value(item, bytes_digest_key=bytes_digest_key)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [stable_json_value(item, bytes_digest_key=bytes_digest_key) for item in value]
    if isinstance(value, set):
        return sorted(stable_json_value(item, bytes_digest_key=bytes_digest_key) for item in value)
    if isinstance(value, bytes):
        return {bytes_digest_key: hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, Path):
        return str(value)
    return value


def canonical_digest(value: Any, *, bytes_digest_key: str = "sha256") -> str:
    """Return the canonical SHA-256 digest for a JSON-stable value."""

    payload = json.dumps(
        stable_json_value(value, bytes_digest_key=bytes_digest_key),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
