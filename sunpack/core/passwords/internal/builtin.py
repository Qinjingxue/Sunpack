from __future__ import annotations

from itertools import chain
import hashlib
import json
import logging
import ntpath
import re
import uuid
from threading import RLock
from pathlib import Path
from types import MappingProxyType
from sunpack_native import file_generation_tokens, read_shared_utf8_text

from sunpack.core.platform.windows.file_mutex import file_mutex
from sunpack.core.support.resource_lifecycle import open_service_file, write_task_text
from sunpack.core.support.resources import get_resource_path
from sunpack.core.passwords.internal.store import PasswordSnapshot, EMPTY_PASSWORD_SNAPSHOT, password_scope_key


DEFAULT_BUILTIN_PASSWORDS = ["123456", "123", "0000", "789"]
_LOG = logging.getLogger(__name__)
_INVALID_TEXT = re.compile("[\x00\ud800-\udfff]")
_WS = re.compile(r"[ \t\r\n]*")


def builtin_password_path() -> Path:
    return get_resource_path("builtin_passwords.json")


def ensure_builtin_password_file() -> Path:
    path = builtin_password_path()
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open_service_file(temp, "x", encoding="utf-8") as handle:
            json.dump({"passwords": [{"value": v} for v in DEFAULT_BUILTIN_PASSWORDS],
                       "clipboard_history": []}, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        try:
            temp.rename(path)
        except FileExistsError:
            pass
    finally:
        temp.unlink(missing_ok=True)
    return path


def _text(value, field: str) -> str:
    if not isinstance(value, str) or _INVALID_TEXT.search(value):
        raise ValueError(f"{field} must be a string without NUL or unpaired surrogates")
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _parse_document(text: str, previous: PasswordSnapshot = EMPTY_PASSWORD_SNAPSHOT, *, build_index: bool = True):
    # Decode one record at a time: no second full list of password dictionaries.
    decoder = json.JSONDecoder(object_pairs_hook=_object)
    index = _WS.match(text, 0).end()
    if text[index:index + 1] != "{":
        raise ValueError("password file must contain a JSON object")
    index += 1
    fields = set()
    buckets: dict[str, list[str]] = {"": []}
    history = []
    history_bounds = None
    while True:
        index = _WS.match(text, index).end()
        if text[index:index + 1] == "}":
            index += 1
            break
        key, index = decoder.raw_decode(text, index)
        if not isinstance(key, str) or key not in {"passwords", "clipboard_history"} or key in fields:
            raise ValueError("unsupported or duplicate password file field")
        fields.add(key)
        index = _WS.match(text, index).end()
        if text[index:index + 1] != ":":
            raise ValueError("expected ':'")
        index = _WS.match(text, index + 1).end()
        start = index
        if text[index:index + 1] != "[":
            raise ValueError(f"{key} must be an array")
        index += 1
        while True:
            index = _WS.match(text, index).end()
            if text[index:index + 1] == "]":
                index += 1
                break
            entry, index = decoder.raw_decode(text, index)
            if key == "clipboard_history":
                history.append(_text(entry, key))
            else:
                if not isinstance(entry, dict) or "value" not in entry or entry.keys() - {"value", "scopes"}:
                    raise ValueError("password records require value and optional scopes")
                value = _text(entry["value"], "value")
                scopes = entry.get("scopes")
                if "scopes" not in entry:
                    if build_index:
                        buckets[""].append(value)
                else:
                    if not isinstance(scopes, list) or not scopes:
                        raise ValueError("scopes must be a non-empty array of absolute directories")
                    for scope in scopes:
                        scope = _text(scope, "scope")
                        drive, tail = ntpath.splitdrive(scope.replace("/", chr(92)))
                        unc_root = drive.startswith(chr(92) * 2) and all(drive[2:].split(chr(92)))
                        if not drive or not (tail.startswith(chr(92)) or unc_root):
                            raise ValueError("scope must be an absolute Windows directory")
                        if build_index:
                            buckets.setdefault(password_scope_key(scope), []).append(value)
            index = _WS.match(text, index).end()
            char = text[index:index + 1]
            if char == "]":
                index += 1
                break
            if char != ",":
                raise ValueError("expected ',' or ']'")
            index = _WS.match(text, index + 1).end()
            if text[index:index + 1] == "]":
                raise ValueError("trailing comma")
        if key == "clipboard_history":
            history_bounds = start, index
        index = _WS.match(text, index).end()
        char = text[index:index + 1]
        if char == "}":
            index += 1
            break
        if char != ",":
            raise ValueError("expected ',' or '}'")
        index = _WS.match(text, index + 1).end()
        if text[index:index + 1] == "}":
            raise ValueError("trailing comma")
    if _WS.match(text, index).end() != len(text) or "passwords" not in fields:
        raise ValueError("password file requires passwords and no trailing data")
    if not build_index:
        return previous, history, history_bounds
    buckets[""].extend(history)
    globals_ = tuple(dict.fromkeys(buckets.pop("")))
    if globals_ == previous.global_passwords:
        globals_ = previous.global_passwords
    scoped = {}
    while buckets:
        scope, values = buckets.popitem()
        values = tuple(dict.fromkeys(values))
        old = previous.scoped_index.get(scope)
        scoped[scope] = old if old == values else values
    if globals_ == previous.global_passwords and scoped == previous.scoped_index:
        return previous, history, history_bounds
    # Incremental semantic digest avoids serializing another copy of the document.
    digest = hashlib.blake2b(digest_size=16)
    for scope, values in chain((("", globals_),), sorted(scoped.items())):
        digest.update(len(values).to_bytes(8, "little"))
        for value in chain((scope,), values):
            data = value.encode("utf-8")
            digest.update(len(data).to_bytes(8, "little"))
            digest.update(data)
    return PasswordSnapshot(globals_, MappingProxyType(scoped), digest.hexdigest()), history, history_bounds


def read_builtin_password_file(path: str | Path, previous=EMPTY_PASSWORD_SNAPSHOT) -> PasswordSnapshot:
    return _parse_document(read_shared_utf8_text(path), previous)[0]


class PasswordFileSource:
    def __init__(self):
        self.path = ensure_builtin_password_file()
        self.snapshot = EMPTY_PASSWORD_SNAPSHOT
        self._generation = object()
        self._lock = RLock()
        self.reload()

    def reload(self) -> PasswordSnapshot:
        with self._lock:
            generation = file_generation_tokens([str(self.path)])[0]
            if generation == self._generation:
                return self.snapshot
            try:
                updated = read_builtin_password_file(self.path, self.snapshot)
            except FileNotFoundError:
                updated = EMPTY_PASSWORD_SNAPSHOT
            except (OSError, ValueError, UnicodeError):
                _LOG.error("Cannot load password JSON; keeping the last valid snapshot", exc_info=True)
                return self.snapshot
            # An edit during parsing must be consumed by its queued file event.
            if file_generation_tokens([str(self.path)])[0] == generation:
                self._generation = generation
            self.snapshot = updated
            return updated


_SOURCE: PasswordFileSource | None = None
_SOURCE_LOCK = RLock()


def password_file_source() -> PasswordFileSource:
    global _SOURCE
    with _SOURCE_LOCK:
        if _SOURCE is None:
            _SOURCE = PasswordFileSource()
        return _SOURCE


def clear_password_file_source() -> None:
    global _SOURCE
    with _SOURCE_LOCK:
        _SOURCE = None


def merge_watch_clipboard_passwords(passwords: list[str], *, max_entries: int = 30) -> bool:
    if max_entries <= 0 or not passwords:
        return False
    path = builtin_password_path()
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with file_mutex(path):
            original = read_shared_utf8_text(path)
            _, history, bounds = _parse_document(original, build_index=False)
            updated = list(dict.fromkeys(history))
            for value in dict.fromkeys(passwords):
                _text(value, "clipboard password")
                if value in updated:
                    updated.remove(value)
                updated.append(value)
            updated = updated[-max_entries:]
            if updated == history:
                return False
            replacement = json.dumps(updated, ensure_ascii=False)
            if bounds is None:
                end = original.rfind("}")
                content = original[:end] + ', "clipboard_history": ' + replacement + original[end:]
            else:
                start, end = bounds
                content = original[:start] + replacement + original[end:]
            write_task_text(temp, content, encoding="utf-8")
            temp.replace(path)
            return True
    except (OSError, ValueError, UnicodeError):
        _LOG.error("Cannot merge clipboard history into password JSON", exc_info=True)
        return False
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            _LOG.warning("Cannot remove clipboard merge temporary file", exc_info=True)
