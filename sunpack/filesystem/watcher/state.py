from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import errno
import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from sunpack.support.resource_lifecycle import (
    named_task_temporary_file,
    open_service_file,
    read_task_text,
)

from .group_models import (
    BLOCKER_MISSING_VOLUME,
    WatchGroupSnapshot,
    WatchGroupState,
)


STATE_VERSION = 15
LOADABLE_STATE_VERSIONS = {STATE_VERSION}
DEFAULT_JOURNAL_COMPACT_RECORDS = 4096
DEFAULT_JOURNAL_COMPACT_BYTES = 512 * 1024
DEFAULT_JOURNAL_HARD_BYTES = 1 * 1024 * 1024


class WatchStateJournalError(RuntimeError):
    """The durable watch-state journal is corrupt before its final record."""


_STATE_PATH_LOCKS_GUARD = threading.Lock()
_STATE_PATH_LOCKS: dict[str, threading.RLock] = {}


def _state_path_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(os.path.abspath(str(path)))
    with _STATE_PATH_LOCKS_GUARD:
        lock = _STATE_PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _STATE_PATH_LOCKS[key] = lock
        return lock


def _flush_file(handle) -> None:
    """Make a critical state transition durable before dependent filesystem work."""

    handle.flush()
    os.fsync(handle.fileno())


def _sync_file_path(path: Path) -> None:
    # Windows' CRT commit path requires a writable descriptor.
    with open_service_file(path, "rb+") as handle:
        os.fsync(handle.fileno())


@dataclass
class WatchPendingWork:
    path: str
    size: int
    mtime: float
    file_id: str = ""
    change_usn: int = 0
    force: bool = False
    password_scope_dir: str = ""
    internal_recovery: bool = False
    active_outputs: dict[str, str] = field(default_factory=dict)
    committed_roots: list[str] = field(default_factory=list)
    completed_sources: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        base = f"{self.path}|{self.size}|{self.mtime:.6f}"
        return f"{base}|{self.file_id}|{self.change_usn}"


@dataclass
class WatchStateEntry:
    """Latest retry-blocking failure for one input path."""

    path: str
    size: int
    mtime: float
    file_id: str = ""
    change_usn: int = 0
    status: str = "pending"
    last_error: str = ""
    attempt_count: int = 0
    failure_kind: str = ""
    failure_stage: str = ""
    failure_payload: dict[str, Any] = field(default_factory=dict)
    last_attempt_at: float = 0.0
    password_generation: int = 0

    @property
    def fingerprint(self) -> str:
        base = f"{self.path}|{self.size}|{self.mtime:.6f}"
        return f"{base}|{self.file_id}|{self.change_usn}"

    @property
    def password_scope_dir(self) -> str:
        payload = self.failure_payload if isinstance(self.failure_payload, dict) else {}
        configured = str(payload.get("password_scope_dir") or "").strip()
        return os.path.abspath(configured) if configured else os.path.dirname(os.path.abspath(self.path))


class WatchStateStore:
    """Persistent crash queue and retry blockers for watch mode."""

    def __init__(
        self,
        path: str,
        *,
        compact_records: int = DEFAULT_JOURNAL_COMPACT_RECORDS,
        compact_bytes: int = DEFAULT_JOURNAL_COMPACT_BYTES,
        hard_compact_bytes: int = DEFAULT_JOURNAL_HARD_BYTES,
    ):
        self.path = Path(path)
        self.journal_path = self.path.with_name(f"{self.path.stem}.journal.jsonl")
        self._state_lock = _state_path_lock(self.path)
        self._compact_records = max(1, int(compact_records))
        self._compact_bytes = max(1, int(compact_bytes))
        self._hard_compact_bytes = max(self._compact_bytes, int(hard_compact_bytes))
        self._journal_records = 0
        self._journal_bytes = 0
        self._compaction_due = False
        self.pending_work: dict[str, WatchPendingWork] = {}
        self.entries: dict[str, WatchStateEntry] = {}
        self.groups: dict[str, WatchGroupState] = {}
        self.password_generation = 0
        self.password_source_signature = ""
        self.load()

    def load(self) -> None:
        with self._state_lock:
            self._reset_memory_locked()
            incompatible = False
            if self.path.exists():
                try:
                    payload = json.loads(read_task_text(self.path, encoding="utf-8"))
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    version = payload.get("version")
                    if version not in LOADABLE_STATE_VERSIONS:
                        incompatible = True
                    else:
                        try:
                            self.password_generation = max(
                                0,
                                int(payload.get("password_generation", 0)),
                            )
                        except (TypeError, ValueError):
                            self.password_generation = 0
                        self.password_source_signature = str(
                            payload.get("password_source_signature") or ""
                        )
                        self.pending_work = self._load_records(
                            payload.get("pending_work"),
                            WatchPendingWork,
                        )
                        self.entries = self._load_records(
                            payload.get("entries"),
                            WatchStateEntry,
                        )
                        self.groups = self._load_records(
                            payload.get("groups"),
                            WatchGroupState,
                            normalize_keys=False,
                        )
            if incompatible:
                # State schemas are intentionally not migrated. Replace an old
                # or incompatible snapshot and its journal as one new empty state.
                self._reset_memory_locked()
                self._compact_locked()
                return
            if not self._load_journal_locked():
                self._reset_memory_locked()
                self._compact_locked()

    @staticmethod
    def _load_records(payload, record_type, *, normalize_keys: bool = True) -> dict:
        result = {}
        if not isinstance(payload, dict):
            return result
        for key, value in payload.items():
            if not isinstance(value, dict):
                continue
            try:
                record = record_type(**value)
            except TypeError:
                continue
            record_key = _path_key(record.path) if normalize_keys and hasattr(record, "path") else str(key)
            result[record_key] = record
        return result

    def save(self) -> None:
        """Force a compact snapshot for explicit callers and clean shutdowns."""

        with self._state_lock:
            self._compact_locked()

    def compact_if_needed(self, *, force: bool = False) -> bool:
        with self._state_lock:
            if not force and not self._compaction_due:
                return False
            self._compact_locked()
            return True

    @property
    def compaction_due(self) -> bool:
        with self._state_lock:
            return self._compaction_due

    def entry_items(self) -> list[WatchStateEntry]:
        with self._state_lock:
            return list(self.entries.values())

    def _reset_memory_locked(self) -> None:
        self.pending_work = {}
        self.entries = {}
        self.groups = {}
        self.password_generation = 0
        self.password_source_signature = ""
        self._journal_records = 0
        self._journal_bytes = 0
        self._compaction_due = False

    def _snapshot_payload_locked(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "password_generation": self.password_generation,
            "password_source_signature": self.password_source_signature,
            "pending_work": {
                key: asdict(value)
                for key, value in self.pending_work.items()
            },
            "entries": {
                key: asdict(value)
                for key, value in self.entries.items()
            },
            "groups": {
                key: asdict(value)
                for key, value in self.groups.items()
            },
        }

    def _write_snapshot_locked(self) -> None:
        payload = self._snapshot_payload_locked()
        self._atomic_replace_text_locked(
            self.path,
            lambda handle: json.dump(
                payload,
                handle,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )

    def _compact_locked(self) -> None:
        self._write_snapshot_locked()
        self._atomic_replace_text_locked(self.journal_path, lambda _handle: None)
        self._journal_records = 0
        self._journal_bytes = 0
        self._compaction_due = False

    def _atomic_replace_text_locked(self, target: Path, writer) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with named_task_temporary_file(
                mode="w",
                encoding="utf-8",
                newline="",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as temp:
                temp_path = Path(temp.name)
                writer(temp)
                _flush_file(temp)
            os.replace(temp_path, target)
            _sync_file_path(target)
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass

    def _load_journal_locked(self) -> bool:
        if not self.journal_path.exists():
            return True
        try:
            content = read_task_text(self.journal_path, encoding="utf-8")
        except FileNotFoundError:
            return True
        complete_content = content
        if content and not content.endswith("\n"):
            last_newline = content.rfind("\n")
            complete_content = content[: last_newline + 1]
            self._atomic_replace_text_locked(
                self.journal_path,
                lambda handle: handle.write(complete_content),
            )

        decoded_operations = []
        record_count = 0
        for line_number, line in enumerate(complete_content.splitlines(), start=1):
            if not line:
                continue
            try:
                transaction = json.loads(line)
            except json.JSONDecodeError as exc:
                raise WatchStateJournalError(
                    f"corrupt watch state journal at {self.journal_path}:{line_number}"
                ) from exc
            if not isinstance(transaction, dict):
                raise WatchStateJournalError(
                    f"invalid watch state journal record at {self.journal_path}:{line_number}"
                )
            if transaction.get("version") not in LOADABLE_STATE_VERSIONS:
                return False
            operations = transaction.get("operations")
            if not isinstance(operations, list) or not operations:
                raise WatchStateJournalError(
                    f"invalid watch state journal operations at {self.journal_path}:{line_number}"
                )
            try:
                decoded_operations.extend(
                    self._decode_operation(operation)
                    for operation in operations
                )
            except (TypeError, ValueError, KeyError) as exc:
                raise WatchStateJournalError(
                    f"invalid watch state journal operation at {self.journal_path}:{line_number}"
                ) from exc
            record_count += 1

        for operation in decoded_operations:
            self._apply_decoded_operation_locked(operation)
        self._journal_records = record_count
        self._journal_bytes = len(complete_content.encode("utf-8"))
        self._update_compaction_due_locked()
        return True

    def _commit_operations_locked(
        self,
        operations: list[dict[str, Any]],
        *,
        durable: bool = False,
    ) -> None:
        if not operations:
            return
        decoded = [self._decode_operation(operation) for operation in operations]
        if not self.path.exists():
            # The base snapshot must predate this transaction so a crash after
            # the append can always reconstruct the complete state.
            self._write_snapshot_locked()
        transaction = {
            "version": STATE_VERSION,
            "operations": operations,
        }
        serialized = (
            json.dumps(transaction, ensure_ascii=True, separators=(",", ":"))
            + "\n"
        )
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with open_service_file(
            self.journal_path,
            "a",
            encoding="utf-8",
            newline="",
        ) as handle:
            handle.write(serialized)
            if durable:
                _flush_file(handle)
        for operation in decoded:
            self._apply_decoded_operation_locked(operation)
        self._journal_records += 1
        self._journal_bytes += len(serialized.encode("utf-8"))
        self._update_compaction_due_locked()
        if self._journal_bytes >= self._hard_compact_bytes:
            self._compact_locked()

    def _update_compaction_due_locked(self) -> None:
        self._compaction_due = (
            self._journal_records >= self._compact_records
            or self._journal_bytes >= self._compact_bytes
        )

    @staticmethod
    def _put_operation(collection: str, key: str, value) -> dict[str, Any]:
        return {
            "op": "put",
            "collection": collection,
            "key": key,
            "value": asdict(value),
        }

    @staticmethod
    def _delete_operation(collection: str, key: str) -> dict[str, Any]:
        return {
            "op": "delete",
            "collection": collection,
            "key": key,
        }

    def _metadata_operation(
        self,
        password_generation: int,
        password_source_signature: str,
    ) -> dict[str, Any]:
        return {
            "op": "set_metadata",
            "value": {
                "password_generation": max(0, int(password_generation)),
                "password_source_signature": str(password_source_signature or ""),
            },
        }

    @staticmethod
    def _decode_operation(operation):
        if not isinstance(operation, dict):
            raise TypeError("journal operation must be an object")
        action = operation.get("op")
        if action == "set_metadata":
            value = operation.get("value")
            if not isinstance(value, dict):
                raise TypeError("metadata value must be an object")
            generation = max(0, int(value["password_generation"]))
            signature = str(value.get("password_source_signature") or "")
            return action, "", "", (generation, signature)

        collection = str(operation.get("collection") or "")
        record_types = {
            "pending_work": WatchPendingWork,
            "entries": WatchStateEntry,
            "groups": WatchGroupState,
        }
        record_type = record_types.get(collection)
        if record_type is None:
            raise ValueError(f"unknown state collection: {collection}")
        key = str(operation.get("key") or "")
        if not key:
            raise ValueError("state operation key must not be empty")
        if action == "delete":
            return action, collection, key, None
        if action != "put":
            raise ValueError(f"unknown state operation: {action}")
        value = operation.get("value")
        if not isinstance(value, dict):
            raise TypeError("state record value must be an object")
        record = record_type(**value)
        if collection in {"pending_work", "entries"}:
            key = _path_key(record.path)
        return action, collection, key, record

    def _apply_decoded_operation_locked(self, operation) -> None:
        action, collection, key, value = operation
        if action == "set_metadata":
            self.password_generation, self.password_source_signature = value
            return
        records = getattr(self, collection)
        if action == "delete":
            records.pop(key, None)
        else:
            records[key] = value

    def queue_active(
        self,
        candidate,
        *,
        force: bool = False,
        password_scope_dir: str = "",
        internal_recovery: bool = False,
    ) -> None:
        key = _path_key(candidate.path)
        with self._state_lock:
            previous = self.pending_work.get(key)
            pending = WatchPendingWork(
                path=os.path.abspath(candidate.path),
                size=int(candidate.size),
                mtime=float(candidate.mtime),
                file_id=str(getattr(candidate, "file_id", "") or ""),
                change_usn=int(getattr(candidate, "change_usn", 0) or 0),
                force=bool(force),
                password_scope_dir=os.path.abspath(
                    password_scope_dir
                    or (previous.password_scope_dir if previous else "")
                    or os.path.dirname(os.path.abspath(candidate.path))
                ),
                internal_recovery=bool(
                    internal_recovery or (previous.internal_recovery if previous else False)
                ),
                active_outputs=dict(previous.active_outputs if previous else {}),
                committed_roots=list(previous.committed_roots if previous else []),
                completed_sources=list(previous.completed_sources if previous else []),
            )
            self._commit_operations_locked([
                self._put_operation("pending_work", key, pending),
            ], durable=True)

    def record_attempt(
        self,
        path: str,
        size: int,
        mtime: float,
        file_id: str = "",
        change_usn: int = 0,
    ) -> None:
        with self._state_lock:
            key = _path_key(path)
            previous = self.pending_work.get(key)
            pending = WatchPendingWork(
                path=os.path.abspath(path),
                size=size,
                mtime=mtime,
                file_id=file_id,
                change_usn=int(change_usn),
                force=False,
                password_scope_dir=(
                    previous.password_scope_dir
                    if previous
                    else os.path.dirname(os.path.abspath(path))
                ),
                internal_recovery=bool(previous.internal_recovery if previous else False),
                active_outputs=dict(previous.active_outputs if previous else {}),
                committed_roots=list(previous.committed_roots if previous else []),
                completed_sources=list(previous.completed_sources if previous else []),
            )
            self._commit_operations_locked([
                self._put_operation("pending_work", key, pending),
            ])

    def pending_work_items(self) -> list[WatchPendingWork]:
        with self._state_lock:
            return list(self.pending_work.values())

    def pending_work_for_path(self, path: str) -> WatchPendingWork | None:
        with self._state_lock:
            return self.pending_work.get(_path_key(path))

    def record_task_output_started(self, owner_path: str, task_path: str, output_dir: str) -> bool:
        if not task_path or not output_dir:
            return False
        with self._state_lock:
            key = _path_key(owner_path)
            pending = self.pending_work.get(key)
            if pending is None:
                return False
            active = dict(pending.active_outputs)
            active[os.path.abspath(task_path)] = os.path.abspath(output_dir)
            updated = replace(pending, active_outputs=active)
            self._commit_operations_locked([
                self._put_operation("pending_work", key, updated),
            ], durable=True)
            return True

    def record_task_output_committed(self, owner_path: str, task_path: str, output_dir: str) -> bool:
        if not task_path:
            return False
        with self._state_lock:
            key = _path_key(owner_path)
            pending = self.pending_work.get(key)
            if pending is None:
                return False
            task_path = os.path.abspath(task_path)
            active = dict(pending.active_outputs)
            active.pop(task_path, None)
            roots = list(pending.committed_roots)
            if output_dir:
                root = os.path.abspath(output_dir)
                root_key = _path_key(root)
                if not any(
                    root_key == _path_key(value)
                    or _is_path_under(root_key, _path_key(value))
                    for value in roots
                ):
                    # Keep only the outermost committed roots. One targeted
                    # recursive recovery scan then covers nested task outputs
                    # without rescanning every descendant output directory.
                    roots = [
                        value
                        for value in roots
                        if not _is_path_under(_path_key(value), root_key)
                    ]
                    roots.append(root)
            completed = list(pending.completed_sources)
            task_key = _path_key(task_path)
            if (
                task_key != _path_key(owner_path)
                and not any(_path_key(value) == task_key for value in completed)
            ):
                # A committed recursive task must not be rediscovered from a
                # committed output root after a crash. The original Watch owner
                # remains the recovery anchor and is intentionally not listed.
                completed.append(task_path)
            updated = replace(
                pending,
                active_outputs=active,
                committed_roots=roots,
                completed_sources=completed,
            )
            self._commit_operations_locked([
                self._put_operation("pending_work", key, updated),
            ], durable=True)
            return True

    def rebase_pending_work(
        self,
        owner_path: str,
        candidates: Iterable,
        *,
        password_scope_dir: str = "",
    ) -> None:
        with self._state_lock:
            owner_key = _path_key(owner_path)
            previous = self.pending_work.get(owner_key)
            scope = os.path.abspath(
                password_scope_dir
                or (previous.password_scope_dir if previous else "")
                or os.path.dirname(os.path.abspath(owner_path))
            )
            unique = {}
            for candidate in candidates:
                unique.setdefault(_path_key(candidate.path), candidate)
            operations = [self._delete_operation("pending_work", owner_key)]
            for key, candidate in sorted(unique.items()):
                pending = WatchPendingWork(
                    path=os.path.abspath(candidate.path),
                    size=int(candidate.size),
                    mtime=float(candidate.mtime),
                    file_id=str(getattr(candidate, "file_id", "") or ""),
                    change_usn=int(getattr(candidate, "change_usn", 0) or 0),
                    force=True,
                    password_scope_dir=scope,
                    internal_recovery=True,
                )
                operations.append(self._put_operation("pending_work", key, pending))
            self._commit_operations_locked(operations, durable=True)

    def complete_work(self, paths: Iterable[str]) -> None:
        with self._state_lock:
            keys = {
                _path_key(path)
                for path in paths
                if _path_key(path) in self.pending_work
            }
            self._commit_operations_locked([
                self._delete_operation("pending_work", key)
                for key in sorted(keys)
            ], durable=True)

    def complete_work_if_matches(self, candidate) -> None:
        with self._state_lock:
            key = _path_key(candidate.path)
            pending = self.pending_work.get(key)
            if pending is None:
                return
            if (
                pending.size != int(candidate.size)
                or pending.mtime != float(candidate.mtime)
                or pending.file_id != str(candidate.file_id or "")
                or pending.change_usn != int(candidate.change_usn)
            ):
                return
            self._commit_operations_locked([
                self._delete_operation("pending_work", key),
            ], durable=True)

    def forget_path(self, path: str, *, recursive: bool = False) -> bool:
        normalized = os.path.abspath(path)
        with self._state_lock:
            operations = []
            for collection_name, collection in (
                ("pending_work", self.pending_work),
                ("entries", self.entries),
            ):
                operations.extend(
                    self._delete_operation(collection_name, key)
                    for key in collection
                    if _path_matches(key, normalized, recursive=recursive)
                )
            operations.extend(
                self._delete_operation("groups", group_id)
                for group_id, group in self.groups.items()
                if any(
                    _path_matches(member, normalized, recursive=recursive)
                    for member in [group.head_path, *group.owned_paths]
                    if member
                )
            )
            self._commit_operations_locked(operations)
            return bool(operations)

    def latest_entry_for_path(self, path: str) -> WatchStateEntry | None:
        with self._state_lock:
            return self.entries.get(_path_key(path))

    def advance_entry_observation(self, candidate) -> bool:
        with self._state_lock:
            key = _path_key(candidate.path)
            entry = self.entries.get(key)
            if entry is None:
                return False
            if entry.file_id != str(candidate.file_id or "") or entry.size != int(candidate.size):
                return False
            updated = replace(
                entry,
                mtime=float(candidate.mtime),
                change_usn=int(candidate.change_usn),
            )
            self._commit_operations_locked([
                self._put_operation("entries", key, updated),
            ])
            return True

    def clear_entries(self, paths: Iterable[str]) -> None:
        with self._state_lock:
            keys = {
                _path_key(path)
                for path in paths
                if _path_key(path) in self.entries
            }
            self._commit_operations_locked([
                self._delete_operation("entries", key)
                for key in sorted(keys)
            ])

    def prune_missing_records(self) -> tuple[int, int]:
        """Remove state records whose recorded filesystem paths are gone.

        ``entries`` describe one concrete input file, so a missing entry path
        makes the record stale.  A group stores only concrete paths that were
        validated and dispatched, so it is stale when one of its already-
        recorded physical paths is definitely gone.

        Filesystem errors other than a definite missing path are treated as
        unknown and retain the record.  This keeps a transient permission or
        volume error from destroying retry state during startup.
        """
        with self._state_lock:
            entry_keys = [
                key
                for key, entry in self.entries.items()
                if _recorded_file_presence(entry.path) is False
            ]
            group_ids = []
            for group_id, group in self.groups.items():
                recorded_paths = _group_recorded_paths(group)
                if not recorded_paths or any(
                    _recorded_file_presence(path) is False
                    for path in recorded_paths
                ):
                    group_ids.append(group_id)
            operations = [
                *(self._delete_operation("entries", key) for key in entry_keys),
                *(self._delete_operation("groups", group_id) for group_id in group_ids),
            ]
            self._commit_operations_locked(operations)
            return len(entry_keys), len(group_ids)

    def mark_password_source_changed(self, signature: str | None = None) -> int:
        with self._state_lock:
            next_signature = (
                self.password_source_signature
                if signature is None
                else str(signature or "")
            )
            next_generation = self.password_generation + 1
            self._commit_operations_locked([
                self._metadata_operation(next_generation, next_signature),
            ])
            return self.password_generation

    def record_password_source_signature(self, signature: str) -> bool:
        with self._state_lock:
            signature = str(signature or "")
            previous = self.password_source_signature
            changed = bool(previous and previous != signature)
            if not previous and any(
                entry.status == "failed_password"
                for entry in self.entries.values()
            ):
                changed = True
            next_generation = self.password_generation + (1 if changed else 0)
            if previous != signature or changed:
                self._commit_operations_locked([
                    self._metadata_operation(next_generation, signature),
                ])
            return changed

    def failed_password_entries_under(self, directory: str, *, include_subtree: bool = True) -> list[WatchStateEntry]:
        with self._state_lock:
            root = Path(directory).resolve()
            result: list[WatchStateEntry] = []
            for entry in self.entries.values():
                if entry.status != "failed_password":
                    continue
                try:
                    scope = Path(entry.password_scope_dir).resolve()
                    if include_subtree:
                        scope.relative_to(root)
                    elif scope != root:
                        continue
                except ValueError:
                    continue
                result.append(entry)
            return result

    def mark(
        self,
        path: str,
        size: int,
        mtime: float,
        *,
        file_id: str = "",
        change_usn: int = 0,
        status: str,
        error: str = "",
        failure_payload: dict[str, Any] | None = None,
    ) -> None:
        with self._state_lock:
            key = _path_key(path)
            previous = self.entries.get(key)
            payload = dict(failure_payload or {})
            blockers = {str(value) for value in payload.get("blockers") or []}
            if status not in {"failed_password", "suspended_missing_volume"} and not blockers:
                if previous is not None:
                    self._commit_operations_locked([
                        self._delete_operation("entries", key),
                    ], durable=True)
                return
            entry = WatchStateEntry(
                path=os.path.abspath(path),
                size=size,
                mtime=mtime,
                file_id=file_id,
                change_usn=int(change_usn),
                status=status,
                last_error=error,
                attempt_count=(previous.attempt_count + 1) if previous else 1,
                failure_kind=str(payload.get("kind") or ""),
                failure_stage=str(payload.get("stage") or ""),
                failure_payload=payload,
                last_attempt_at=time.time(),
                password_generation=self.password_generation,
            )
            self._commit_operations_locked([
                self._put_operation("entries", key, entry),
            ], durable=True)

    def group_state(self, group_id: str) -> WatchGroupState | None:
        with self._state_lock:
            return self.groups.get(group_id)

    def group_items(self) -> list[WatchGroupState]:
        with self._state_lock:
            return list(self.groups.values())

    def record_group_waiting(self, snapshot: WatchGroupSnapshot) -> None:
        with self._state_lock:
            previous = self.groups.get(snapshot.group_id)
            blockers = set(previous.blockers if previous else [])
            blockers.discard(BLOCKER_MISSING_VOLUME)
            record = self._group_record(
                snapshot,
                previous=previous,
                status="waiting",
                blockers=sorted(blockers),
                last_attempted_input_fingerprint=snapshot.input_fingerprint,
                password_generation=(
                    previous.password_generation
                    if previous
                    else self.password_generation
                ),
                failure_payload={
                    "kind": "relation_waiting",
                    "stage": "relation",
                    "message": "waiting for a dispatchable split candidate",
                },
            )
            self._commit_operations_locked([
                self._put_operation("groups", snapshot.group_id, record),
            ], durable=True)

    def record_group_attempt(self, snapshot: WatchGroupSnapshot) -> None:
        with self._state_lock:
            previous = self.groups.get(snapshot.group_id)
            record = self._group_record(
                snapshot,
                previous=previous,
                status="running",
                blockers=list(previous.blockers if previous else []),
                last_attempted_input_fingerprint=snapshot.input_fingerprint,
                password_generation=(
                    previous.password_generation
                    if previous
                    else self.password_generation
                ),
                failure_payload=dict(previous.failure_payload if previous else {}),
                increment_attempt=True,
            )
            self._commit_operations_locked([
                self._put_operation("groups", snapshot.group_id, record),
            ])

    def record_group_suspended(
        self,
        snapshot: WatchGroupSnapshot,
        *,
        blockers: list[str],
        failure_payload: dict[str, Any] | None = None,
    ) -> None:
        with self._state_lock:
            previous = self.groups.get(snapshot.group_id)
            record = self._group_record(
                snapshot,
                previous=previous,
                status="suspended",
                blockers=sorted(set(blockers)),
                last_attempted_input_fingerprint=snapshot.input_fingerprint,
                password_generation=self.password_generation,
                failure_payload=dict(failure_payload or {}),
            )
            self._commit_operations_locked([
                self._put_operation("groups", snapshot.group_id, record),
            ], durable=True)

    def record_group_terminal(
        self,
        snapshot: WatchGroupSnapshot,
        *,
        status: str,
        failure_payload: dict[str, Any] | None = None,
    ) -> None:
        with self._state_lock:
            previous = self.groups.get(snapshot.group_id)
            record = self._group_record(
                snapshot,
                previous=previous,
                status=status,
                blockers=[],
                last_attempted_input_fingerprint=snapshot.input_fingerprint,
                password_generation=self.password_generation,
                failure_payload=dict(failure_payload or {}),
            )
            self._commit_operations_locked([
                self._put_operation("groups", snapshot.group_id, record),
            ], durable=True)

    def record_group_done(self, snapshot: WatchGroupSnapshot) -> None:
        self.record_group_terminal(snapshot, status="done")

    def clear_group(self, group_id: str) -> bool:
        with self._state_lock:
            if group_id not in self.groups:
                return False
            self._commit_operations_locked([
                self._delete_operation("groups", group_id),
            ])
            return True

    def _group_record(
        self,
        snapshot: WatchGroupSnapshot,
        *,
        previous: WatchGroupState | None,
        status: str,
        blockers: list[str],
        last_attempted_input_fingerprint: str,
        password_generation: int,
        failure_payload: dict[str, Any],
        increment_attempt: bool = False,
    ) -> WatchGroupState:
        return WatchGroupState(
            group_id=snapshot.group_id,
            directory=snapshot.directory,
            logical_name=snapshot.logical_name,
            split_family=snapshot.split_family,
            head_path=snapshot.head_path,
            input_paths=list(snapshot.input_paths),
            owned_paths=list(snapshot.owned_paths),
            status=status,
            blockers=list(blockers),
            input_fingerprint=snapshot.input_fingerprint,
            ownership_fingerprint=snapshot.ownership_fingerprint,
            last_attempted_input_fingerprint=last_attempted_input_fingerprint,
            password_generation=password_generation,
            failure_payload=dict(failure_payload),
            attempt_count=(previous.attempt_count if previous else 0) + (1 if increment_attempt else 0),
            updated_at=time.time(),
        )

def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _recorded_file_presence(path: str) -> bool | None:
    """Return ``True``/``False`` for known file presence, ``None`` if unknown."""

    if not str(path or "").strip():
        return False
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR} or getattr(exc, "winerror", None) in {2, 3}:
            return False
        return None


def _group_recorded_paths(group: WatchGroupState) -> list[str]:
    """Return the concrete paths currently represented by a persisted group."""

    raw_paths: list[object] = [getattr(group, "head_path", "")]
    for field_name in ("input_paths", "owned_paths"):
        value = getattr(group, field_name, ())
        if isinstance(value, str):
            raw_paths.append(value)
        elif value:
            raw_paths.extend(value)

    result: dict[str, str] = {}
    for value in raw_paths:
        path = str(value or "").strip()
        if not path:
            continue
        result.setdefault(_path_key(path), os.path.abspath(path))
    return list(result.values())


def _path_matches(path: str, expected: str, *, recursive: bool) -> bool:
    normalized = _path_key(path)
    expected_key = _path_key(expected)
    return normalized == expected_key or (recursive and _is_path_under(normalized, expected_key))


def _is_path_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _paths_overlap_for_departure(path: str, departed: str, *, recursive: bool) -> bool:
    path_key = _path_key(path)
    departed_key = _path_key(departed)
    return path_key == departed_key or (recursive and _is_path_under(path_key, departed_key))
