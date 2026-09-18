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

from sunpack_native import write_watch_state_snapshot_native as _native_write_watch_state_snapshot

from sunpack.filesystem.watcher.journal_commit import (
    JournalTicket,
    seed_state_stream,
    submit_segment_seal,
    submit_state_transaction,
    submit_stream_flush,
)
from sunpack.support.resource_lifecycle import (
    named_task_temporary_file,
    open_service_file,
    read_task_text,
    task_scandir,
)

from .group_models import (
    BLOCKER_MISSING_VOLUME,
    WatchGroupSnapshot,
    WatchGroupState,
)


STATE_VERSION = 17
DEFAULT_JOURNAL_COMPACT_RECORDS = 8192
DEFAULT_JOURNAL_COMPACT_BYTES = 8 * 1024 * 1024
DEFAULT_JOURNAL_HARD_BYTES = 256 * 1024 * 1024


class WatchStateJournalError(RuntimeError):
    """The durable Watch state sequence is corrupt or discontinuous."""


_STATE_PATH_LOCKS_GUARD = threading.Lock()
_STATE_PATH_LOCKS: dict[str, threading.RLock] = {}
_SEQUENCE_GUARD = threading.Lock()
_SEQUENCE_NEXT: dict[str, int] = {}
_SEQUENCE_SEGMENT_START: dict[str, int] = {}


def _state_path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _state_path_lock(path: Path) -> threading.RLock:
    key = _state_path_key(path)
    with _STATE_PATH_LOCKS_GUARD:
        lock = _STATE_PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _STATE_PATH_LOCKS[key] = lock
        return lock


def _seed_sequence(path: Path, last_seq: int) -> int:
    key = _state_path_key(path)
    with _SEQUENCE_GUARD:
        _SEQUENCE_NEXT[key] = max(_SEQUENCE_NEXT.get(key, 1), int(last_seq) + 1)
        return _SEQUENCE_SEGMENT_START.setdefault(key, int(last_seq) + 1)


def _reset_sequence(path: Path, next_seq: int = 1) -> None:
    key = _state_path_key(path)
    with _SEQUENCE_GUARD:
        value = max(1, int(next_seq))
        _SEQUENCE_NEXT[key] = value
        _SEQUENCE_SEGMENT_START[key] = value


def _reserve_sequence(path: Path, floor: int) -> tuple[int, int]:
    key = _state_path_key(path)
    with _SEQUENCE_GUARD:
        seq = max(_SEQUENCE_NEXT.get(key, 1), int(floor) + 1)
        _SEQUENCE_NEXT[key] = seq + 1
        segment_start = _SEQUENCE_SEGMENT_START.setdefault(key, seq)
        return seq, segment_start


def _sequence_tail(path: Path) -> int:
    with _SEQUENCE_GUARD:
        return _SEQUENCE_NEXT.get(_state_path_key(path), 1) - 1


def _current_sequence_segment(path: Path, fallback: int) -> int:
    with _SEQUENCE_GUARD:
        return _SEQUENCE_SEGMENT_START.get(_state_path_key(path), int(fallback))


def _rotate_sequence_segment(path: Path, boundary: int) -> tuple[int, int] | None:
    """Atomically cut the WAL only when this store owns the full sequence prefix."""

    key = _state_path_key(path)
    with _SEQUENCE_GUARD:
        if _SEQUENCE_NEXT.get(key, 1) - 1 != int(boundary):
            return None
        old_start = _SEQUENCE_SEGMENT_START.setdefault(key, int(boundary) + 1)
        if old_start > int(boundary):
            return None
        new_start = int(boundary) + 1
        _SEQUENCE_SEGMENT_START[key] = new_start
        return old_start, new_start



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
    durable_owner: bool = False
    active_outputs: dict[str, str] = field(default_factory=dict)
    committed_roots: list[str] = field(default_factory=list)
    completed_sources: list[str] = field(default_factory=list)
    publications: dict[str, dict[str, str]] = field(default_factory=dict)

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


@dataclass(frozen=True)
class _SnapshotView:
    checkpoint_seq: int
    password_generation: int
    password_source_signature: str
    watch_cursors: dict[str, dict[str, int]]
    pending_work: dict[str, WatchPendingWork]
    entries: dict[str, WatchStateEntry]
    groups: dict[str, WatchGroupState]


class WatchStateStore:
    """Persistent crash queue with sequenced WAL and asynchronous checkpoints."""

    def __init__(
        self,
        path: str,
        *,
        compact_records: int = DEFAULT_JOURNAL_COMPACT_RECORDS,
        compact_bytes: int = DEFAULT_JOURNAL_COMPACT_BYTES,
        hard_compact_bytes: int = DEFAULT_JOURNAL_HARD_BYTES,
    ):
        self.path = Path(path)
        self._state_lock = _state_path_lock(self.path)
        self._checkpoint_condition = threading.Condition(self._state_lock)
        self._compact_records = max(1, int(compact_records))
        self._compact_bytes = max(1, int(compact_bytes))
        self._hard_compact_bytes = max(self._compact_bytes, int(hard_compact_bytes))
        self._writer_stream = _state_path_key(self.path)

        self.pending_work: dict[str, WatchPendingWork] = {}
        self.entries: dict[str, WatchStateEntry] = {}
        self.groups: dict[str, WatchGroupState] = {}
        self.password_generation = 0
        self.password_source_signature = ""
        self.watch_cursors: dict[str, dict[str, int]] = {}

        self._checkpoint_seq = 0
        self._applied_seq = 0
        self._active_segment_start = 1
        self._segment_records: dict[int, int] = {}
        self._segment_bytes: dict[int, int] = {}
        self._journal_records = 0
        self._journal_bytes = 0
        self._compaction_due = False
        self._checkpoint_running = False
        self._checkpoint_requested = False
        self._checkpoint_error: BaseException | None = None
        self._persistence_fault: BaseException | None = None
        self._snapshot_exists = False
        self._external_sequence_gap = False
        self.load()
        seed_state_stream(stream=self._writer_stream, seq=self._applied_seq)

    @property
    def journal_path(self) -> Path:
        start = _current_sequence_segment(self.path, self._active_segment_start)
        return self._segment_path(start)

    def _segment_path(self, start_seq: int) -> Path:
        return self.path.with_name(
            f"{self.path.stem}.journal.{int(start_seq):020d}.jsonl"
        )

    @property
    def _legacy_journal_path(self) -> Path:
        return self.path.with_name(f"{self.path.stem}.journal.jsonl")

    def _journal_paths(self) -> list[Path]:
        prefix = f"{self.path.stem}.journal."
        suffix = ".jsonl"
        paths: list[tuple[int, Path]] = []

        try:
            with task_scandir(self.path.parent) as entries:
                for entry in entries:
                    if not entry.name.startswith(prefix) or not entry.name.endswith(suffix):
                        continue
                    path = Path(entry.path)
                    start = self._segment_start_from_path(path)
                    if start is not None:
                        paths.append((start, path))
        except FileNotFoundError:
            return []

        paths.sort(key=lambda item: item[0])
        return [path for _, path in paths]

    def _segment_start_from_path(self, path: Path) -> int | None:
        prefix = f"{self.path.stem}.journal."
        suffix = ".jsonl"
        name = path.name
        if not name.startswith(prefix) or not name.endswith(suffix):
            return None
        raw = name[len(prefix) : -len(suffix)]
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value >= 1 else None

    def load(self) -> None:
        with self._state_lock:
            self._reset_memory_locked()
            incompatible = False
            if self.path.exists():
                try:
                    payload = json.loads(read_task_text(self.path, encoding="utf-8"))
                except Exception as exc:
                    raise WatchStateJournalError(
                        f"corrupt watch state snapshot at {self.path}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise WatchStateJournalError(
                        f"invalid watch state snapshot at {self.path}"
                    )
                if payload.get("version") != STATE_VERSION:
                    incompatible = True
                else:
                    self._snapshot_exists = True
                    try:
                        self._checkpoint_seq = max(
                            0,
                            int(payload.get("checkpoint_seq", 0)),
                        )
                        self._applied_seq = self._checkpoint_seq
                        self.password_generation = max(
                            0,
                            int(payload.get("password_generation", 0)),
                        )
                    except (TypeError, ValueError) as exc:
                        raise WatchStateJournalError(
                            f"invalid watch state snapshot metadata at {self.path}"
                        ) from exc
                    self.password_source_signature = str(
                        payload.get("password_source_signature") or ""
                    )
                    raw_cursors = payload.get("watch_cursors")
                    if isinstance(raw_cursors, dict):
                        self.watch_cursors = {
                            str(key).lower(): {
                                "journal_id": int(value.get("journal_id", 0) or 0),
                                "next_usn": int(value.get("next_usn", 0) or 0),
                            }
                            for key, value in raw_cursors.items()
                            if isinstance(value, dict)
                        }
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
                self._discard_incompatible_state_locked()
                view = self._capture_snapshot_locked()
                self._write_snapshot_view(view)
                self._snapshot_exists = True
                _reset_sequence(self.path, 1)
                return

            try:
                self._legacy_journal_path.unlink()
            except FileNotFoundError:
                pass
            self._load_journal_segments_locked()
            self._active_segment_start = _seed_sequence(self.path, self._applied_seq)
            self._update_compaction_due_locked()

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

    def _load_journal_segments_locked(self) -> None:
        paths = self._journal_paths()
        expected_seq = self._checkpoint_seq + 1
        for path in paths:
            segment_start = self._segment_start_from_path(path)
            if segment_start is None:
                continue
            segment_records = 0
            segment_bytes = 0
            try:
                with open_service_file(path, "r", encoding="utf-8", newline="") as handle:
                    for line_number, line in enumerate(handle, start=1):
                        if not line:
                            continue
                        # A process may restart after a torn final append and then
                        # continue in a new segment.  An incomplete final line is
                        # therefore harmless in any immutable old segment; a real
                        # lost transaction is still caught by the next seq gap.
                        if not line.endswith("\n"):
                            break
                        try:
                            transaction = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise WatchStateJournalError(
                                f"corrupt watch state journal at {path}:{line_number}"
                            ) from exc
                        if not isinstance(transaction, dict):
                            raise WatchStateJournalError(
                                f"invalid watch state journal record at {path}:{line_number}"
                            )
                        if transaction.get("version") != STATE_VERSION:
                            raise WatchStateJournalError(
                                f"incompatible watch state journal at {path}:{line_number}"
                            )
                        try:
                            seq = int(transaction["seq"])
                        except (KeyError, TypeError, ValueError) as exc:
                            raise WatchStateJournalError(
                                f"invalid watch state sequence at {path}:{line_number}"
                            ) from exc
                        if seq <= self._checkpoint_seq:
                            continue
                        if seq != expected_seq:
                            raise WatchStateJournalError(
                                f"non-contiguous watch state sequence at {path}:{line_number}: "
                                f"expected {expected_seq}, got {seq}"
                            )
                        operations = transaction.get("operations")
                        if not isinstance(operations, list) or not operations:
                            raise WatchStateJournalError(
                                f"invalid watch state operations at {path}:{line_number}"
                            )
                        try:
                            decoded = [
                                self._decode_operation(operation)
                                for operation in operations
                            ]
                        except (TypeError, ValueError, KeyError) as exc:
                            raise WatchStateJournalError(
                                f"invalid watch state operation at {path}:{line_number}"
                            ) from exc
                        for operation in decoded:
                            self._apply_decoded_operation_locked(operation)
                        self._applied_seq = seq
                        expected_seq = seq + 1
                        segment_records += 1
                        segment_bytes += len(line.encode("utf-8"))
            except FileNotFoundError:
                continue
            if segment_records:
                self._segment_records[segment_start] = segment_records
                self._segment_bytes[segment_start] = segment_bytes
                self._journal_records += segment_records
                self._journal_bytes += segment_bytes

    def _discard_incompatible_state_locked(self) -> None:
        self._reset_memory_locked()
        for path in [self.path, self._legacy_journal_path, *self._journal_paths()]:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def save(self) -> None:
        """Force one checkpoint and wait until it covers the current sequence."""

        with self._checkpoint_condition:
            self._raise_persistence_fault_locked()
            target_seq = self._applied_seq
            self._request_checkpoint_locked(force=True)
            while (
                (not self._snapshot_exists or self._checkpoint_seq < target_seq)
                and self._checkpoint_error is None
                and self._persistence_fault is None
            ):
                self._checkpoint_condition.wait()
            self._raise_persistence_fault_locked()
            if self._checkpoint_error is not None:
                raise self._checkpoint_error

    def flush(self) -> None:
        """Flush all journal operations submitted before this call."""

        with self._state_lock:
            self._raise_persistence_fault_locked()
            ticket = submit_stream_flush(
                stream=self._writer_stream,
                target_seq=self._applied_seq,
                on_error=self._on_journal_error,
            )
        ticket.wait()
        with self._state_lock:
            self._raise_persistence_fault_locked()

    def compact_if_needed(self, *, force: bool = False) -> bool:
        """Request a checkpoint without doing snapshot work on the caller."""

        with self._state_lock:
            if not force and not self._compaction_due:
                return False
            self._request_checkpoint_locked(force=force)
            return True

    @property
    def compaction_due(self) -> bool:
        with self._state_lock:
            return self._compaction_due

    @property
    def checkpoint_seq(self) -> int:
        with self._state_lock:
            return self._checkpoint_seq

    @property
    def applied_seq(self) -> int:
        with self._state_lock:
            return self._applied_seq

    def entry_items(self) -> list[WatchStateEntry]:
        with self._state_lock:
            return list(self.entries.values())

    def _reset_memory_locked(self) -> None:
        self.pending_work = {}
        self.entries = {}
        self.groups = {}
        self.password_generation = 0
        self.password_source_signature = ""
        self.watch_cursors = {}
        self._checkpoint_seq = 0
        self._applied_seq = 0
        self._active_segment_start = 1
        self._segment_records = {}
        self._segment_bytes = {}
        self._journal_records = 0
        self._journal_bytes = 0
        self._compaction_due = False
        self._snapshot_exists = False
        self._external_sequence_gap = False

    def _capture_snapshot_locked(self) -> _SnapshotView:
        # Records are replaced, not mutated in place, by WatchStateStore.  A
        # shallow root copy therefore freezes a checkpoint view in O(dict copy)
        # time without recursively duplicating every nested payload.
        return _SnapshotView(
            checkpoint_seq=self._applied_seq,
            password_generation=self.password_generation,
            password_source_signature=self.password_source_signature,
            watch_cursors={key: dict(value) for key, value in self.watch_cursors.items()},
            pending_work=self.pending_work.copy(),
            entries=self.entries.copy(),
            groups=self.groups.copy(),
        )

    def _write_snapshot_view(self, view: _SnapshotView) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            # ResourceLifecycle owns creation/cleanup of the sibling tempfile;
            # native code owns JSON encoding, buffered sequential I/O and fsync.
            with named_task_temporary_file(
                mode="w+b",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temp:
                temp_path = Path(temp.name)
            _native_write_watch_state_snapshot(
                str(temp_path),
                STATE_VERSION,
                view.checkpoint_seq,
                view.password_generation,
                view.password_source_signature,
                view.watch_cursors,
                view.pending_work,
                view.entries,
                view.groups,
            )
            os.replace(temp_path, self.path)
            _sync_file_path(self.path)
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass

    def _request_checkpoint_locked(self, *, force: bool = False) -> None:
        if _sequence_tail(self.path) != self._applied_seq:
            self._external_sequence_gap = True
        if self._external_sequence_gap:
            if force:
                self._checkpoint_error = RuntimeError(
                    "cannot checkpoint a WatchStateStore that does not own the full sequence prefix"
                )
                self._checkpoint_condition.notify_all()
            return
        if self._checkpoint_running:
            self._checkpoint_requested = True
            return
        if not force and not self._compaction_due:
            return
        self._checkpoint_running = True
        self._checkpoint_requested = False
        self._checkpoint_error = None
        threading.Thread(
            target=self._checkpoint_loop,
            name="sunpack-watch-checkpoint",
            daemon=True,
        ).start()

    def _checkpoint_loop(self) -> None:
        while True:
            seal_ticket: JournalTicket | None = None
            with self._state_lock:
                if self._persistence_fault is not None:
                    self._checkpoint_running = False
                    self._checkpoint_condition.notify_all()
                    return
                if _sequence_tail(self.path) != self._applied_seq:
                    self._external_sequence_gap = True
                    self._checkpoint_error = RuntimeError(
                        "cannot checkpoint a WatchStateStore that does not own the full sequence prefix"
                    )
                    self._checkpoint_running = False
                    self._checkpoint_condition.notify_all()
                    return
                boundary = self._applied_seq
                view = self._capture_snapshot_locked()
                rotation = _rotate_sequence_segment(self.path, boundary)
                if rotation is not None:
                    old_start, new_start = rotation
                    self._active_segment_start = new_start
                    seal_ticket = submit_segment_seal(
                        stream=self._writer_stream,
                        old_path=str(self._segment_path(old_start)),
                        new_path=str(self._segment_path(new_start)),
                        old_start=old_start,
                        boundary=boundary,
                        on_error=self._on_journal_error,
                    )
                else:
                    self._active_segment_start = _current_sequence_segment(
                        self.path,
                        boundary + 1,
                    )
                self._checkpoint_requested = False

            error: BaseException | None = None
            try:
                if seal_ticket is not None:
                    seal_ticket.wait()
                self._write_snapshot_view(view)
                self._retire_segments_through(boundary)
            except BaseException as exc:
                error = exc

            with self._checkpoint_condition:
                if error is None:
                    self._snapshot_exists = True
                    self._checkpoint_seq = max(self._checkpoint_seq, boundary)
                    retired_record_starts = [
                        start for start in self._segment_records if start <= boundary
                    ]
                    for start in retired_record_starts:
                        self._journal_records -= self._segment_records.pop(start, 0)
                        self._journal_bytes -= self._segment_bytes.pop(start, 0)
                    self._journal_records = max(0, self._journal_records)
                    self._journal_bytes = max(0, self._journal_bytes)
                    self._checkpoint_error = None
                    self._update_compaction_due_locked()
                else:
                    self._checkpoint_error = error
                    self._update_compaction_due_locked()
                    if self._journal_bytes >= self._hard_compact_bytes:
                        self._persistence_fault = RuntimeError(
                            "Watch state checkpoint failed at the journal safety limit"
                        )
                        self._persistence_fault.__cause__ = error

                self._checkpoint_condition.notify_all()
                if error is not None:
                    self._checkpoint_running = False
                    return
                if (
                    self._applied_seq > boundary
                    and (self._checkpoint_requested or self._compaction_due)
                ):
                    continue
                self._checkpoint_running = False
                return

    def _retire_segments_through(self, boundary: int) -> None:
        for path in self._journal_paths():
            start = self._segment_start_from_path(path)
            if start is None or start > boundary:
                continue
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                # Snapshot publication already made these segments redundant.
                # A later checkpoint/startup may retry cleanup safely.
                pass

    def _on_journal_written(self, segment_start: int, byte_count: int) -> None:
        with self._state_lock:
            self._segment_bytes[segment_start] = (
                self._segment_bytes.get(segment_start, 0) + int(byte_count)
            )
            self._journal_bytes += int(byte_count)
            self._update_compaction_due_locked()
            if self._compaction_due:
                self._request_checkpoint_locked()
            if (
                self._checkpoint_error is not None
                and self._journal_bytes >= self._hard_compact_bytes
            ):
                self._persistence_fault = RuntimeError(
                    "Watch state journal reached its safety limit after checkpoint failure"
                )
                self._persistence_fault.__cause__ = self._checkpoint_error
                self._checkpoint_condition.notify_all()

    def _on_journal_error(self, error: BaseException) -> None:
        with self._checkpoint_condition:
            if self._persistence_fault is None:
                self._persistence_fault = error
            self._checkpoint_condition.notify_all()

    def _raise_persistence_fault_locked(self) -> None:
        if self._persistence_fault is not None:
            raise RuntimeError("Watch state persistence is unavailable") from self._persistence_fault

    def _commit_operations_locked(
        self,
        operations: list[dict[str, Any]],
        *,
        durable: bool = False,
    ) -> None:
        if not operations:
            return
        self._raise_persistence_fault_locked()
        decoded = [self._decode_operation(operation) for operation in operations]
        previous_seq = self._applied_seq
        seq, segment_start = _reserve_sequence(self.path, previous_seq)
        if seq != previous_seq + 1:
            self._external_sequence_gap = True
        self._active_segment_start = segment_start
        ticket = submit_state_transaction(
            stream=self._writer_stream,
            path=str(self._segment_path(segment_start)),
            segment_start=segment_start,
            seq=seq,
            version=STATE_VERSION,
            operations=operations,
            durable=durable,
            on_written=self._on_journal_written,
            on_error=self._on_journal_error,
        )
        for operation in decoded:
            self._apply_decoded_operation_locked(operation)
        self._applied_seq = seq
        self._segment_records[segment_start] = (
            self._segment_records.get(segment_start, 0) + 1
        )
        self._journal_records += 1
        self._update_compaction_due_locked()
        if self._compaction_due:
            self._request_checkpoint_locked()

        # Both durable and ordinary calls return only after their WAL bytes have
        # reached the writer.  Durable tickets additionally include the fsync
        # barrier.  The global state lock is released for that wait, so unrelated
        # Watch state progression is never serialized behind physical I/O.
        self._state_lock.release()
        try:
            ticket.wait()
        finally:
            self._state_lock.acquire()
        self._raise_persistence_fault_locked()

    def _commit_operations_concurrent(
        self,
        operations: list[dict[str, Any]],
        *,
        durable: bool,
    ) -> None:
        with self._state_lock:
            self._commit_operations_locked(operations, durable=durable)

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

        if action == "set_watch_cursors":
            value = operation.get("value")
            if not isinstance(value, dict):
                raise TypeError("watch cursor value must be an object")
            normalized = {
                str(key).lower(): {
                    "journal_id": int(item.get("journal_id", 0) or 0),
                    "next_usn": int(item.get("next_usn", 0) or 0),
                }
                for key, item in value.items()
                if isinstance(item, dict)
            }
            return action, "", "", normalized
        if action == "task_commit":
            value = operation.get("value")
            if not isinstance(value, dict):
                raise TypeError("task commit value must be an object")
            owner = value.get("owner")
            if not isinstance(owner, dict):
                raise TypeError("task commit owner must be an object")
            task_path = os.path.abspath(str(value.get("task_path") or ""))
            output_dir = os.path.abspath(str(value.get("output_dir") or ""))
            staging_dir = os.path.abspath(str(value.get("staging_dir") or "")) if value.get("staging_dir") else ""
            staging_file_id = str(value.get("staging_file_id") or "")
            if not task_path or not output_dir:
                raise ValueError("task commit requires task/output paths")
            owner_record = WatchPendingWork(**owner)
            return action, "pending_work", _path_key(owner_record.path), {
                "owner": owner_record,
                "task_path": task_path,
                "output_dir": output_dir,
                "staging_dir": staging_dir,
                "staging_file_id": staging_file_id,
            }

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
        if action == "set_watch_cursors":
            self.watch_cursors = dict(value)
            return
        if action == "task_commit":
            pending = self.pending_work.get(key)
            if pending is None:
                pending = value["owner"]
            task_path = value["task_path"]
            output_dir = value["output_dir"]
            staging_dir = value["staging_dir"]
            staging_file_id = value.get("staging_file_id", "")
            active = dict(pending.active_outputs)
            active.pop(task_path, None)
            publications = dict(getattr(pending, "publications", {}) or {})
            publications[_path_key(task_path)] = {
                "task_path": task_path,
                "staging_dir": staging_dir,
                "staging_file_id": staging_file_id,
                "output_dir": output_dir,
            }
            roots = list(pending.committed_roots)
            root_key = _path_key(output_dir)
            if not any(
                root_key == _path_key(existing)
                or _is_path_under(root_key, _path_key(existing))
                for existing in roots
            ):
                roots = [
                    existing
                    for existing in roots
                    if not _is_path_under(_path_key(existing), root_key)
                ]
                roots.append(output_dir)
            completed = list(pending.completed_sources)
            task_key = _path_key(task_path)
            if (
                task_key != _path_key(pending.path)
                and not any(_path_key(existing) == task_key for existing in completed)
            ):
                completed.append(task_path)
            self.pending_work[key] = replace(
                pending,
                active_outputs=active,
                committed_roots=roots,
                completed_sources=completed,
                publications=publications,
            )
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
        durable_owner: bool = False,
        persist: bool = True,
        durable: bool = False,
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
                durable_owner=bool(
                    durable_owner or (previous.durable_owner if previous else False)
                ),
                active_outputs=dict(previous.active_outputs if previous else {}),
                committed_roots=list(previous.committed_roots if previous else []),
                completed_sources=list(previous.completed_sources if previous else []),
                publications=dict(getattr(previous, "publications", {}) if previous else {}),
            )
            if persist:
                self._commit_operations_locked([
                    self._put_operation("pending_work", key, pending),
                ], durable=durable)
            else:
                self.pending_work[key] = pending

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
                durable_owner=bool(previous.durable_owner if previous else False),
                active_outputs=dict(previous.active_outputs if previous else {}),
                committed_roots=list(previous.committed_roots if previous else []),
                completed_sources=list(previous.completed_sources if previous else []),
                publications=dict(getattr(previous, "publications", {}) if previous else {}),
            )
            if previous is not None and not previous.durable_owner:
                self.pending_work[key] = pending
            else:
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
        """Diagnostic observation; correctness no longer depends on START fsync."""
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
            self.pending_work[key] = updated
            return True

    def record_task_output_committed(
        self,
        owner_path: str,
        task_path: str,
        output_dir: str,
        *,
        staging_dir: str = "",
        staging_file_id: str = "",
    ) -> bool:
        if not task_path or not output_dir:
            return False
        with self._state_lock:
            key = _path_key(owner_path)
            pending = self.pending_work.get(key)
            if pending is None:
                return False
            owner = WatchPendingWork(
                path=pending.path,
                size=pending.size,
                mtime=pending.mtime,
                file_id=pending.file_id,
                change_usn=pending.change_usn,
                force=pending.force,
                password_scope_dir=pending.password_scope_dir,
                internal_recovery=pending.internal_recovery,
                durable_owner=pending.durable_owner,
            )
        operation = {
            "op": "task_commit",
            "value": {
                "owner": asdict(owner),
                "task_path": os.path.abspath(task_path),
                "output_dir": os.path.abspath(output_dir),
                "staging_dir": os.path.abspath(staging_dir) if staging_dir else "",
                "staging_file_id": str(staging_file_id or ""),
            },
        }
        self._commit_operations_concurrent([operation], durable=True)
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
                    durable_owner=True,
                )
                operations.append(self._put_operation("pending_work", key, pending))
            self._commit_operations_locked(operations, durable=True)

    def complete_work(self, paths: Iterable[str], *, durable: bool = False) -> None:
        with self._state_lock:
            keys = {
                _path_key(path)
                for path in paths
                if _path_key(path) in self.pending_work
            }
            self._commit_operations_locked([
                self._delete_operation("pending_work", key)
                for key in sorted(keys)
            ], durable=durable)

    def complete_work_if_matches(self, candidate, *, durable: bool | None = None) -> None:
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
            use_durable = pending.durable_owner if durable is None else bool(durable)
            self._commit_operations_locked([
                self._delete_operation("pending_work", key),
            ], durable=use_durable)

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

    def watch_cursor_snapshot(self) -> dict[str, dict[str, int]]:
        with self._state_lock:
            return {key: dict(value) for key, value in self.watch_cursors.items()}

    def merge_watch_cursors(self, cursors: dict[str, dict[str, int]], *, durable: bool = True) -> None:
        with self._state_lock:
            merged = {key: dict(value) for key, value in self.watch_cursors.items()}
            for key, value in cursors.items():
                if not isinstance(value, dict):
                    continue
                merged[str(key).lower()] = {
                    "journal_id": int(value.get("journal_id", 0) or 0),
                    "next_usn": int(value.get("next_usn", 0) or 0),
                }
            self._commit_operations_locked([
                {"op": "set_watch_cursors", "value": merged},
            ], durable=durable)

    def queue_recovery_batch(
        self,
        candidates: Iterable,
        cursors: dict[str, dict[str, int]],
        *,
        retire_paths: Iterable[str] = (),
    ) -> None:
        """Atomically cover a USN range and retain every recovered candidate."""
        with self._state_lock:
            operations: list[dict[str, Any]] = []
            for path in retire_paths:
                key = _path_key(path)
                if key in self.pending_work:
                    operations.append(self._delete_operation("pending_work", key))
            for candidate in candidates:
                key = _path_key(candidate.path)
                previous = self.pending_work.get(key)
                pending = WatchPendingWork(
                    path=os.path.abspath(candidate.path),
                    size=int(candidate.size),
                    mtime=float(candidate.mtime),
                    file_id=str(getattr(candidate, "file_id", "") or ""),
                    change_usn=int(getattr(candidate, "change_usn", 0) or 0),
                    force=True,
                    password_scope_dir=os.path.abspath(
                        (previous.password_scope_dir if previous else "")
                        or os.path.dirname(os.path.abspath(candidate.path))
                    ),
                    internal_recovery=bool(previous.internal_recovery if previous else False),
                    durable_owner=True,
                    active_outputs=dict(previous.active_outputs if previous else {}),
                    committed_roots=list(previous.committed_roots if previous else []),
                    completed_sources=list(previous.completed_sources if previous else []),
                    publications=dict(getattr(previous, "publications", {}) if previous else {}),
                )
                operations.append(self._put_operation("pending_work", key, pending))
            merged = {key: dict(value) for key, value in self.watch_cursors.items()}
            for key, value in cursors.items():
                if isinstance(value, dict):
                    merged[str(key).lower()] = {
                        "journal_id": int(value.get("journal_id", 0) or 0),
                        "next_usn": int(value.get("next_usn", 0) or 0),
                    }
            operations.append({"op": "set_watch_cursors", "value": merged})
            self._commit_operations_locked(operations, durable=True)

    def watch_cursor(self, volume_key: str) -> dict[str, int] | None:
        with self._state_lock:
            value = self.watch_cursors.get(str(volume_key).lower())
            return dict(value) if value is not None else None

    def record_watch_cursors(self, cursors: dict[str, dict[str, int]]) -> None:
        normalized = {
            str(key).lower(): {
                "journal_id": int(value.get("journal_id", 0) or 0),
                "next_usn": int(value.get("next_usn", 0) or 0),
            }
            for key, value in cursors.items()
            if isinstance(value, dict)
        }
        self._commit_operations_concurrent([
            {"op": "set_watch_cursors", "value": normalized},
        ], durable=True)

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
        """Remove state records whose concrete filesystem paths are gone."""
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
