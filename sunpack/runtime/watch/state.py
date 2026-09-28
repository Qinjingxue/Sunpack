from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import errno
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from sunpack_native import NativeWatchState, watch_path_key

from sunpack.runtime.watch.journal_commit import (
    JournalTicket,
    seed_state_stream,
    submit_segment_seal,
    submit_state_transaction,
    submit_stream_flush,
)
from sunpack.core.support.resource_lifecycle import (
    named_task_temporary_file,
    open_service_file,
    task_scandir,
)

STATE_VERSION = 18
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
    source_input_root: str = ""
    internal_recovery: bool = False
    durable_owner: bool = False
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

    @property
    def source_input_root(self) -> str:
        return str(self.failure_payload.get("source_input_root") or "")


class WatchStateStore:
    """Persistent crash queue with sequenced WAL and asynchronous checkpoints.

    Records live in a Rust-owned ``NativeWatchState``; the dataclasses above
    are built per lookup and never kept resident by the store.
    """

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
        self._native = NativeWatchState()

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
    def password_generation(self) -> int:
        return int(self._native.password_generation)

    @property
    def password_source_signature(self) -> str:
        return str(self._native.password_source_signature)

    @property
    def pending_work_count(self) -> int:
        return int(self._native.pending_count)

    @property
    def entry_count(self) -> int:
        return int(self._native.entry_count)

    @property
    def pending_work(self) -> dict[str, WatchPendingWork]:
        """Materialized diagnostic view; production code uses the lookup methods."""
        return {_path_key(item.path): item for item in self.pending_work_items()}

    @property
    def entries(self) -> dict[str, WatchStateEntry]:
        """Materialized diagnostic view; production code uses the lookup methods."""
        return {_path_key(item.path): item for item in self.entry_items()}

    @property
    def journal_path(self) -> Path:
        start = _current_sequence_segment(self.path, self._active_segment_start)
        return self._segment_path(start)

    def _segment_path(self, start_seq: int) -> Path:
        return self.path.with_name(
            f"{self.path.stem}.journal.{int(start_seq):020d}.jsonl"
        )

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
                    loaded = self._native.load_snapshot(str(self.path), STATE_VERSION)
                except ValueError as exc:
                    raise WatchStateJournalError(str(exc)) from exc
                except OSError as exc:
                    raise WatchStateJournalError(
                        f"corrupt watch state snapshot at {self.path}"
                    ) from exc
                if not loaded.compatible:
                    incompatible = True
                else:
                    self._snapshot_exists = True
                    self._checkpoint_seq = int(loaded.checkpoint_seq)
                    self._applied_seq = self._checkpoint_seq

            if incompatible:
                self._discard_incompatible_state_locked()
                view = self._capture_snapshot_locked()
                self._write_snapshot_view(view)
                self._snapshot_exists = True
                _reset_sequence(self.path, 1)
                return

            self._load_journal_segments_locked()
            self._active_segment_start = _seed_sequence(self.path, self._applied_seq)
            self._update_compaction_due_locked()

    def _load_journal_segments_locked(self) -> None:
        expected_seq = self._checkpoint_seq + 1
        for path in self._journal_paths():
            segment_start = self._segment_start_from_path(path)
            if segment_start is None:
                continue
            try:
                replay = self._native.replay_segment(
                    str(path),
                    self._checkpoint_seq,
                    expected_seq,
                    STATE_VERSION,
                )
            except FileNotFoundError:
                continue
            except ValueError as exc:
                raise WatchStateJournalError(str(exc)) from exc
            if replay.records:
                self._applied_seq = int(replay.applied_seq)
                expected_seq = int(replay.expected_seq)
                self._segment_records[segment_start] = int(replay.records)
                self._segment_bytes[segment_start] = int(replay.bytes)
                self._journal_records += int(replay.records)
                self._journal_bytes += int(replay.bytes)

    def _discard_incompatible_state_locked(self) -> None:
        self._reset_memory_locked()
        for path in [self.path, *self._journal_paths()]:
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
            return [WatchStateEntry(**item) for item in self._native.entry_items()]

    def _pending_record(self, path: str) -> WatchPendingWork | None:
        raw = self._native.pending(path)
        return WatchPendingWork(**raw) if raw is not None else None

    def _entry_record(self, path: str) -> WatchStateEntry | None:
        raw = self._native.entry(path)
        return WatchStateEntry(**raw) if raw is not None else None

    def _apply_in_memory_locked(self, operations: list[dict[str, Any]]) -> None:
        """Apply operations that intentionally bypass the WAL."""
        self._native.apply(self._native.decode_operations(operations))

    def _reset_memory_locked(self) -> None:
        self._native.reset()
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

    def _capture_snapshot_locked(self):
        # Records are immutable and shared, so the native view copies only the
        # map of record handles, not the records themselves.
        return self._native.capture(self._applied_seq)

    def _write_snapshot_view(self, view) -> None:
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
            view.write(str(temp_path), STATE_VERSION)
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
        decoded = self._native.decode_operations(operations)
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
        self._native.apply(decoded)
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

    def queue_active(
        self,
        candidate,
        *,
        force: bool = False,
        password_scope_dir: str = "",
        source_input_root: str = "",
        internal_recovery: bool = False,
        durable_owner: bool = False,
        persist: bool = True,
        durable: bool = False,
    ) -> None:
        key = _path_key(candidate.path)
        with self._state_lock:
            previous = self._pending_record(key)
            pending = WatchPendingWork(
                path=os.path.abspath(candidate.path),
                size=int(candidate.size),
                mtime=float(candidate.mtime),
                file_id=str(getattr(candidate, "file_id", "") or ""),
                change_usn=int(getattr(candidate, "change_usn", 0) or 0),
                force=bool(force),
                source_input_root=source_input_root or (previous.source_input_root if previous else ""),
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
            )
            operations = [self._put_operation("pending_work", key, pending)]
            if persist:
                self._commit_operations_locked(operations, durable=durable)
            else:
                self._apply_in_memory_locked(operations)

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
            previous = self._pending_record(key)
            pending = WatchPendingWork(
                path=os.path.abspath(path),
                size=size,
                mtime=mtime,
                file_id=file_id,
                change_usn=int(change_usn),
                force=False,
                source_input_root=previous.source_input_root if previous else "",
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
            )
            operations = [self._put_operation("pending_work", key, pending)]
            if previous is not None and not previous.durable_owner:
                self._apply_in_memory_locked(operations)
            else:
                self._commit_operations_locked(operations)

    def pending_work_items(self) -> list[WatchPendingWork]:
        with self._state_lock:
            return [WatchPendingWork(**item) for item in self._native.pending_items()]

    def bind_input_root(self, path: str, input_root: str) -> None:
        """Persist request provenance before an extraction can create outputs."""
        with self._state_lock:
            key = _path_key(path)
            pending = self._pending_record(key)
            if pending is None or pending.source_input_root == input_root:
                return
            updated = replace(pending, source_input_root=input_root)
            self._commit_operations_locked([
                self._put_operation("pending_work", key, updated),
            ], durable=pending.durable_owner)

    def pending_work_for_path(self, path: str) -> WatchPendingWork | None:
        with self._state_lock:
            return self._pending_record(path)

    def record_task_output_started(self, owner_path: str, task_path: str, output_dir: str) -> bool:
        if not task_path or not output_dir:
            return False
        with self._state_lock:
            key = _path_key(owner_path)
            pending = self._pending_record(key)
            if pending is None:
                return False
            active = dict(pending.active_outputs)
            active[os.path.abspath(task_path)] = os.path.abspath(output_dir)
            updated = replace(pending, active_outputs=active)
            self._commit_operations_locked([
                self._put_operation("pending_work", key, updated),
            ], durable=True)
            return True

    def record_task_output_finished(
        self,
        owner_path: str,
        task_path: str,
        output_dir: str,
        *,
        keep_output: bool,
    ) -> bool:
        """End the task's durable write record after verification."""
        if not task_path or not output_dir:
            return False
        with self._state_lock:
            key = _path_key(owner_path)
            pending = self._pending_record(key)
            if pending is None:
                return False
            task_path = os.path.abspath(task_path)
            active = dict(pending.active_outputs)
            if task_path not in active:
                return False
            active.pop(task_path)
            roots = list(pending.committed_roots)
            completed = list(pending.completed_sources)
            if keep_output:
                output_dir = os.path.abspath(output_dir)
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
                task_key = _path_key(task_path)
                if (
                    task_key != _path_key(pending.path)
                    and not any(_path_key(existing) == task_key for existing in completed)
                ):
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
        source_input_root: str = "",
    ) -> None:
        with self._state_lock:
            owner_key = _path_key(owner_path)
            previous = self._pending_record(owner_key)
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
                    source_input_root=source_input_root or (previous.source_input_root if previous else ""),
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
                if self._native.has_pending(path)
            }
            self._commit_operations_locked([
                self._delete_operation("pending_work", key)
                for key in sorted(keys)
            ], durable=durable)

    def complete_work_if_matches(self, candidate, *, durable: bool | None = None) -> None:
        with self._state_lock:
            key = _path_key(candidate.path)
            pending = self._pending_record(key)
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
        with self._state_lock:
            pending_keys, entry_keys = self._native.keys_matching(os.path.abspath(path), recursive)
            operations = [
                *(self._delete_operation("pending_work", key) for key in pending_keys),
                *(self._delete_operation("entries", key) for key in entry_keys),
            ]
            self._commit_operations_locked(operations)
            return bool(operations)

    def watch_cursor_snapshot(self) -> dict[str, dict[str, int]]:
        with self._state_lock:
            return dict(self._native.watch_cursors())

    def merge_watch_cursors(self, cursors: dict[str, dict[str, int]], *, durable: bool = True) -> None:
        with self._state_lock:
            merged = dict(self._native.watch_cursors())
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
    ) -> None:
        """Atomically cover a USN range and retain every recovered candidate."""
        with self._state_lock:
            operations: list[dict[str, Any]] = []
            for candidate in candidates:
                key = _path_key(candidate.path)
                previous = self._pending_record(key)
                pending = WatchPendingWork(
                    path=os.path.abspath(candidate.path),
                    size=int(candidate.size),
                    mtime=float(candidate.mtime),
                    file_id=str(getattr(candidate, "file_id", "") or ""),
                    change_usn=int(getattr(candidate, "change_usn", 0) or 0),
                    force=True,
                    source_input_root=previous.source_input_root if previous else "",
                    password_scope_dir=os.path.abspath(
                        (previous.password_scope_dir if previous else "")
                        or os.path.dirname(os.path.abspath(candidate.path))
                    ),
                    internal_recovery=bool(previous.internal_recovery if previous else False),
                    durable_owner=True,
                    active_outputs=dict(previous.active_outputs if previous else {}),
                    committed_roots=list(previous.committed_roots if previous else []),
                    completed_sources=list(previous.completed_sources if previous else []),
                )
                operations.append(self._put_operation("pending_work", key, pending))
            merged = dict(self._native.watch_cursors())
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
            value = self._native.watch_cursor(str(volume_key))
            return dict(value) if value is not None else None

    def latest_entry_for_path(self, path: str) -> WatchStateEntry | None:
        with self._state_lock:
            return self._entry_record(path)

    def advance_entry_observation(self, candidate) -> bool:
        with self._state_lock:
            key = _path_key(candidate.path)
            entry = self._entry_record(key)
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
                if self._native.has_entry(path)
            }
            self._commit_operations_locked([
                self._delete_operation("entries", key)
                for key in sorted(keys)
            ])

    def prune_missing_records(self) -> int:
        """Remove retry records whose concrete filesystem paths are gone."""
        with self._state_lock:
            entry_keys = [
                key
                for key, recorded_path in self._native.entry_paths()
                if _recorded_file_presence(recorded_path) is False
            ]
            self._commit_operations_locked([
                self._delete_operation("entries", key)
                for key in entry_keys
            ])
            return len(entry_keys)

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
            if not previous and self._native.has_entry_status("failed_password"):
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
            for raw in self._native.entry_items("failed_password"):
                entry = WatchStateEntry(**raw)
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
            previous = self._entry_record(key)
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

def _path_key(path: str) -> str:
    # One key function with NativeWatchState, which keys its record maps.
    return watch_path_key(str(path))


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


def _is_path_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False
