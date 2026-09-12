from __future__ import annotations

import builtins
import asyncio
import contextlib
import contextvars
import os
import stat as stat_module
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence


class ResourceLifecycleError(RuntimeError):
    """Base error for a lifecycle invariant violation."""


class ResourceBusyError(ResourceLifecycleError):
    """A promotion could not prove that all overlapping resources were closed."""


class ResourcePolicy(str, Enum):
    TASK_OWNED = "task_owned"
    PROCESS_CACHE = "process_cache"
    SERVICE_OWNED = "service_owned"


class ResourceKind(str, Enum):
    PYTHON_FILE = "python_file"
    DIRECTORY_ITERATOR = "directory_iterator"
    NATIVE_READER = "native_reader"
    NATIVE_ARCHIVE_SESSION = "native_archive_session"
    NATIVE_ANALYSIS_VIEW = "native_analysis_view"
    NATIVE_MULTI_VOLUME_VIEW = "native_multi_volume_view"
    ARCHIVE_SESSION_BORROW = "archive_session_borrow"
    FILE_OPERATION = "file_operation"
    IOCP_FILE_HANDLE = "iocp_file_handle"
    VOLUME_DEVICE = "volume_device"
    DIRECTORY_WATCH = "directory_watch"
    OTHER = "other"


class ResourceState(str, Enum):
    ACTIVE = "active"
    RELEASING = "releasing"
    RELEASED = "released"
    RELEASE_FAILED = "release_failed"


class ScopeState(str, Enum):
    ACTIVE = "active"
    QUIESCING = "quiescing"
    CLOSED = "closed"


def _normalized_path(path: os.PathLike[str] | str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(os.fspath(path))))


def _is_path_under(candidate: str, root: str) -> bool:
    try:
        return os.path.commonpath((candidate, root)) == root
    except ValueError:
        return False


@dataclass(frozen=True)
class FileIdentity:
    """Stable-enough Windows identity plus a logical path fallback.

    Existing files use st_dev/st_ino (volume + file id on Windows). Paths that
    do not exist yet still participate in promotion exclusion by normalized
    path, which is required for output creation.
    """

    path: str
    device: int | None = None
    file_id: int | None = None
    is_directory: bool = False

    @classmethod
    def from_path(
        cls,
        path: os.PathLike[str] | str,
        *,
        directory: bool | None = None,
    ) -> "FileIdentity":
        normalized = _normalized_path(path)
        try:
            metadata = os.stat(normalized, follow_symlinks=False)
        except OSError:
            metadata = None
        if metadata is None:
            return cls(path=normalized, is_directory=bool(directory))
        return cls._from_normalized_stat(normalized, metadata, directory=directory)

    @classmethod
    def from_stat(
        cls,
        path: os.PathLike[str] | str,
        metadata: os.stat_result,
        *,
        directory: bool | None = None,
    ) -> "FileIdentity":
        normalized = _normalized_path(path)
        return cls._from_normalized_stat(normalized, metadata, directory=directory)

    @classmethod
    def _from_normalized_stat(
        cls,
        normalized: str,
        metadata: os.stat_result,
        *,
        directory: bool | None = None,
    ) -> "FileIdentity":
        if directory is None:
            directory = stat_module.S_ISDIR(metadata.st_mode)
        device = int(metadata.st_dev) if metadata.st_dev else None
        file_id = int(metadata.st_ino) if metadata.st_ino else None
        return cls(
            path=normalized,
            device=device,
            file_id=file_id,
            is_directory=bool(directory),
        )

    @classmethod
    def promotion_root(cls, path: os.PathLike[str] | str) -> "FileIdentity":
        return cls.from_path(path, directory=True)

    def same_file(self, other: "FileIdentity") -> bool:
        if (
            self.device is not None
            and self.file_id is not None
            and other.device is not None
            and other.file_id is not None
        ):
            return self.device == other.device and self.file_id == other.file_id
        return self.path == other.path

    def contains(self, other: "FileIdentity") -> bool:
        if self.same_file(other):
            return True
        return self.is_directory and _is_path_under(other.path, self.path)

    def overlaps(self, other: "FileIdentity") -> bool:
        return self.contains(other) or other.contains(self)


def _file_identity(
    path: os.PathLike[str] | str,
    *,
    directory: bool | None = None,
) -> FileIdentity:
    """Reuse an identity already resolved by the active file operation."""

    normalized = _normalized_path(path)
    for cached in reversed(_CURRENT_FILE_IDENTITIES.get()):
        if cached.path != normalized:
            continue
        if directory is not None and cached.is_directory is not bool(directory):
            continue
        return cached
    try:
        metadata = os.stat(normalized, follow_symlinks=False)
    except OSError:
        return FileIdentity(path=normalized, is_directory=bool(directory))
    return FileIdentity._from_normalized_stat(
        normalized,
        metadata,
        directory=directory,
    )


def file_identities(
    files: Iterable[os.PathLike[str] | str | FileIdentity],
    *,
    directories: bool = False,
) -> tuple[FileIdentity, ...]:
    identities: list[FileIdentity] = []
    seen: set[tuple[str, int | None, int | None, bool]] = set()
    for item in files:
        identity = (
            item
            if isinstance(item, FileIdentity)
            else _file_identity(item, directory=True if directories else None)
        )
        key = (identity.path, identity.device, identity.file_id, identity.is_directory)
        if key not in seen:
            identities.append(identity)
            seen.add(key)
    return tuple(identities)


@dataclass
class ResourceRecord:
    resource_id: str
    task_id: str | None
    kind: ResourceKind
    policy: ResourcePolicy
    files: tuple[FileIdentity, ...]
    owner_type: str
    owner_repr: str
    release_callback: Callable[[], Any]
    promotion_blocking: bool
    created_at: float
    created_thread: int
    created_from: str
    state: ResourceState = ResourceState.ACTIVE
    released_at: float | None = None
    release_error: str = ""

    def overlaps(self, roots: Sequence[FileIdentity]) -> bool:
        return any(file.overlaps(root) for file in self.files for root in roots)

    def describe(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "task_id": self.task_id,
            "kind": self.kind.value,
            "policy": self.policy.value,
            "files": [item.path for item in self.files],
            "owner_type": self.owner_type,
            "owner": self.owner_repr,
            "promotion_blocking": self.promotion_blocking,
            "state": self.state.value,
            "created_at": self.created_at,
            "created_thread": self.created_thread,
            "created_from": self.created_from,
            "release_error": self.release_error,
        }


@dataclass(frozen=True)
class ReleaseReport:
    attempted: int
    released: int
    failed: tuple[dict[str, Any], ...] = ()

    @property
    def ok(self) -> bool:
        return not self.failed


@dataclass
class PromotionBarrierReport:
    roots: tuple[str, ...]
    gate_wait_seconds: float = 0.0
    cleanup_seconds: float = 0.0
    barrier_seconds: float = 0.0
    released_resources: int = 0
    cache_reports: list[Any] = field(default_factory=list)
    open_file_audit: tuple[str, ...] = ()
    native_resource_audit: tuple[dict[str, Any], ...] = ()


_LOCK = threading.RLock()
_CHANGED = threading.Condition(_LOCK)
_RESOURCES: dict[str, ResourceRecord] = {}
_RELEASE_HISTORY: deque[dict[str, Any]] = deque(maxlen=512)
_TASK_SCOPES: dict[str, "TaskResourceScope"] = {}
_ACTIVE_PROMOTIONS: dict[str, tuple[FileIdentity, ...]] = {}
_CURRENT_SCOPE: contextvars.ContextVar["TaskResourceScope | None"] = contextvars.ContextVar(
    "sunpack_task_resource_scope",
    default=None,
)
_CURRENT_PROMOTION_ROOTS: contextvars.ContextVar[tuple[FileIdentity, ...]] = contextvars.ContextVar(
    "sunpack_current_promotion_roots",
    default=(),
)
_CURRENT_OPERATION_STACK: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "sunpack_current_resource_operation_stack",
    default=(),
)
_CURRENT_FILE_IDENTITIES: contextvars.ContextVar[tuple[FileIdentity, ...]] = contextvars.ContextVar(
    "sunpack_current_file_identities",
    default=(),
)


def _capture_origin() -> str:
    frame = sys._getframe(2)
    try:
        while frame is not None:
            filename = frame.f_code.co_filename
            normalized = filename.replace("\\", "/")
            if not normalized.endswith("/support/resource_lifecycle.py"):
                return f"{filename}:{frame.f_lineno} in {frame.f_code.co_name}"
            frame = frame.f_back
        return "<unknown>"
    finally:
        del frame


def _owner_description(owner: Any) -> tuple[str, str]:
    owner_type = type(owner).__qualname__
    try:
        owner_repr = repr(owner)
    except Exception:
        owner_repr = f"<{owner_type}>"
    if len(owner_repr) > 240:
        owner_repr = owner_repr[:237] + "..."
    return owner_type, owner_repr


def _matching_active_records(roots: Sequence[FileIdentity]) -> list[ResourceRecord]:
    return [
        record
        for record in _RESOURCES.values()
        if record.state in {ResourceState.ACTIVE, ResourceState.RELEASING, ResourceState.RELEASE_FAILED}
        and record.overlaps(roots)
        and record.promotion_blocking
    ]


def _promotion_conflict(identities: Sequence[FileIdentity]) -> tuple[str, tuple[FileIdentity, ...]] | None:
    for token, roots in _ACTIVE_PROMOTIONS.items():
        if any(identity.overlaps(root) for identity in identities for root in roots):
            return token, roots
    return None


@contextlib.contextmanager
def lifecycle_registration(
    files: Iterable[os.PathLike[str] | str | FileIdentity],
    *,
    timeout: float = 30.0,
) -> Iterator[tuple[FileIdentity, ...]]:
    """Hold the shared coordination lock across handle creation + registry insert."""

    identities = file_identities(files)
    deadline = time.monotonic() + max(0.0, float(timeout))
    with _CHANGED:
        while True:
            conflict = _promotion_conflict(identities)
            if conflict is None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                roots = ", ".join(item.path for item in conflict[1])
                raise ResourceBusyError(f"resource registration blocked by promotion roots: {roots}")
            _CHANGED.wait(remaining)
        yield identities


class ResourceLease:
    __slots__ = ("_resource_id",)

    def __init__(self, resource_id: str):
        self._resource_id = resource_id

    @property
    def resource_id(self) -> str:
        return self._resource_id

    @property
    def closed(self) -> bool:
        with _LOCK:
            record = _RESOURCES.get(self._resource_id)
            return record is None or record.state is ResourceState.RELEASED

    def close(self) -> bool:
        return _release_resource(self._resource_id)

    release = close

    def __enter__(self) -> "ResourceLease":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _register_resource_locked(
    *,
    task_id: str | None,
    kind: ResourceKind,
    policy: ResourcePolicy,
    files: tuple[FileIdentity, ...],
    owner: Any,
    release: Callable[[], Any],
    promotion_blocking: bool,
) -> ResourceLease:
    if not callable(release):
        raise TypeError("resource release callback must be callable")
    conflict = _promotion_conflict(files)
    if conflict is not None:
        roots = ", ".join(item.path for item in conflict[1])
        raise ResourceBusyError(f"cannot register resource during promotion of {roots}")
    resource_id = uuid.uuid4().hex
    owner_type, owner_repr = _owner_description(owner)
    _RESOURCES[resource_id] = ResourceRecord(
        resource_id=resource_id,
        task_id=task_id,
        kind=kind,
        policy=policy,
        files=files,
        owner_type=owner_type,
        owner_repr=owner_repr,
        release_callback=release,
        promotion_blocking=promotion_blocking,
        created_at=time.time(),
        created_thread=threading.get_ident(),
        created_from=_capture_origin(),
    )
    _CHANGED.notify_all()
    return ResourceLease(resource_id)


def register_resource(
    owner: Any,
    files: Iterable[os.PathLike[str] | str | FileIdentity],
    release: Callable[[], Any],
    *,
    kind: ResourceKind = ResourceKind.OTHER,
    policy: ResourcePolicy = ResourcePolicy.TASK_OWNED,
    task_id: str | None = None,
    registration_held: bool = False,
    promotion_blocking: bool = True,
) -> ResourceLease:
    identities = file_identities(files)
    if registration_held:
        with _CHANGED:
            return _register_resource_locked(
                task_id=task_id,
                kind=kind,
                policy=policy,
                files=identities,
                owner=owner,
                release=release,
                promotion_blocking=promotion_blocking,
            )
    with lifecycle_registration(identities):
        return _register_resource_locked(
            task_id=task_id,
            kind=kind,
            policy=policy,
            files=identities,
            owner=owner,
            release=release,
            promotion_blocking=promotion_blocking,
        )


def _release_resource(resource_id: str) -> bool:
    with _CHANGED:
        record = _RESOURCES.get(resource_id)
        if record is None or record.state is ResourceState.RELEASED:
            return False
        if record.state is ResourceState.RELEASING:
            return False
        record.state = ResourceState.RELEASING
        callback = record.release_callback
    try:
        callback()
    except BaseException as exc:
        with _CHANGED:
            record.state = ResourceState.RELEASE_FAILED
            record.release_error = f"{type(exc).__name__}: {exc}"
            _CHANGED.notify_all()
        raise
    with _CHANGED:
        record.state = ResourceState.RELEASED
        record.released_at = time.time()
        record.release_callback = lambda: None
        _RELEASE_HISTORY.append(record.describe())
        _RESOURCES.pop(resource_id, None)
        _CHANGED.notify_all()
    return True


def _release_records(records: Sequence[ResourceRecord]) -> ReleaseReport:
    released = 0
    failed: list[dict[str, Any]] = []
    for record in reversed(records):
        try:
            released += int(_release_resource(record.resource_id))
        except BaseException:
            with _LOCK:
                failed.append(record.describe())
    return ReleaseReport(attempted=len(records), released=released, failed=tuple(failed))


class TaskResourceScope:
    def __init__(self, task_id: str, *, files: Iterable[os.PathLike[str] | str] = ()):
        task_id = str(task_id or "").strip()
        if not task_id:
            raise ValueError("TaskResourceScope requires a task_id")
        self.task_id = task_id
        self.files = file_identities(files)
        self.state = ScopeState.ACTIVE
        self.created_at = time.time()
        self._resource_ids: list[str] = []
        self._active_operations = 0
        self._active_file_operations: dict[FileIdentity, int] = {}
        self._async_idle_waiters: list[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = []
        with _CHANGED:
            existing = _TASK_SCOPES.get(task_id)
            if existing is not None and existing.state is not ScopeState.CLOSED:
                raise ResourceLifecycleError(f"task resource scope already exists: {task_id}")
            _TASK_SCOPES[task_id] = self

    @contextlib.contextmanager
    def activate(self) -> Iterator["TaskResourceScope"]:
        token = _CURRENT_SCOPE.set(self)
        try:
            yield self
        finally:
            _CURRENT_SCOPE.reset(token)

    def register(
        self,
        owner: Any,
        files: Iterable[os.PathLike[str] | str | FileIdentity],
        release: Callable[[], Any],
        *,
        kind: ResourceKind = ResourceKind.OTHER,
        policy: ResourcePolicy = ResourcePolicy.TASK_OWNED,
        registration_held: bool = False,
    ) -> ResourceLease:
        identities = file_identities(files)
        manager = contextlib.nullcontext(identities) if registration_held else lifecycle_registration(identities)
        with manager:
            with _CHANGED:
                if self.state is not ScopeState.ACTIVE:
                    raise ResourceLifecycleError(
                        f"task {self.task_id} cannot register {kind.value} while {self.state.value}"
                    )
                lease = _register_resource_locked(
                    task_id=self.task_id,
                    kind=kind,
                    policy=policy,
                    files=identities,
                    owner=owner,
                    release=release,
                    promotion_blocking=True,
                )
                self._resource_ids.append(lease.resource_id)
                return lease

    @contextlib.contextmanager
    def operation(
        self,
        *,
        files: Iterable[os.PathLike[str] | str | FileIdentity] = (),
    ) -> Iterator[None]:
        raw_files = tuple(files)

        def enter(identities: tuple[FileIdentity, ...]) -> None:
            with _CHANGED:
                if self.state is not ScopeState.ACTIVE:
                    raise ResourceLifecycleError(
                        f"task operation entered after quiesce: {self.task_id} ({self.state.value})"
                    )
                self._active_operations += 1
                for identity in identities:
                    self._active_file_operations[identity] = (
                        self._active_file_operations.get(identity, 0) + 1
                    )

        if raw_files:
            # The conservative logical identities acquire the promotion gate
            # before os.stat touches a path. Resolve the physical identities
            # once while that coordination lock is held.
            logical_identities = tuple(
                item
                if isinstance(item, FileIdentity)
                else FileIdentity(path=_normalized_path(item), is_directory=True)
                for item in raw_files
            )
            with lifecycle_registration(logical_identities):
                identities = file_identities(raw_files)
                enter(identities)
        else:
            identities = ()
            enter(identities)
        operation_token = _CURRENT_OPERATION_STACK.set(
            (*_CURRENT_OPERATION_STACK.get(), self.task_id)
        )
        identity_token = (
            _CURRENT_FILE_IDENTITIES.set((*_CURRENT_FILE_IDENTITIES.get(), *identities))
            if identities
            else None
        )
        try:
            yield
        finally:
            if identity_token is not None:
                _CURRENT_FILE_IDENTITIES.reset(identity_token)
            _CURRENT_OPERATION_STACK.reset(operation_token)
            idle_waiters: tuple[tuple[asyncio.AbstractEventLoop, asyncio.Event], ...] = ()
            with _CHANGED:
                self._active_operations = max(0, self._active_operations - 1)
                for identity in identities:
                    remaining = self._active_file_operations.get(identity, 0) - 1
                    if remaining > 0:
                        self._active_file_operations[identity] = remaining
                    else:
                        self._active_file_operations.pop(identity, None)
                if not self._active_operations and self._async_idle_waiters:
                    idle_waiters = tuple(self._async_idle_waiters)
                    self._async_idle_waiters.clear()
                _CHANGED.notify_all()
            for loop, event in idle_waiters:
                try:
                    loop.call_soon_threadsafe(event.set)
                except RuntimeError:
                    pass

    def begin_promotion(self, *, timeout: float) -> None:
        deadline = time.monotonic() + max(0.0, float(timeout))
        own_operations = _CURRENT_OPERATION_STACK.get().count(self.task_id)
        with _CHANGED:
            if self.state is not ScopeState.ACTIVE:
                raise ResourceLifecycleError(
                    f"task {self.task_id} cannot enter promotion while {self.state.value}"
                )
            self.state = ScopeState.QUIESCING
            while self._active_operations > own_operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.state = ScopeState.ACTIVE
                    _CHANGED.notify_all()
                    raise ResourceBusyError(
                        f"task {self.task_id} still has "
                        f"{self._active_operations - own_operations} concurrent operations"
                    )
                _CHANGED.wait(remaining)

    def end_promotion(self) -> None:
        with _CHANGED:
            if self.state is ScopeState.QUIESCING:
                self.state = ScopeState.ACTIVE
                _CHANGED.notify_all()

    def release_under(self, roots: Iterable[os.PathLike[str] | str | FileIdentity]) -> ReleaseReport:
        identities = file_identities(roots, directories=True)
        with _LOCK:
            records = [
                _RESOURCES[resource_id]
                for resource_id in self._resource_ids
                if resource_id in _RESOURCES
                and _RESOURCES[resource_id].state is not ResourceState.RELEASED
                and _RESOURCES[resource_id].overlaps(identities)
            ]
        return _release_records(records)

    def close(self, *, timeout: float = 30.0) -> ReleaseReport:
        deadline = time.monotonic() + max(0.0, float(timeout))
        with _CHANGED:
            if self.state is ScopeState.CLOSED:
                return ReleaseReport(0, 0)
            self.state = ScopeState.QUIESCING
            while self._active_operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ResourceBusyError(
                        f"task {self.task_id} still has {self._active_operations} active operations"
                    )
                _CHANGED.wait(remaining)
            records = [
                _RESOURCES[resource_id]
                for resource_id in self._resource_ids
                if resource_id in _RESOURCES and _RESOURCES[resource_id].state is not ResourceState.RELEASED
            ]
        report = _release_records(records)
        with _CHANGED:
            self.state = ScopeState.CLOSED
            if _TASK_SCOPES.get(self.task_id) is self:
                _TASK_SCOPES.pop(self.task_id, None)
            _CHANGED.notify_all()
        if not report.ok:
            raise ResourceLifecycleError(
                f"task {self.task_id} resource cleanup failed: {report.failed}"
            )
        return report

    async def aclose(self, *, timeout: float = 30.0) -> ReleaseReport:
        deadline = time.monotonic() + max(0.0, float(timeout))
        waiter: tuple[asyncio.AbstractEventLoop, asyncio.Event] | None = None
        with _CHANGED:
            if self.state is ScopeState.CLOSED:
                return ReleaseReport(0, 0)
            self.state = ScopeState.QUIESCING
            if self._active_operations:
                waiter = (asyncio.get_running_loop(), asyncio.Event())
                self._async_idle_waiters.append(waiter)
        if waiter is not None:
            event = waiter[1]
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise asyncio.TimeoutError
                await asyncio.wait_for(event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                with _CHANGED:
                    active_operations = self._active_operations
                if active_operations:
                    raise ResourceBusyError(
                        f"task {self.task_id} still has {active_operations} active operations"
                    ) from None
            finally:
                with _CHANGED:
                    if waiter in self._async_idle_waiters:
                        self._async_idle_waiters.remove(waiter)
        with _CHANGED:
            active_operations = self._active_operations
            if active_operations:
                raise ResourceBusyError(
                    f"task {self.task_id} still has {active_operations} active operations"
                )
            records = [
                _RESOURCES[resource_id]
                for resource_id in self._resource_ids
                if resource_id in _RESOURCES
                and _RESOURCES[resource_id].state is not ResourceState.RELEASED
            ]
        report = _release_records(records)
        with _CHANGED:
            self.state = ScopeState.CLOSED
            if _TASK_SCOPES.get(self.task_id) is self:
                _TASK_SCOPES.pop(self.task_id, None)
            _CHANGED.notify_all()
        if not report.ok:
            raise ResourceLifecycleError(
                f"task {self.task_id} resource cleanup failed: {report.failed}"
            )
        return report


def current_task_resource_scope() -> TaskResourceScope | None:
    scope = _CURRENT_SCOPE.get()
    if scope is not None:
        return scope
    try:
        from sunpack.coordinator.async_work import CURRENT_WORK

        work = CURRENT_WORK.get()
    except (ImportError, LookupError):
        work = None
    if work is None:
        return None
    with _LOCK:
        return _TASK_SCOPES.get(work.request_id)


def task_resource_scope(task_id: str) -> TaskResourceScope | None:
    with _LOCK:
        return _TASK_SCOPES.get(str(task_id))


def register_current_task_resource(
    owner: Any,
    files: Iterable[os.PathLike[str] | str | FileIdentity],
    release: Callable[[], Any],
    *,
    kind: ResourceKind = ResourceKind.OTHER,
    registration_held: bool = False,
) -> ResourceLease:
    scope = current_task_resource_scope()
    if scope is not None:
        return scope.register(
            owner,
            files,
            release,
            kind=kind,
            registration_held=registration_held,
        )
    # Unscoped resources remain visible to promotion and are released there.
    return register_resource(
        owner,
        files,
        release,
        kind=kind,
        policy=ResourcePolicy.TASK_OWNED,
        registration_held=registration_held,
    )


def register_process_cache_resource(
    owner: Any,
    files: Iterable[os.PathLike[str] | str | FileIdentity],
    release: Callable[[], Any],
    *,
    kind: ResourceKind = ResourceKind.OTHER,
    registration_held: bool = False,
) -> ResourceLease:
    return register_resource(
        owner,
        files,
        release,
        kind=kind,
        policy=ResourcePolicy.PROCESS_CACHE,
        registration_held=registration_held,
    )


def register_service_resource(
    owner: Any,
    files: Iterable[os.PathLike[str] | str | FileIdentity],
    release: Callable[[], Any],
    *,
    kind: ResourceKind = ResourceKind.OTHER,
    registration_held: bool = False,
    promotion_blocking: bool = True,
) -> ResourceLease:
    return register_resource(
        owner,
        files,
        release,
        kind=kind,
        policy=ResourcePolicy.SERVICE_OWNED,
        registration_held=registration_held,
        promotion_blocking=promotion_blocking,
    )


@contextlib.contextmanager
def current_resource_operation() -> Iterator[None]:
    scope = current_task_resource_scope()
    if scope is None:
        yield
    else:
        with scope.operation():
            yield


def resource_snapshot(
    roots: Iterable[os.PathLike[str] | str | FileIdentity] | None = None,
    *,
    include_released: bool = False,
) -> tuple[dict[str, Any], ...]:
    identities = file_identities(roots or (), directories=True)
    with _LOCK:
        records = list(_RESOURCES.values())
        if identities:
            records = [record for record in records if record.overlaps(identities)]
        active_operations = _describe_active_file_operations(identities)
        if not include_released:
            records = [record for record in records if record.state is not ResourceState.RELEASED]
            return tuple([*(record.describe() for record in records), *active_operations])
        history = list(_RELEASE_HISTORY)
        if identities:
            root_paths = tuple(item.path for item in identities)
            history = [
                item
                for item in history
                if any(
                    _is_path_under(str(path), root) or _is_path_under(root, str(path))
                    for path in item.get("files", ())
                    for root in root_paths
                )
            ]
        return tuple([*(record.describe() for record in records), *active_operations, *history])


def _format_busy(records: Sequence[ResourceRecord]) -> str:
    details = "; ".join(
        f"{record.kind.value} policy={record.policy.value} "
        f"task={record.task_id or '<unscoped>'} "
        f"files={[item.path for item in record.files]} created={record.created_from} "
        f"state={record.state.value} error={record.release_error or '-'}"
        for record in records
    )
    return details or "<none>"


def _matching_active_file_operations(
    roots: Sequence[FileIdentity],
    *,
    exclude_task_id: str | None = None,
) -> list[tuple["TaskResourceScope", FileIdentity, int]]:
    matches: list[tuple[TaskResourceScope, FileIdentity, int]] = []
    for scope in _TASK_SCOPES.values():
        if scope.task_id == exclude_task_id or scope.state is ScopeState.CLOSED:
            continue
        for identity, count in scope._active_file_operations.items():
            if count > 0 and (not roots or any(identity.overlaps(root) for root in roots)):
                matches.append((scope, identity, count))
    return matches


def _describe_active_file_operations(
    roots: Sequence[FileIdentity],
) -> list[dict[str, Any]]:
    return [
        {
            "resource_id": f"operation:{scope.task_id}:{identity.path}",
            "task_id": scope.task_id,
            "kind": ResourceKind.FILE_OPERATION.value,
            "policy": ResourcePolicy.TASK_OWNED.value,
            "files": [identity.path],
            "owner_type": "TaskResourceScope",
            "owner": scope.task_id,
            "promotion_blocking": True,
            "state": ResourceState.ACTIVE.value,
            "created_at": scope.created_at,
            "created_thread": None,
            "created_from": "<lightweight file operation>",
            "release_error": "",
            "active_count": count,
        }
        for scope, identity, count in _matching_active_file_operations(roots)
    ]


def _format_active_file_operations(
    operations: Sequence[tuple["TaskResourceScope", FileIdentity, int]],
) -> str:
    return "; ".join(
        f"file_operation task={scope.task_id} files={[identity.path]} active_count={count}"
        for scope, identity, count in operations
    ) or "<none>"


def _release_promotable_records(roots: Sequence[FileIdentity]) -> ReleaseReport:
    with _LOCK:
        records = [
            record
            for record in _matching_active_records(roots)
            if record.policy is ResourcePolicy.PROCESS_CACHE
            or (
                record.policy is ResourcePolicy.TASK_OWNED
                and record.task_id is None
            )
        ]
    return _release_records(records)


def _own_open_files_under(roots: Sequence[FileIdentity]) -> tuple[str, ...]:
    try:
        import psutil

        opened = psutil.Process().open_files()
    except Exception:
        return ()
    matches: list[str] = []
    for item in opened:
        try:
            identity = FileIdentity.from_path(item.path)
        except Exception:
            continue
        if any(identity.overlaps(root) for root in roots):
            matches.append(identity.path)
    return tuple(sorted(set(matches)))


def audit_open_files(
    roots: Iterable[os.PathLike[str] | str | FileIdentity],
) -> tuple[str, ...]:
    return _own_open_files_under(file_identities(roots, directories=True))


def _native_resources_under(roots: Sequence[FileIdentity]) -> tuple[dict[str, Any], ...]:
    try:
        import sunpack_native

        return tuple(
            dict(item)
            for item in sunpack_native.native_resource_snapshot([item.path for item in roots])
        )
    except Exception as exc:
        raise ResourceLifecycleError(f"native resource audit failed: {exc}") from exc


def _begin_native_promotion(roots: Sequence[FileIdentity]) -> int | None:
    try:
        import sunpack_native

        return int(sunpack_native.native_begin_promotion([item.path for item in roots]))
    except Exception as exc:
        raise ResourceLifecycleError(f"native promotion gate failed to start: {exc}") from exc


def _end_native_promotion(token: int | None) -> None:
    if token is None:
        return
    try:
        import sunpack_native

        sunpack_native.native_end_promotion(token)
    except Exception as exc:
        raise ResourceLifecycleError(f"native promotion gate failed to close: {exc}") from exc


def _wait_for_native_resources(
    roots: Sequence[FileIdentity],
    *,
    deadline: float,
) -> tuple[dict[str, Any], ...]:
    try:
        import sunpack_native

        resources = tuple(
            dict(item)
            for item in sunpack_native.native_wait_for_resources(
                [item.path for item in roots],
                max(0.0, deadline - time.monotonic()),
            )
        )
    except Exception as exc:
        raise ResourceLifecycleError(f"native resource wait failed: {exc}") from exc
    if resources:
        raise ResourceBusyError(
            "promotion found live native resources: " + repr(resources)
        )
    return ()


@contextlib.contextmanager
def promotion_barrier(
    roots: Iterable[os.PathLike[str] | str | FileIdentity],
    *,
    cache_releasers: Iterable[Callable[[str], Any]] = (),
    timeout: float = 30.0,
    strict_open_file_audit: bool = False,
    quiesce: bool = True,
) -> Iterator[PromotionBarrierReport]:
    root_identities = file_identities(roots, directories=True)
    if not root_identities:
        yield PromotionBarrierReport(roots=())
        return
    inherited_roots = _CURRENT_PROMOTION_ROOTS.get()
    if inherited_roots and all(
        any(parent.contains(root) for parent in inherited_roots)
        for root in root_identities
    ):
        yield PromotionBarrierReport(roots=tuple(item.path for item in root_identities))
        return
    started = time.monotonic()
    deadline = started + max(0.0, float(timeout))
    token = uuid.uuid4().hex
    current = current_task_resource_scope()
    promotion_started = False
    if quiesce and current is not None:
        current.begin_promotion(timeout=max(0.0, deadline - time.monotonic()))
        promotion_started = True

    released_resources = 0
    if current is not None:
        try:
            # The promoter must stop owning overlapping resources before it
            # waits for other tasks.  Do this before publishing the gate so a
            # borrower can finish naturally instead of being trapped behind
            # the promotion it is needed to release.
            current_report = current.release_under(root_identities)
            released_resources += current_report.released
            if not current_report.ok:
                raise ResourceLifecycleError(f"promotion task cleanup failed: {current_report.failed}")
        except BaseException:
            if promotion_started:
                current.end_promotion()
            raise

    with _CHANGED:
        try:
            while True:
                conflict = _promotion_conflict(root_identities)
                busy = [
                    record
                    for record in _matching_active_records(root_identities)
                    if record.policy is ResourcePolicy.TASK_OWNED and record.task_id is not None
                ]
                active_operations = _matching_active_file_operations(
                    root_identities,
                    exclude_task_id=current.task_id if current is not None else None,
                )
                if conflict is None and not busy and not active_operations:
                    # lifecycle_registration() and file-operation admission
                    # use _CHANGED too.  Holding it across this check and the
                    # insert closes the admission race before mutation starts.
                    _ACTIVE_PROMOTIONS[token] = root_identities
                    _CHANGED.notify_all()
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if conflict is not None and not busy and not active_operations:
                        raise ResourceBusyError("timed out waiting for an overlapping promotion barrier")
                    raise ResourceBusyError(
                        "promotion blocked by active task resources: "
                        + _format_busy(busy)
                        + "; active operations: "
                        + _format_active_file_operations(active_operations)
                    )
                _CHANGED.wait(remaining)
        except BaseException:
            if promotion_started:
                current.end_promotion()
            raise
    native_promotion_token: int | None = None
    report = PromotionBarrierReport(
        roots=tuple(item.path for item in root_identities),
        gate_wait_seconds=time.monotonic() - started,
    )
    context_token = _CURRENT_PROMOTION_ROOTS.set(root_identities)
    try:
        cleanup_started = time.monotonic()
        release_report = _release_promotable_records(root_identities)
        report.released_resources = released_resources + release_report.released
        if not release_report.ok:
            raise ResourceLifecycleError(f"promotion cache cleanup failed: {release_report.failed}")

        native_promotion_token = _begin_native_promotion(root_identities)

        for root in root_identities:
            for releaser in cache_releasers:
                report.cache_reports.append(releaser(root.path))

        with _LOCK:
            busy = _matching_active_records(root_identities)
        if busy:
            raise ResourceBusyError("promotion registry is not clean: " + _format_busy(busy))

        report.native_resource_audit = _wait_for_native_resources(
            root_identities,
            deadline=deadline,
        )
        if strict_open_file_audit:
            report.open_file_audit = _own_open_files_under(root_identities)
            if report.open_file_audit:
                raise ResourceBusyError(
                    "promotion found unregistered process file handles: "
                    + ", ".join(report.open_file_audit)
                )
        report.cleanup_seconds = time.monotonic() - cleanup_started
        yield report
    finally:
        report.barrier_seconds = time.monotonic() - started
        _CURRENT_PROMOTION_ROOTS.reset(context_token)
        try:
            _end_native_promotion(native_promotion_token)
        finally:
            with _CHANGED:
                _ACTIVE_PROMOTIONS.pop(token, None)
                _CHANGED.notify_all()
            if promotion_started:
                current.end_promotion()


class TaskFileHandle:
    def __init__(self, handle: Any, lease: ResourceLease):
        self._handle = handle
        self._lease = lease

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)

    def __iter__(self):
        return iter(self._handle)

    @property
    def closed(self) -> bool:
        return bool(self._handle.closed)

    def close(self) -> None:
        self._lease.close()

    def __enter__(self) -> "TaskFileHandle":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class _NamedTemporaryHandle:
    def __init__(self, handle: Any, name: str, *, delete: bool):
        self._handle = handle
        self.name = name
        self._delete = bool(delete)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)

    def __iter__(self):
        return iter(self._handle)

    @property
    def closed(self) -> bool:
        return bool(self._handle.closed)

    def close(self) -> None:
        try:
            self._handle.close()
        finally:
            if self._delete:
                _remove_named_temporary_file(self.name)


def _remove_named_temporary_file(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def open_task_file(file: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> TaskFileHandle:
    identity = _file_identity(file)
    with lifecycle_registration((identity,)) as identities:
        handle = builtins.open(file, *args, **kwargs)
        try:
            lease = register_current_task_resource(
                handle,
                identities,
                handle.close,
                kind=ResourceKind.PYTHON_FILE,
                registration_held=True,
            )
        except BaseException:
            handle.close()
            raise
    return TaskFileHandle(handle, lease)


def open_service_file(file: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> TaskFileHandle:
    identity = _file_identity(file)
    with lifecycle_registration((identity,)) as identities:
        handle = builtins.open(file, *args, **kwargs)
        try:
            lease = register_resource(
                handle,
                identities,
                handle.close,
                kind=ResourceKind.PYTHON_FILE,
                policy=ResourcePolicy.SERVICE_OWNED,
                registration_held=True,
            )
        except BaseException:
            handle.close()
            raise
    return TaskFileHandle(handle, lease)


def named_task_temporary_file(
    mode: str = "w+b",
    buffering: int = -1,
    encoding: str | None = None,
    newline: str | None = None,
    suffix: str | None = None,
    prefix: str | None = None,
    dir: os.PathLike[str] | str | None = None,
    delete: bool = True,
    *,
    errors: str | None = None,
) -> TaskFileHandle:
    directory = os.fspath(dir if dir is not None else tempfile.gettempdir())
    prefix = tempfile.gettempprefix() if prefix is None else os.fspath(prefix)
    suffix = "" if suffix is None else os.fspath(suffix)
    if not isinstance(directory, str) or not isinstance(prefix, str) or not isinstance(suffix, str):
        raise TypeError("named task temporary files require string paths")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    for _attempt in range(100):
        name = os.path.join(directory, f"{prefix}{uuid.uuid4().hex}{suffix}")
        logical_identity = FileIdentity(path=_normalized_path(name))
        try:
            with lifecycle_registration((logical_identity,)):
                descriptor = os.open(name, flags, 0o600)
                try:
                    raw_handle = os.fdopen(
                        descriptor,
                        mode,
                        buffering,
                        encoding,
                        errors,
                        newline,
                    )
                except BaseException:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    _remove_named_temporary_file(name)
                    raise
                handle = _NamedTemporaryHandle(raw_handle, name, delete=delete)
                try:
                    identity = FileIdentity.from_stat(name, os.fstat(raw_handle.fileno()))
                    lease = register_current_task_resource(
                        handle,
                        (identity,),
                        handle.close,
                        kind=ResourceKind.PYTHON_FILE,
                        registration_held=True,
                    )
                except BaseException:
                    handle.close()
                    _remove_named_temporary_file(name)
                    raise
            return TaskFileHandle(handle, lease)
        except FileExistsError:
            continue
    raise FileExistsError("could not allocate a unique named task temporary file")


class TaskDirectoryIterator:
    def __init__(self, iterator: os.ScandirIterator, lease: ResourceLease):
        self._iterator = iterator
        self._lease = lease

    def __iter__(self) -> "TaskDirectoryIterator":
        return self

    def __next__(self):
        return next(self._iterator)

    def close(self) -> None:
        self._lease.close()

    def __enter__(self) -> "TaskDirectoryIterator":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def task_scandir(path: os.PathLike[str] | str = ".") -> TaskDirectoryIterator:
    identity = _file_identity(path, directory=True)
    with lifecycle_registration((identity,)) as identities:
        iterator = os.scandir(path)
        try:
            lease = register_current_task_resource(
                iterator,
                identities,
                iterator.close,
                kind=ResourceKind.DIRECTORY_ITERATOR,
                registration_held=True,
            )
        except BaseException:
            iterator.close()
            raise
    return TaskDirectoryIterator(iterator, lease)


def task_walk(
    top: os.PathLike[str] | str,
    *,
    topdown: bool = True,
    onerror: Callable[[OSError], Any] | None = None,
    followlinks: bool = False,
) -> Iterator[tuple[str, list[str], list[str]]]:
    top_path = os.fspath(top)
    try:
        with task_scandir(top_path) as entries:
            materialized = list(entries)
    except OSError as exc:
        if onerror is not None:
            onerror(exc)
        return
    directories: list[str] = []
    files: list[str] = []
    for entry in materialized:
        try:
            is_dir = entry.is_dir()
        except OSError:
            is_dir = False
        (directories if is_dir else files).append(entry.name)
    if topdown:
        yield top_path, directories, files
    for name in directories:
        child = os.path.join(top_path, name)
        if followlinks or not os.path.islink(child):
            yield from task_walk(child, topdown=topdown, onerror=onerror, followlinks=followlinks)
    if not topdown:
        yield top_path, directories, files


def read_task_bytes(path: os.PathLike[str] | str) -> bytes:
    with open_task_file(path, "rb") as handle:
        return handle.read()


def write_task_bytes(path: os.PathLike[str] | str, data: bytes) -> int:
    with open_task_file(path, "wb") as handle:
        return int(handle.write(data))


def read_task_text(
    path: os.PathLike[str] | str,
    *,
    encoding: str = "utf-8",
    errors: str | None = None,
) -> str:
    kwargs = {"encoding": encoding}
    if errors is not None:
        kwargs["errors"] = errors
    with open_task_file(path, "r", **kwargs) as handle:
        return str(handle.read())


def write_task_text(
    path: os.PathLike[str] | str,
    data: str,
    *,
    encoding: str = "utf-8",
    errors: str | None = None,
) -> int:
    kwargs = {"encoding": encoding}
    if errors is not None:
        kwargs["errors"] = errors
    with open_task_file(path, "w", **kwargs) as handle:
        return int(handle.write(data))


def task_glob(path: os.PathLike[str] | str, pattern: str) -> list[Path]:
    root = Path(path)
    with task_scandir(root) as iterator:
        return [root / entry.name for entry in iterator if Path(entry.name).match(pattern)]


def task_rglob(path: os.PathLike[str] | str, pattern: str) -> list[Path]:
    root = Path(path)
    matches: list[Path] = []
    for current, directories, files in task_walk(root):
        current_path = Path(current)
        for name in (*directories, *files):
            candidate = current_path / name
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                continue
            if relative.match(pattern):
                matches.append(candidate)
    return matches


def reset_resource_lifecycle_for_tests() -> None:
    """Fail loudly on leaked resources, then reset global coordination state."""

    with _LOCK:
        records = [record for record in _RESOURCES.values() if record.state is not ResourceState.RELEASED]
    report = _release_records(records)
    with _CHANGED:
        _RESOURCES.clear()
        _RELEASE_HISTORY.clear()
        _TASK_SCOPES.clear()
        _ACTIVE_PROMOTIONS.clear()
        _CHANGED.notify_all()
    if not report.ok:
        raise ResourceLifecycleError(f"test lifecycle reset failed: {report.failed}")
