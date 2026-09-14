from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from sunpack.filesystem.watcher.scanner import WatchCandidate
from sunpack.filesystem.watcher.state import WatchStateStore
from sunpack.support.path_keys import path_key

from .group_models import WatchGroupSnapshot
from .group_models import BLOCKER_MISSING_VOLUME, BLOCKER_PASSWORD


@dataclass(frozen=True)
class WatchDispatch:
    candidate: WatchCandidate
    group: WatchGroupSnapshot | None = None


@dataclass(frozen=True)
class DeferredWatch:
    """A ready split member postponed for group coordination.

    ``group`` is populated for members deferred because another member of the
    same split group is still pending or in flight.  ``group`` is ``None`` for
    dispatch-level deferrals such as output-root conflicts.
    """

    candidate: WatchCandidate
    group: WatchGroupSnapshot | None = None


class WatchGroupResolver(Protocol):
    def resolve_paths(self, paths: list[str]) -> dict[str, WatchGroupSnapshot | None]: ...


class NullWatchGroupResolver:
    def resolve_paths(self, paths: list[str]) -> dict[str, WatchGroupSnapshot | None]:
        return {path_key(path): None for path in paths}


def plan_watch_dispatches(
    ready: list[WatchCandidate],
    *,
    active_paths: set[str],
    coordinator: WatchGroupResolver,
    state: WatchStateStore,
    prepare_candidate: Callable[[str], WatchCandidate | None],
) -> tuple[list[WatchDispatch], list[WatchGroupSnapshot], list[DeferredWatch]]:
    """Collapse quiet part events into one canonical head dispatch per split group."""
    if not ready:
        return [], [], []
    resolved = coordinator.resolve_paths([candidate.path for candidate in ready])
    dispatches: list[WatchDispatch] = []
    waiting: list[WatchGroupSnapshot] = []
    deferred: list[DeferredWatch] = []
    seen_groups: set[str] = set()
    deferred_groups: set[str] = set()

    for candidate in ready:
        snapshot = resolved.get(path_key(candidate.path))
        if snapshot is None:
            entry = state.latest_entry_for_path(candidate.path)
            blockers = _entry_blockers(entry)
            if BLOCKER_MISSING_VOLUME in blockers:
                continue
            dispatches.append(WatchDispatch(candidate=candidate))
            continue
        if snapshot.group_id in seen_groups:
            # Co-ready members of a group handled earlier in this tick are
            # covered by that dispatch.  When the group was deferred instead,
            # keep every co-ready member pending so the whole group can
            # dispatch together once its remaining members are ready.
            if snapshot.group_id in deferred_groups:
                deferred.append(DeferredWatch(candidate=candidate, group=snapshot))
            continue
        seen_groups.add(snapshot.group_id)
        if any(path_key(member) in active_paths for member in snapshot.owned_paths):
            deferred_groups.add(snapshot.group_id)
            deferred.append(DeferredWatch(candidate=candidate, group=snapshot))
            continue
        if not snapshot.has_head:
            state.record_group_waiting(snapshot)
            waiting.append(snapshot)
            continue
        previous = state.group_state(snapshot.group_id)
        if previous is not None and not previous.retry_ready(snapshot, state.password_generation):
            continue
        if previous is None:
            member_entries = [
                entry
                for path in snapshot.input_paths
                if (entry := state.latest_entry_for_path(path)) is not None
            ]
            inherited = set().union(*(_entry_blockers(entry) for entry in member_entries)) if member_entries else set()
            if BLOCKER_PASSWORD in inherited:
                password_generation = max(
                    (entry.password_generation for entry in member_entries if BLOCKER_PASSWORD in _entry_blockers(entry)),
                    default=state.password_generation,
                )
                if state.password_generation <= password_generation:
                    continue
        head_key = path_key(snapshot.head_path)
        selected = candidate if path_key(candidate.path) == head_key else prepare_candidate(snapshot.head_path)
        if selected is None:
            state.record_group_waiting(snapshot)
            waiting.append(snapshot)
            continue
        state.record_group_attempt(snapshot)
        dispatches.append(WatchDispatch(candidate=selected, group=snapshot))
    return dispatches, waiting, deferred


def _entry_blockers(entry) -> set[str]:
    if entry is None:
        return set()
    payload = entry.failure_payload if isinstance(entry.failure_payload, dict) else {}
    explicit = payload.get("blockers")
    if isinstance(explicit, list):
        return {str(value) for value in explicit}
    blockers: set[str] = set()
    if entry.status == "failed_password":
        blockers.add(BLOCKER_PASSWORD)
    if entry.status == "suspended_missing_volume" or _payload_contains_kind(payload, BLOCKER_MISSING_VOLUME):
        blockers.add(BLOCKER_MISSING_VOLUME)
    return blockers


def _payload_contains_kind(payload: dict, kind: str) -> bool:
    if str(payload.get("kind") or "") == kind:
        return True
    return any(
        isinstance(cause, dict) and _payload_contains_kind(cause, kind)
        for cause in payload.get("causes") or []
    )
