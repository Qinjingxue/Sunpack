from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict

from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.passwords.internal.store import PasswordStore
from sunpack.relations.scheduler import RelationsScheduler
from sunpack.support.path_keys import path_key

from sunpack.filesystem.watcher.group_models import WatchGroupSnapshot
from sunpack.filesystem.watcher.scanner import watch_candidate_for_path


class WatchGroupCoordinator:
    """Resolve stable file events to canonical split-archive groups."""

    def __init__(self, config: dict, *, password_tester=None):
        self.config = config
        self.relations = RelationsScheduler(config)
        self.password_store = (
            password_tester.password_store
            if password_tester is not None
            else PasswordStore.from_sources(
                cli_passwords=list(config.get("user_passwords") or []),
                builtin_passwords=list(config.get("builtin_passwords") or []),
            )
        )

    def set_password_callback(self, callback) -> None:
        """Register a listener for passwords discovered by the relation prober."""
        self.relations.set_password_callback(callback)

    def resolve_paths(self, paths: list[str]) -> dict[str, WatchGroupSnapshot | None]:
        by_directory: dict[str, list[str]] = defaultdict(list)
        for path in paths:
            by_directory[os.path.dirname(os.path.abspath(path))].append(os.path.abspath(path))

        resolved: dict[str, WatchGroupSnapshot | None] = {}
        for directory, directory_paths in by_directory.items():
            session = DetectionScanSession(self.relations, config=self.config)
            groups = session.relation_groups_for_directory(directory)
            snapshots = [self._snapshot(group, directory) for group in groups if group.kind == "split_archive"]
            snapshots.extend(
                self._seed_snapshots(
                    directory,
                    session.relation_seed_states_for_directory(directory),
                )
            )
            for path in directory_paths:
                selected = next(
                    (snapshot for snapshot in snapshots if path_key(path) in {path_key(item) for item in snapshot.owned_paths}),
                    None,
                )
                resolved[path_key(path)] = selected
        return resolved

    def refresh_password_sources(self) -> None:
        """Synchronize the prober's store with the watch scheduler's live sources."""
        self.relations.refresh_password_sources()

    def resolve_head(self, head_path: str) -> WatchGroupSnapshot | None:
        return self.resolve_paths([head_path]).get(path_key(head_path))

    def _snapshot(self, group, directory: str) -> WatchGroupSnapshot:
        volumes = list(group.split_volumes or [])
        first = next((volume for volume in volumes if volume.number == 1), None)
        head_path = os.path.abspath(first.path) if first is not None else ""
        input_paths = tuple(os.path.abspath(path) for path in group.input_paths)
        companion_paths = tuple(os.path.abspath(path) for path in (group.companion_paths or []))
        owned_paths = tuple(os.path.abspath(path) for path in group.owned_paths)
        split_family = str(group.relation.split_family or (volumes[0].style if volumes else "split"))
        group_id = _group_id(directory, group.logical_name, split_family)
        payload = {
            "group_id": group_id,
            "members": [_file_version(path) for path in input_paths],
            "sources": [str(volume.source) for volume in volumes],
        }
        input_fingerprint = _fingerprint(payload)
        ownership_fingerprint = _fingerprint({
            **payload,
            "owned_members": [_file_version(path) for path in owned_paths],
        })
        return WatchGroupSnapshot(
            group_id=group_id,
            directory=os.path.abspath(directory),
            logical_name=str(group.logical_name),
            split_family=split_family,
            head_path=head_path,
            input_paths=input_paths,
            companion_paths=companion_paths,
            owned_paths=owned_paths,
            input_fingerprint=input_fingerprint,
            ownership_fingerprint=ownership_fingerprint,
        )

    def _seed_snapshots(
        self,
        directory: str,
        seed_states: list[dict[str, object]],
    ) -> list[WatchGroupSnapshot]:
        """Represent a structurally proven incomplete seed as existing wait state.

        The snapshot deliberately has no head.  ``plan_watch_dispatches`` already
        records such a snapshot as waiting and will reconsider it on the next
        filesystem event; no separate incomplete-volume state is introduced.
        """
        grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
        for state in seed_states:
            logical_name = str(state.get("logical_name") or "")
            split_family = str(state.get("split_family") or "")
            if not logical_name or not split_family:
                continue
            key = (logical_name.casefold(), split_family.casefold())
            paths = state.get("related_paths") or [state.get("path")]
            grouped[key].update(str(path) for path in paths if path)

        snapshots: list[WatchGroupSnapshot] = []
        for (logical_key, family_key), paths in grouped.items():
            input_paths = tuple(sorted(paths, key=path_key))
            if not input_paths:
                continue
            logical_name = next(
                (
                    str(state.get("logical_name"))
                    for state in seed_states
                    if str(state.get("logical_name") or "").casefold() == logical_key
                    and str(state.get("split_family") or "").casefold() == family_key
                ),
                logical_key,
            )
            split_family = next(
                (
                    str(state.get("split_family"))
                    for state in seed_states
                    if str(state.get("logical_name") or "").casefold() == logical_key
                    and str(state.get("split_family") or "").casefold() == family_key
                ),
                family_key,
            )
            group_id = _group_id(directory, logical_name, split_family)
            payload = {
                "group_id": group_id,
                "members": [_file_version(path) for path in input_paths],
                "sources": ["seed"],
            }
            snapshots.append(
                WatchGroupSnapshot(
                    group_id=group_id,
                    directory=os.path.abspath(directory),
                    logical_name=logical_name,
                    split_family=split_family,
                    head_path="",
                    input_paths=input_paths,
                    companion_paths=(),
                    owned_paths=input_paths,
                    input_fingerprint=_fingerprint(payload),
                    ownership_fingerprint=_fingerprint(payload),
                )
            )
        return snapshots

def _group_id(directory: str, logical_name: str, split_family: str) -> str:
    raw = "|".join((path_key(directory), split_family.lower(), logical_name.lower()))
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _fingerprint(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _file_version(path: str) -> tuple[str, int, int, str, int]:
    try:
        stat = os.stat(path)
    except OSError:
        return path_key(path), 0, 0, "", 0
    candidate = watch_candidate_for_path(path)
    return (
        path_key(path),
        int(stat.st_size),
        int(stat.st_mtime_ns),
        str(candidate.file_id if candidate is not None else ""),
        int(candidate.change_usn if candidate is not None else 0),
    )
