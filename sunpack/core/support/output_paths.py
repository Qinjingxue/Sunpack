import heapq
import os
import re
from collections import OrderedDict
from collections.abc import Container, MutableSet

from sunpack.core.support.path_keys import absolute_path_key, path_key_is_under
from sunpack.core.contracts.tasks import ArchiveTask


def default_output_dir_for_task(task: ArchiveTask, output_config: dict | None = None) -> str:
    """Build the preferred output path; the reservation layer resolves collisions."""
    output_config = output_config if isinstance(output_config, dict) else {}
    path = task.main_path
    out_name = task.logical_name or os.path.splitext(os.path.basename(path))[0]
    if output_config.get("root"):
        output_root = os.path.abspath(os.path.normpath(str(output_config.get("root"))))
        common_root = output_config.get("common_root")
        # Recursive archives are created below the configured output root.  In
        # that case their output must stay beside the generated archive instead
        # of being relativized against the original input root.
        relative_root = output_root if _is_relative_to(os.path.dirname(path), output_root) else common_root
        relative_parent = "" if output_config.get("fixed_root") and not task.runtime.get("nested_output") else _relative_parent(path, relative_root)
        out_dir = os.path.join(output_root, relative_parent, os.path.basename(out_name))
    else:
        out_dir = os.path.join(os.path.dirname(path), os.path.basename(out_name))
    # Absolute normalized path: the write-routing key and the extraction request must come from the identical string.
    return normalized_output_dir(out_dir)


def _relative_parent(path: str, common_root: str | None) -> str:
    parent = os.path.dirname(os.path.abspath(os.path.normpath(path)))
    if not common_root:
        return ""
    root = os.path.abspath(os.path.normpath(str(common_root)))
    try:
        relative = os.path.relpath(parent, root)
    except ValueError:
        return _safe_path_component(parent)
    if relative in {"", "."}:
        return ""
    if relative.startswith("..") and (relative == ".." or relative.startswith(".." + os.sep)):
        return _safe_path_component(parent)
    return relative


def _safe_path_component(value: str) -> str:
    drive, tail = os.path.splitdrive(os.path.abspath(value))
    text = (drive.rstrip(":") + "_" + tail.strip(os.sep)).strip("_")
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text) or "input"


def _is_relative_to(path: str, root: str) -> bool:
    candidate = absolute_path_key(path)
    normalized_root = absolute_path_key(root)
    return path_key_is_under(candidate, normalized_root)


def normalized_output_dir(path: str) -> str:
    """Absolute, normalized output path.

    The volume key and the extraction request must derive from the same string; a relative
    path resolved in two different places would mis-route the per-volume write facility.
    """
    return os.path.abspath(os.path.normpath(str(path)))


def resolve_output_volume_key(path: str) -> str:
    """Volume identity for an output path, or an empty string when unknown.

    Reported by the Rust layer, because the output directory usually does not exist yet when
    the job is built.  An empty result makes the caller substitute a synthetic per-job key so
    the job still gets its own write facility.
    """
    try:
        from sunpack_native import resolve_output_volume_key as _resolve

        return str(_resolve(normalized_output_dir(path)) or "")
    except Exception:
        return ""


class _NumberedPaths:
    _RELEASED_HISTORY_LIMIT = 256

    def __init__(self, start: int):
        self.next_index = start
        self.available: list[int] = []
        self.observed_slots: set[str] = set()

    def take(self) -> int:
        if self.available and self.available[0] < self.next_index:
            return heapq.heappop(self.available)
        index = self.next_index
        self.next_index += 1
        if self.available and self.available[0] == index:
            heapq.heappop(self.available)
        return index

    def release(self, index: int) -> None:
        if len(self.available) >= self._RELEASED_HISTORY_LIMIT:
            # Rewind the bounded search hint rather than losing reusable names.
            self.next_index = min(self.next_index, self.available[0], index)
            self.available.clear()
        else:
            heapq.heappush(self.available, index)


class OutputPathAllocator:
    """Cache numbered searches; the caller serializes allocation and release."""

    _FAMILY_HISTORY_LIMIT = 256

    def __init__(self):
        self._numbers: OrderedDict[tuple[str, int], _NumberedPaths] = OrderedDict()
        # Different starting names can visit the same numbered alternative.
        self._slots: dict[str, dict[_NumberedPaths, int]] = {}

    def next_available(
        self,
        path: str,
        reserved: Container[str],
        local_reserved: Container[str] = (),
        *,
        is_directory: bool = False,
    ) -> str:
        candidate = os.path.normpath(path)
        key = absolute_path_key(candidate)
        if key not in reserved and key not in local_reserved and not os.path.exists(candidate):
            return candidate

        parent = os.path.dirname(candidate)
        name = os.path.basename(candidate)
        stem, extension = (name, "") if is_directory else os.path.splitext(name)
        match = re.fullmatch(r"(.*)\((\d+)\)", stem)
        base_stem = stem if match is None else match.group(1)
        start = 1 if match is None else int(match.group(2)) + 1
        family = (absolute_path_key(os.path.join(parent, base_stem + extension)), start)
        numbers = self._numbers.get(family)
        if numbers is None:
            numbers = self._numbers[family] = _NumberedPaths(start)
            if len(self._numbers) > self._FAMILY_HISTORY_LIMIT:
                _, evicted = self._numbers.popitem(last=False)
                # Eviction retains actual reservations, but drops search-only
                # references to other owners' paths.
                for observed_key in evicted.observed_slots:
                    slots = self._slots[observed_key]
                    slots.pop(evicted)
                    if not slots:
                        self._slots.pop(observed_key)
                evicted.observed_slots.clear()
        else:
            self._numbers.move_to_end(family)

        local_slots: list[int] = []
        try:
            while True:
                index = numbers.take()
                candidate = os.path.join(parent, f"{base_stem}({index}){extension}")
                key = absolute_path_key(candidate)
                # Cache shared and on-disk occupancy, but keep local exclusions
                # available to other requests. Always check a selected slot live.
                if key not in reserved and key in local_reserved:
                    local_slots.append(index)
                    continue
                if key in reserved:
                    self._slots.setdefault(key, {})[numbers] = index
                    numbers.observed_slots.add(key)
                elif not os.path.exists(candidate):
                    self._slots.setdefault(key, {})[numbers] = index
                    return candidate
        finally:
            for index in local_slots:
                numbers.release(index)

    def release(self, path_key: str) -> None:
        for numbers, index in self._slots.pop(path_key, {}).items():
            numbers.observed_slots.discard(path_key)
            numbers.release(index)

    def clear_cache(self) -> dict[str, int]:
        counts = {"families": len(self._numbers), "slots": len(self._slots)}
        self._numbers.clear()
        self._slots.clear()
        return counts


def next_available_path(path: str, reserved: MutableSet[str] | None = None) -> str:
    """Return and optionally reserve an available browser-style alternative."""
    candidate = OutputPathAllocator().next_available(path, reserved if reserved is not None else ())
    if reserved is not None:
        reserved.add(absolute_path_key(candidate))
    return candidate
