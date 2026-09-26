import heapq
import os
import re
from collections.abc import Container, MutableSet

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support.path_keys import absolute_path_key


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
        relative_parent = _relative_parent(path, relative_root)
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
    try:
        return os.path.commonpath((os.path.abspath(path), os.path.abspath(root))) == os.path.abspath(root)
    except ValueError:
        return False


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
    def __init__(self, start: int):
        self.next_index = start
        self.available: list[int] = []

    def take(self) -> int:
        if self.available:
            return heapq.heappop(self.available)
        index = self.next_index
        self.next_index += 1
        return index


class OutputPathAllocator:
    """Cache numbered searches; the caller serializes allocation and release."""

    def __init__(self):
        self._numbers: dict[tuple[str, int], _NumberedPaths] = {}
        # Different starting names can visit the same numbered alternative.
        self._slots: dict[str, dict[_NumberedPaths, int]] = {}

    def next_available(
        self,
        path: str,
        reserved: Container[str],
        local_reserved: Container[str] = (),
    ) -> str:
        candidate = os.path.normpath(path)
        key = absolute_path_key(candidate)
        if key not in reserved and key not in local_reserved and not os.path.exists(candidate):
            return candidate

        parent = os.path.dirname(candidate)
        stem, extension = os.path.splitext(os.path.basename(candidate))
        match = re.fullmatch(r"(.*)\((\d+)\)", stem)
        base_stem = stem if match is None else match.group(1)
        start = 1 if match is None else int(match.group(2)) + 1
        family = (absolute_path_key(os.path.join(parent, base_stem + extension)), start)
        numbers = self._numbers.get(family)
        if numbers is None:
            numbers = self._numbers[family] = _NumberedPaths(start)

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
                self._slots.setdefault(key, {})[numbers] = index
                if key not in reserved and not os.path.exists(candidate):
                    return candidate
        finally:
            for index in local_slots:
                heapq.heappush(numbers.available, index)

    def release(self, path_key: str) -> None:
        for numbers, index in self._slots.pop(path_key, {}).items():
            heapq.heappush(numbers.available, index)


def next_available_path(path: str, reserved: MutableSet[str] | None = None) -> str:
    """Return and optionally reserve an available browser-style alternative."""
    candidate = OutputPathAllocator().next_available(path, reserved if reserved is not None else ())
    if reserved is not None:
        reserved.add(absolute_path_key(candidate))
    return candidate
