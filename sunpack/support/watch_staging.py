from __future__ import annotations

import hashlib
import os
from pathlib import Path

from sunpack_native import (
    publish_watch_staged_output as _native_publish,
    watch_path_identity as _native_path_identity,
)
from sunpack.support.output_cleanup import cleanup_watch_staging_path
from sunpack.support.output_inventory import OutputInventory

STAGING_PREFIX = ".sunpack-partial-"


def staging_output_dir(final_output_dir: str, source_path: str) -> str:
    final = os.path.abspath(final_output_dir)
    source = os.path.abspath(source_path)
    stat = os.stat(source)
    material = "\0".join((
        os.path.normcase(source),
        str(int(stat.st_size)),
        str(int(stat.st_mtime_ns)),
        os.path.normcase(final),
    )).encode("utf-8", "surrogatepass")
    digest = hashlib.blake2b(material, digest_size=12).hexdigest()
    return os.path.join(os.path.dirname(final), f"{STAGING_PREFIX}{digest}")


def is_staging_path(path: str) -> bool:
    try:
        return any(part.lower().startswith(STAGING_PREFIX) for part in Path(os.path.abspath(path)).parts)
    except (OSError, ValueError):
        return False


def prepare_staging_output(final_output_dir: str, source_path: str) -> str:
    staging = staging_output_dir(final_output_dir, source_path)
    parent = os.path.dirname(staging)
    os.makedirs(parent, exist_ok=True)
    if os.path.lexists(staging):
        _remove_staging_path(staging)
    return staging


def _remove_staging_path(staging: str) -> None:
    result = cleanup_watch_staging_path(staging)
    if result.cleaned or result.already_absent:
        return
    detail = f": {result.error}" if result.error else ""
    raise OSError(f"watch staging cleanup failed ({result.reason}){detail}")


def cleanup_staging_output(staging: str) -> None:
    if not staging or not is_staging_path(staging) or not os.path.lexists(staging):
        return
    _remove_staging_path(staging)


def publish_staging_output(staging: str, final_output_dir: str) -> None:
    _native_publish(str(staging), str(final_output_dir))


def staging_file_identity(staging: str) -> str:
    _volume, file_id, _change_usn = _native_path_identity(str(staging))
    return str(file_id or "")


def _rebase_path(path: str, old_root: str, new_root: str) -> str:
    if not path:
        return path
    absolute = os.path.abspath(path)
    old = os.path.abspath(old_root)
    try:
        relative = os.path.relpath(absolute, old)
    except ValueError:
        return path
    if relative == os.curdir:
        return os.path.abspath(new_root)
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return path
    return os.path.abspath(os.path.join(new_root, relative))


def _rebase_inventory_payload(payload, old_root: str, new_root: str):
    if not isinstance(payload, dict):
        return payload
    updated = dict(payload)
    if updated.get("root"):
        updated["root"] = _rebase_path(str(updated["root"]), old_root, new_root)
    raw_files = updated.get("files")
    if isinstance(raw_files, list):
        files = []
        for raw in raw_files:
            if not isinstance(raw, dict):
                files.append(raw)
                continue
            item = dict(raw)
            for key in ("abs_path", "output_path"):
                value = item.get(key)
                if value and os.path.isabs(str(value)):
                    item[key] = _rebase_path(str(value), old_root, new_root)
            files.append(item)
        updated["files"] = files
    return updated


def rebase_extraction_result(result, staging_root: str, final_root: str) -> None:
    """Retarget one verified result after the staging directory is renamed.

    Native inventories retain their Rust file table and only rebase absolute
    paths/root metadata, so publishing does not force a second filesystem scan.
    """
    if result is None:
        return
    current_out = str(getattr(result, "out_dir", "") or "")
    rebased_out = _rebase_path(current_out, staging_root, final_root)
    if current_out:
        result.out_dir = rebased_out
    manifest = str(getattr(result, "progress_manifest", "") or "")
    if manifest:
        result.progress_manifest = _rebase_path(manifest, staging_root, final_root)
    inventory = getattr(result, "output_inventory", None)
    if isinstance(inventory, OutputInventory):
        new_inventory_root = _rebase_path(inventory.root, staging_root, final_root)
        result.output_inventory = inventory.rebased_root(new_inventory_root)
    payload = getattr(result, "output_inventory_payload", None)
    if isinstance(payload, dict):
        result.output_inventory_payload = _rebase_inventory_payload(
            payload, staging_root, final_root
        )
    embedded = list(getattr(result, "embedded_results", None) or [])
    for segment, child in embedded:
        if isinstance(segment, dict) and segment.get("out_dir"):
            segment["out_dir"] = _rebase_path(
                str(segment["out_dir"]), staging_root, final_root
            )
        rebase_extraction_result(child, staging_root, final_root)
