import os

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.path_keys import normalized_path


def default_output_dir_for_task(task: ArchiveTask, output_config: dict | None = None) -> str:
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
    if normalized_path(out_dir) == normalized_path(path):
        out_dir += "_extracted"
    # Return an absolute normalized path so callers derive the write-routing key
    # and the extraction request from the identical string.
    return normalized_output_dir(_non_existing_output_dir(out_dir))


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

    The volume key and the extraction request must be derived from the same path
    string: resolving a relative path in one place and letting the worker resolve
    it against its own working directory in another would silently mis-route the
    per-volume write facility.
    """
    return os.path.abspath(os.path.normpath(str(path)))


def resolve_output_volume_key(path: str) -> str:
    """Volume identity for an output path, or an empty string when unknown.

    Reported by the Rust layer (nearest existing ancestor -> canonicalize ->
    volume GUID), because the output directory usually does not exist yet when the
    job is built.  An empty result is not fatal: the caller substitutes a
    synthetic per-job key so the job still gets its own write facility instead of
    sharing another volume's.
    """
    try:
        from sunpack_native import resolve_output_volume_key as _resolve

        return str(_resolve(normalized_output_dir(path)) or "")
    except Exception:
        return ""


def _non_existing_output_dir(path: str) -> str:
    if not os.path.exists(path):
        return path

    base = f"{path}_extracted"
    if not os.path.exists(base):
        return base

    index = 2
    while True:
        candidate = f"{base}_{index}"
        if not os.path.exists(candidate):
            return candidate
        index += 1
