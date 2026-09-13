from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts

from sunpack.detection.pipeline.facts.registry import register_fact


@register_fact(
    "file.path",
    type="str",
    description="Absolute or normalized path of the candidate file.",
)
def collect_file_path(base_path: str) -> str:
    return base_path


@register_fact(
    "file.size",
    type="int",
    description="File size in bytes, or -1 if unavailable.",
    context=True,
)
def collect_file_size(context) -> int:
    existing = context.fact_bag.get("file.size")
    if isinstance(existing, int):
        return existing
    scan_session = getattr(context, "scan_session", None)
    base_path = context.fact_bag.get("file.path") or context.base_path
    if scan_session is not None:
        facts = scan_session.file_head_facts_for_path(base_path, magic_size=0)
        size = facts.get("size")
        if isinstance(size, int):
            return size
    rows = _native_batch_file_head_facts([base_path], 0)
    if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("size"), int):
        return int(rows[0]["size"])
    return -1
