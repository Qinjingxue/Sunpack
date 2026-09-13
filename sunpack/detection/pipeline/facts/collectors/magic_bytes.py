from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts

from sunpack.detection.pipeline.facts.registry import register_fact


@register_fact(
    "file.magic_bytes",
    type="bytes",
    description="First 16 bytes used by processors and rules for magic signature checks.",
    context=True,
)
def collect_magic_bytes(context) -> bytes:
    base_path = context.fact_bag.get("file.path") or context.base_path
    scan_session = getattr(context, "scan_session", None)
    if scan_session is not None:
        facts = scan_session.file_head_facts_for_path(base_path, magic_size=16)
        magic = facts.get("magic")
        if isinstance(magic, bytes):
            return magic[:16]
    rows = _native_batch_file_head_facts([base_path], 16)
    if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("magic"), bytes):
        return rows[0]["magic"][:16]
    return b""
