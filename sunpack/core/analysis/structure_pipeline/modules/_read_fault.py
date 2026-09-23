from __future__ import annotations


def read_fault_damage_flags(native: dict) -> list[str]:
    """Project a native field-level read fault into input-integrity evidence."""

    fault = native.get("read_error")
    if not isinstance(fault, dict):
        return list(native.get("damage_flags") or [])
    flags = list(native.get("damage_flags") or [])
    flags.append("read_error")
    if str(fault.get("code") or "") == "unexpected_eof":
        flags.append("input_truncated")
    field = str(fault.get("field") or "").strip()
    if field:
        flags.append(f"field_read_error:{field}")
    if fault.get("possible_missing_volume"):
        flags.append("missing_volume")
    return list(dict.fromkeys(str(flag) for flag in flags if flag))
