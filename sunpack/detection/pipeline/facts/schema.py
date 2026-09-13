from typing import Any


FACT_SCHEMA: dict[str, dict[str, Any]] = {
    "file.path": {
        "type": "str",
        "producer": "facts.collectors.file_facts",
        "description": "Absolute or normalized path of the candidate file.",
    },
    "file.size": {
        "type": "int",
        "producer": "facts.collectors.file_facts",
        "description": "File size in bytes, or -1 if unavailable.",
    },
    "file.magic_bytes": {
        "type": "bytes",
        "producer": "facts.collectors.magic_bytes",
        "description": "First 16 bytes used by processors and rules for magic signature checks.",
    },
    "relation.is_split_related": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the candidate belongs to a split-volume relation.",
    },
    "file.is_split_candidate": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the candidate name looks like a split-volume member.",
    },
    "file.split_role": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Split relation role, such as first/member.",
    },
    "file.split_members": {
        "type": "list[str]",
        "producer": "relations.group_builder",
        "description": "Other paths that belong to the same split group.",
    },
    "file.logical_name": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Logical archive/group name derived from related paths.",
    },
    "candidate.kind": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Logical candidate kind, such as file or split_archive.",
    },
    "candidate.entry_path": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Actual archive input entry used for detection structure analysis and extraction; may differ from a PE SFX carrier.",
    },
    "candidate.member_paths": {
        "type": "list[str]",
        "producer": "relations.group_builder",
        "description": "Actual archive data-volume paths belonging to the logical candidate; excludes launcher-only SFX carriers.",
    },
    "candidate.carrier_path": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Filesystem path used as the detection carrier, such as a PE SFX launcher.",
    },
    "candidate.companion_paths": {
        "type": "list[str]",
        "producer": "relations.group_builder",
        "description": "Launcher or other owned companion paths related to the candidate but excluded from archive input volumes.",
    },
    "candidate.cleanup_paths": {
        "type": "list[str]",
        "producer": "relations.group_builder",
        "description": "Data and companion paths to remove after a successful extraction.",
    },
    "candidate.logical_name": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Logical display/group name for the candidate.",
    },
    "relation.split_entry_path": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Preferred entry path for the split relation.",
    },
    "relation.split_member_count": {
        "type": "int",
        "producer": "relations.group_builder",
        "description": "Number of paths in the split relation candidate.",
    },
    "relation.split_group_complete": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the relation layer considers the split group complete enough to represent.",
    },
    "relation.split_missing_reason": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Reason a split group was marked incomplete, such as missing_head or missing_middle.",
    },
    "relation.split_missing_indices": {
        "type": "list",
        "producer": "relations.group_builder",
        "description": "Split volume numbers that appear to be missing before the last observed volume.",
    },
    "relation.split_observed_missing_ranges": {
        "type": "list",
        "producer": "relations.group_builder",
        "description": "Compact filename-observed gap ranges; these are hints, not backend-confirmed missing volumes.",
    },
    "relation.split_layout_status": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Filename-layout assessment: coherent, observed_gap, or ambiguous.",
    },
    "relation.split_completeness_status": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Structured relation assessment: coherent, middle_gap, tail_missing, or ambiguous.",
    },
    "relation.split_completeness_confidence": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Evidence confidence for the completeness assessment: hint, strong, or proven.",
    },
    "relation.split_completeness_basis": {
        "type": "list",
        "producer": "relations.group_builder",
        "description": "Machine-readable evidence used by the relation completeness assessment.",
    },
    "relation.split_family": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Split naming family, such as 7z_numbered, rar_part, or exe_companion.",
    },
    "relation.split_index": {
        "type": "int",
        "producer": "relations.group_builder",
        "description": "Numeric index of the entry volume when available.",
    },
    "relation.split_is_first": {
        "type": "bool",
        "producer": "relations.group_builder",
        "description": "Whether the logical candidate entry is the first split volume.",
    },
    "relation.split_volumes": {
        "type": "list",
        "producer": "relations.group_builder",
        "description": "Structured split volume entries with path, inferred number, role, and naming style.",
    },
    "file.detected_ext": {
        "type": "str",
        "producer": "rules.precheck",
        "description": "Archive extension inferred from magic/probe/embedded evidence.",
    },
    "file.magic_matched": {
        "type": "bool",
        "producer": "rules.precheck",
        "description": "Whether archive identity matched a strong magic signature.",
    },
    "file.container_type": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Executable carrier type established for a structurally attached SFX launcher.",
    },
    "file.probe_detected_archive": {
        "type": "bool",
        "producer": "rules.precheck",
        "description": "Whether probe-like evidence indicates an archive.",
    },
    "file.probe_offset": {
        "type": "int",
        "producer": "rules.precheck",
        "description": "Offset where embedded/probed archive payload starts.",
    },
    "file.embedded_archive_found": {
        "type": "bool",
        "producer": "rules.precheck.embedded_payload_identity",
        "description": "Whether a carrier/ambiguous resource contains an embedded archive payload.",
    },
    "embedded_archive.analysis": {
        "type": "dict",
        "producer": "processors.embedded_archive",
        "description": "Embedded archive scan result including found, detected_ext, offset, mode, and ZIP plausibility.",
    },
    "zip.local_header": {
        "type": "dict",
        "producer": "processors.zip_structure",
        "description": "ZIP local header plausibility at the beginning of the candidate file.",
    },
    "zip.local_header_plausible": {
        "type": "bool",
        "producer": "processors.zip_structure",
        "description": "Whether the embedded ZIP local header at the detected offset looks structurally plausible.",
    },
    "zip.local_header_offset": {
        "type": "int",
        "producer": "processors.zip_structure",
        "description": "Offset of the ZIP local header checked for embedded archive plausibility.",
    },
    "zip.local_header_error": {
        "type": "str",
        "producer": "processors.zip_structure",
        "description": "Reason why the embedded ZIP local header plausibility check failed, if any.",
    },
    "zip.eocd_structure": {
        "type": "dict",
        "producer": "processors.zip_eocd_structure",
        "description": "ZIP EOCD/central-directory structure and bounded encryption state derived from the candidate file.",
    },
    "relation.split_group_status": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Tri-state relation result: complete, incomplete, or ambiguous.",
    },
    "zip.directory_consistency": {
        "type": "dict",
        "producer": "processors.zip_directory_consistency",
        "description": "ZIP central directory, local header, descriptor, and ZIP64 consistency facts.",
    },
    "zip.structure_graph": {
        "type": "dict",
        "producer": "processors.zip_structure_graph",
        "description": "ZIP structure graph with nodes, edges, violations, explanations, and summary facts.",
    },
    "tar.header_structure": {
        "type": "dict",
        "producer": "processors.tar_header_structure",
        "description": "TAR header checksum and ustar marker structure check derived from the candidate file.",
    },
    "compression.stream_structure": {
        "type": "dict",
        "producer": "processors.compression_stream_structure",
        "description": "Lightweight gzip, bzip2, xz, or zstd stream structure check derived from the candidate file.",
    },
    "pe.overlay_structure": {
        "type": "dict",
        "producer": "processors.pe_overlay_structure",
        "description": "PE header, overlay range, and archive-like overlay evidence derived from the candidate file.",
    },
    "executable.carrier": {
        "type": "dict",
        "producer": "processors.executable_carrier",
        "description": "Executable carrier classification separating SFX archives from application runtime bundles.",
    },
    "relation.format_hint": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Canonical format routing hint inferred once by the logical-volume relation layer.",
    },
    "relation.format_hint_confidence": {
        "type": "str",
        "producer": "relations.group_builder",
        "description": "Naming-only confidence for the relation format hint; never an archive identity verdict.",
    },
    "analysis.signature_prepass": {
        "type": "dict",
        "producer": "rules.precheck.embedded_payload_identity",
        "description": "Reusable full-stream candidate and signature map produced by the shared embedded scanner.",
    },
    "7z.structure": {
        "type": "dict",
        "producer": "processors.seven_zip_structure",
        "description": "7z signature, header CRC/range/NID checks, and bounded payload/header encryption state.",
    },
    "rar.structure": {
        "type": "dict",
        "producer": "processors.rar_structure",
        "description": "RAR4/RAR5 signature, main-header CRC, and optional second block/header walk checks.",
    },
}


def known_fact_names() -> set[str]:
    return set(FACT_SCHEMA)


def register_fact_schema(fact_name: str, schema: dict[str, Any]):
    FACT_SCHEMA[fact_name] = dict(schema)


def get_fact_schema(fact_name: str) -> dict[str, Any] | None:
    return FACT_SCHEMA.get(fact_name)


def matches_schema_type(value: Any, type_name: str | list[str] | None) -> bool:
    if type_name is None:
        return True
    type_names = type_name if isinstance(type_name, list) else [type_name]
    return any(_matches_one_type(value, name) for name in type_names)


def _matches_one_type(value: Any, type_name: str) -> bool:
    if type_name == "any":
        return True
    if type_name == "str":
        return isinstance(value, str)
    if type_name == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "float":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "bool":
        return isinstance(value, bool)
    if type_name == "bytes":
        return isinstance(value, bytes)
    if type_name == "dict":
        return isinstance(value, dict)
    if type_name == "list":
        return isinstance(value, list)
    if type_name == "list[str]":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if type_name == "list[dict]":
        return isinstance(value, list) and all(isinstance(item, dict) for item in value)
    if type_name == "dict[str,int]":
        return isinstance(value, dict) and all(isinstance(key, str) and isinstance(val, int) for key, val in value.items())
    if type_name == "dict[str,str]":
        return isinstance(value, dict) and all(isinstance(key, str) and isinstance(val, str) for key, val in value.items())
    return True
