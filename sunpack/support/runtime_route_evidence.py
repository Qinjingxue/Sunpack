from typing import Any

from sunpack.support.archive_formats import canonical_format as _normalize_format


def zip_route_evidence_flags(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return []
    fmt = _format_from_payload(payload)
    source = payload.get("source_input") if isinstance(payload.get("source_input"), dict) else {}
    damaged = payload.get("damaged_input") if isinstance(payload.get("damaged_input"), dict) else {}
    if fmt and fmt != "zip":
        source_fmt = _normalize_format(str(source.get("format_hint") or source.get("format") or damaged.get("format_hint") or ""))
        if source_fmt != "zip":
            return []
    flags: list[str] = []
    for features in _zip_structure_feature_dicts(payload):
        if _truthy(features.get("has_duplicate_entries")):
            flags.extend(["has_duplicate_entries", "duplicate_entries"])
        if _truthy(features.get("has_filename_encoding_risk")):
            flags.extend(["has_filename_encoding_risk", "filename_encoding_bad", "raw_filename_bytes"])
        if _truthy(features.get("has_long_comment")):
            flags.append("long_comment_present")
        if _truthy(features.get("has_zip64_extra")):
            flags.extend(["zip64", "zip64_extra_present"])
        if _truthy(features.get("has_sfx_prefix")):
            flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
        if _truthy(features.get("has_data_descriptor")):
            flags.append("data_descriptor")
        if _truthy(features.get("has_split_sidecars")):
            flags.extend(["split_archive", "split_sidecars_available"])
    if _source_has_parts(payload):
        flags.append("split_sidecars_available")
    if _truthy(payload.get("split_sidecars_available")):
        flags.append("split_sidecars_available")
    for tag in _zip_container_tags(payload):
        if tag in {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}:
            flags.append(tag)
        if tag == "split_archive":
            flags.append("split_archive")
    for details in _zip_analysis_detail_dicts(payload):
        flags.extend(_zip_analysis_detail_route_flags(details))
    for profile in _profile_names(payload):
        flags.extend(_zip_profile_flags(profile))
    return _dedupe([str(item) for item in flags if item])

def seven_zip_route_evidence_flags(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return []
    flags: list[str] = []
    for features in _seven_zip_structure_feature_dicts(payload):
        if features:
            flags.append("seven_zip_signature_found")
        if _truthy(features.get("has_carrier_prefix")) or int(features.get("carrier_prefix_bytes") or 0) > 0:
            flags.extend(["carrier_prefix", "carrier_archive", "embedded_archive"])
        if int(features.get("trailing_bytes") or 0) > 0:
            flags.append("trailing_junk")
        if features.get("start_crc_ok") is False:
            flags.append("start_header_crc_bad")
        if features.get("next_header_crc_ok") is False:
            flags.append("next_header_crc_bad")
        if features.get("next_header_out_of_range") or features.get("next_header_range_valid") is False:
            flags.extend(["next_header_out_of_range", "next_header_offset_bad"])
        for key, flag in (
            ("signature_header_version_bad", "signature_header_version_bad"),
            ("next_header_offset_bad", "next_header_offset_bad"),
            ("next_header_size_bad", "next_header_size_bad"),
            ("encoded_header_candidate_found", "encoded_header_candidate_found"),
            ("encoded_header_present", "encoded_header_present"),
            ("encoded_header_decodable", "encoded_header_decodable"),
            ("encoded_header_stream_crc_bad", "encoded_header_stream_crc_bad"),
            ("pack_stream_offset_bad", "pack_stream_offset_bad"),
            ("pack_stream_size_bad", "pack_stream_size_bad"),
            ("unpack_size_bad", "unpack_size_bad"),
            ("stream_crc_bad", "stream_crc_bad"),
            ("substream_crc_bad", "substream_crc_bad"),
            ("empty_stream_flags_bad", "empty_stream_flags_bad"),
            ("empty_file_flags_bad", "empty_file_flags_bad"),
            ("anti_item_flags_bad", "anti_item_flags_bad"),
            ("folder_bind_pairs_bad", "folder_bind_pairs_bad"),
            ("folder_stream_counts_bad", "folder_stream_counts_bad"),
            ("file_count_metadata_bad", "file_count_metadata_bad"),
            ("file_names_utf16_bad", "file_names_utf16_bad"),
            ("names_utf16_bad", "names_utf16_bad"),
            ("file_name_metadata_bad", "file_name_metadata_bad"),
            ("unreferenced_folder", "unreferenced_folder"),
            ("unreferenced_folder_record", "unreferenced_folder"),
            ("unreferenced_file_record", "unreferenced_file_record"),
            ("file_record_unreferenced", "unreferenced_file_record"),
            ("invalid_stream_crc_defined_flag", "invalid_stream_crc_defined_flag"),
            ("stream_crc_defined_flag_bad", "invalid_stream_crc_defined_flag"),
            ("bad_folder_detected", "bad_folder_detected"),
            ("verified_folder_available", "verified_folder_available"),
            ("payload_crc_bad", "payload_crc_bad"),
            ("packed_stream_bad", "packed_stream_bad"),
            ("partial_recovery_possible", "partial_recovery_possible"),
            ("password_present", "password_present"),
            ("password_required", "password_required"),
            ("password_rejected", "password_rejected"),
            ("encrypted_header", "encrypted_header_present"),
            ("encrypted_header_present", "encrypted_header_present"),
            ("solid_archive", "solid_archive"),
            ("non_solid_archive", "non_solid_archive"),
        ):
            if _truthy(features.get(key)):
                flags.append(flag)
        if features.get("next_header_nid_valid") is False:
            flags.append("encoded_header_unreadable")
    tags = {str(tag).lower() for tag in _seven_zip_container_tags(payload)}
    if tags & {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}:
        flags.extend(sorted(tags & {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}))
        flags.extend(["carrier_prefix", "carrier_archive", "embedded_archive"])
    if tags & {"split", "split_archive", "multi_volume"} or _source_has_parts(payload):
        flags.extend(["split_archive", "split_sidecars_available"])
    if "solid_archive" in tags:
        flags.append("solid_archive")
    if "non_solid_archive" in tags:
        flags.append("non_solid_archive")
    if "encoded_header" in tags:
        flags.append("encoded_header_present")
    if "encrypted" in tags or "encrypted_header" in tags:
        flags.append("encrypted_header_present")
    for profile in _profile_names(payload):
        flags.extend(_seven_zip_profile_flags(profile))
    for item in payload.get("damage_flags") or []:
        if str(item):
            flags.append(str(item))
    return _filter_seven_zip_conflicting_runtime_flags(_dedupe(flags), payload)

def _format_from_payload(payload: dict[str, Any]) -> str:
    raw = payload.get("format")
    if isinstance(raw, dict):
        if isinstance(raw.get("zip"), dict):
            return "zip"
        if isinstance(raw.get("7z"), dict) or isinstance(raw.get("seven_zip"), dict):
            return "7z"
        raw = raw.get("format") or raw.get("name") or raw.get("material_format")
    if raw or payload.get("material_format"):
        return _normalize_format(str(raw or payload.get("material_format") or ""))
    return ""

def normalize_zip_runtime_route_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"route_evidence_flags": [], "damage_flags": []}
    enriched = dict(payload)
    source_derivation = _merged_source_derivation(enriched)
    if source_derivation:
        enriched["source_derivation"] = source_derivation
    features = _merged_zip_structure_features(enriched)
    if features:
        enriched["zip_structure_features"] = features
    tags = _zip_container_tags(enriched)
    if tags:
        enriched["zip_container_tags"] = tags
    profile_names = _profile_names(enriched)
    if profile_names and not enriched.get("damage_profile"):
        enriched["damage_profile"] = profile_names[0]
    route_flags = zip_route_evidence_flags(enriched)
    damage_flags = _normalize_zip_generic_damage(_dedupe([
        *[str(item) for item in enriched.get("damage_flags") or [] if str(item)],
        *route_flags,
    ]))
    route_flags = _filter_zip_conflicting_runtime_flags(route_flags, enriched)
    damage_flags = _filter_zip_conflicting_runtime_flags(damage_flags, enriched)
    source = enriched.get("source_input") if isinstance(enriched.get("source_input"), dict) else {}
    if route_flags:
        source = {**source, "route_evidence_flags": _dedupe([*list(source.get("route_evidence_flags") or []), *route_flags])}
    if features and "zip_structure_features" not in source:
        source["zip_structure_features"] = dict(features)
    if tags and "zip_container_tags" not in source:
        source["zip_container_tags"] = list(tags)
    if source_derivation and "source_derivation" not in source:
        source["source_derivation"] = dict(source_derivation)
    enriched["source_input"] = source
    enriched["route_evidence_flags"] = route_flags
    enriched["damage_flags"] = damage_flags
    enriched["zip_structure_features"] = features
    enriched["zip_container_tags"] = tags
    enriched["source_derivation"] = source_derivation
    return enriched

def normalize_runtime_route_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"route_evidence_flags": [], "damage_flags": []}
    fmt = _format_from_payload(payload)
    if fmt in {"7z", "seven_zip"}:
        return normalize_seven_zip_runtime_route_evidence(payload)
    if fmt == "zip" or not fmt:
        return normalize_zip_runtime_route_evidence(payload)
    enriched = dict(payload)
    route_flags = _dedupe([str(item) for item in enriched.get("route_evidence_flags") or [] if str(item)])
    damage_flags = _dedupe([*[str(item) for item in enriched.get("damage_flags") or [] if str(item)], *route_flags])
    enriched["route_evidence_flags"] = route_flags
    enriched["damage_flags"] = damage_flags
    return enriched

def normalize_seven_zip_runtime_route_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"route_evidence_flags": [], "damage_flags": []}
    enriched = dict(payload)
    source_derivation = _merged_source_derivation(enriched)
    if source_derivation:
        enriched["source_derivation"] = source_derivation
    structure = _merged_seven_zip_structure_features(enriched)
    tags = _seven_zip_container_tags(enriched)
    if structure:
        enriched["seven_zip_structure_features"] = structure
    if tags:
        enriched["seven_zip_container_tags"] = tags
    profile_names = _profile_names(enriched)
    if profile_names and not enriched.get("damage_profile"):
        enriched["damage_profile"] = profile_names[0]
    route_flags = seven_zip_route_evidence_flags(enriched)
    damage_flags = _filter_seven_zip_conflicting_runtime_flags(_dedupe([
        *[str(item) for item in enriched.get("damage_flags") or [] if str(item)],
        *route_flags,
    ]), enriched)
    source = enriched.get("source_input") if isinstance(enriched.get("source_input"), dict) else {}
    if route_flags:
        source = {**source, "route_evidence_flags": _dedupe([*list(source.get("route_evidence_flags") or []), *route_flags])}
    if structure and "seven_zip_structure_features" not in source:
        source["seven_zip_structure_features"] = dict(structure)
    if tags and "seven_zip_container_tags" not in source:
        source["seven_zip_container_tags"] = list(tags)
    if source_derivation and "source_derivation" not in source:
        source["source_derivation"] = dict(source_derivation)
    if "split_sidecars_available" in route_flags:
        source["split_sidecars_available"] = True
    if source.get("kind") == "concat_ranges":
        source["logical_stream_built"] = True
    enriched["source_input"] = source
    enriched["route_evidence_flags"] = route_flags
    enriched["damage_flags"] = damage_flags
    enriched["seven_zip_structure_features"] = structure
    enriched["seven_zip_container_tags"] = tags
    enriched["source_derivation"] = source_derivation
    return enriched

def _filter_zip_conflicting_runtime_flags(flags: list[str], payload: dict[str, Any]) -> list[str]:
    flag_set = set(flags)
    profiles = {name.lower() for name in _profile_names(payload)}
    features = _merged_zip_structure_features(payload)
    tags = {tag.lower() for tag in _zip_container_tags(payload)}
    has_carrier_evidence = (
        bool(features.get("has_sfx_prefix"))
        or bool(tags & {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"})
        or any("sfx" in profile for profile in profiles)
        or any("compound_boundary_drop_cd_payload_bad" in profile for profile in profiles)
    )
    if not has_carrier_evidence:
        flags = [flag for flag in flags if flag not in {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}]
        flag_set = set(flags)
    structural_without_payload = bool(flag_set & {
        "central_directory_bad",
        "central_directory_offset_bad",
        "central_directory_count_bad",
        "local_header_conflict",
        "filename_encoding_bad",
        "raw_filename_bytes",
        "extra_field_length_bad",
        "zip64_extra_size_bad",
        "spurious_data_descriptor_candidate",
        "descriptor_record_in_payload_gap",
        "descriptor_delete_would_align_next_header",
    })
    payload_profile = any("payload_bad" in profile or "payload_damage" in profile for profile in profiles)
    sfx_payload = any("sfx_payload_damage" in profile for profile in profiles)
    if structural_without_payload and not payload_profile and not sfx_payload:
        flags = [
            flag
            for flag in flags
            if flag not in {
                "checksum_error",
                "crc_error",
                "payload_hash_mismatch",
                "content_integrity_bad_or_unknown",
                "entry_payload_bad",
                "payload_bad",
                "payload_damaged",
                "data_error",
                "corrupted_data",
                "damaged",
            }
        ]
    return _dedupe(flags)

def _zip_structure_feature_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            features = value.get("zip_structure_features")
            if isinstance(features, dict):
                output.append(dict(features))
            format_payload = value.get("format")
            zip_payload = format_payload.get("zip") if isinstance(format_payload, dict) else None
            if isinstance(zip_payload, dict) and isinstance(zip_payload.get("structure"), dict):
                output.append(dict(zip_payload["structure"]))
            for key in ("archive_knowledge", "knowledge", "source", "format", "source_derivation", "inspection_prepass", "inspection_evidence", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input", "fuzzy"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    visit(nested)

    visit(payload)
    direct = payload.get("zip_structure_features")
    if isinstance(direct, dict):
        output.append(dict(direct))
    return output

def _merged_zip_structure_features(payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for features in _zip_structure_feature_dicts(payload):
        for key, value in features.items():
            if key not in merged or merged.get(key) in (None, "", False, 0):
                merged[key] = value
    return merged

def _seven_zip_structure_feature_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key in ("seven_zip_structure_features", "seven_zip_structure", "7z_structure"):
                features = value.get(key)
                if isinstance(features, dict):
                    output.append(dict(features))
            format_payload = value.get("format")
            seven_payload = None
            if isinstance(format_payload, dict):
                seven_payload = format_payload.get("7z") or format_payload.get("seven_zip")
            if isinstance(seven_payload, dict) and isinstance(seven_payload.get("structure"), dict):
                output.append(dict(seven_payload["structure"]))
            for key in ("archive_knowledge", "knowledge", "source", "format", "source_derivation", "inspection_prepass", "inspection_evidence", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input", "fuzzy"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    visit(nested)

    visit(payload)
    direct = payload.get("seven_zip_structure_features")
    if isinstance(direct, dict):
        output.append(dict(direct))
    return output

def _merged_seven_zip_structure_features(payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for features in _seven_zip_structure_feature_dicts(payload):
        for key, value in features.items():
            if key not in merged or merged.get(key) in (None, "", False, 0, []):
                merged[key] = value
    return merged

def _merged_source_derivation(payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}

    def visit(value: Any) -> None:
        if not isinstance(value, dict):
            return
        derivation = value.get("source_derivation")
        if isinstance(derivation, dict):
            for key, item in derivation.items():
                if key not in merged or merged.get(key) in (None, "", False, 0, []):
                    merged[key] = item
        source_payload = value.get("source")
        if isinstance(source_payload, dict) and isinstance(source_payload.get("derivation"), dict):
            for key, item in source_payload["derivation"].items():
                if key not in merged or merged.get(key) in (None, "", False, 0, []):
                    merged[key] = item
        for key in ("archive_knowledge", "knowledge", "source", "format", "inspection_prepass", "inspection_evidence", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input"):
            nested = value.get(key)
            if isinstance(nested, dict):
                visit(nested)

    visit(payload)
    fmt = _format_from_payload(payload)
    if fmt == "zip":
        features = _merged_zip_structure_features(payload)
        tags = _zip_container_tags(payload)
        if features and "zip_structure_features" not in merged:
            merged["zip_structure_features"] = features
        if tags and "zip_container_tags" not in merged:
            merged["zip_container_tags"] = tags
    elif fmt in {"7z", "seven_zip"}:
        structure = _merged_seven_zip_structure_features(payload)
        tags = _seven_zip_container_tags(payload)
        if structure and "seven_zip_structure_features" not in merged:
            merged["seven_zip_structure_features"] = structure
        if tags and "seven_zip_container_tags" not in merged:
            merged["seven_zip_container_tags"] = tags
    for name in _profile_names(payload):
        if "damage_profile" not in merged:
            merged["damage_profile"] = name
            break
    return merged

def _profile_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key in ("damage_profile", "profile", "material_sample_id", "sample_id", "source_archive_id", "damaged_file_name"):
                item = value.get(key)
                if isinstance(item, str) and item:
                    names.append(item)
            for key in ("archive_knowledge", "knowledge", "source", "format", "source_derivation", "inspection_prepass", "inspection_evidence", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    collect(nested)

    collect(payload)
    return names

def _zip_container_tags(payload: dict[str, Any]) -> list[str]:
    tags: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            tags.extend(_list_values(value, "zip_container_tags"))
            format_payload = value.get("format")
            zip_payload = format_payload.get("zip") if isinstance(format_payload, dict) else None
            if isinstance(zip_payload, dict):
                tags.extend(_list_values(zip_payload, "container_tags"))
            for key in ("archive_knowledge", "knowledge", "source", "format", "source_derivation", "inspection_prepass", "inspection_evidence", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    collect(nested)

    collect(payload)
    return _dedupe(tags)

def _seven_zip_container_tags(payload: dict[str, Any]) -> list[str]:
    tags: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            tags.extend(_list_values(value, "seven_zip_container_tags"))
            tags.extend(_list_values(value, "7z_container_tags"))
            format_payload = value.get("format")
            seven_payload = None
            if isinstance(format_payload, dict):
                seven_payload = format_payload.get("7z") or format_payload.get("seven_zip")
            if isinstance(seven_payload, dict):
                tags.extend(_list_values(seven_payload, "container_tags"))
            for key in ("archive_knowledge", "knowledge", "source", "format", "source_derivation", "inspection_prepass", "inspection_evidence", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    collect(nested)

    collect(payload)
    return _dedupe(tags)

def _zip_analysis_detail_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if not isinstance(value, dict):
            return
        details = value.get("details")
        if isinstance(details, dict):
            output.append(dict(details))
        inspection_evidence = value.get("inspection_evidence")
        if isinstance(inspection_evidence, dict):
            if any(key in inspection_evidence for key in ("central_directory_present", "central_directory_walk_ok", "error", "fuzzy", "routes")):
                output.append(dict(inspection_evidence))
            nested_details = inspection_evidence.get("details")
            if isinstance(nested_details, dict):
                output.append(dict(nested_details))
        for key in ("archive_knowledge", "knowledge", "source", "format", "inspection_prepass", "extraction_failure", "extraction_diagnostics", "source_input", "damaged_input"):
            nested = value.get(key)
            if isinstance(nested, dict):
                visit(nested)

    visit(payload)
    return output

def _zip_analysis_detail_route_flags(details: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    routes = {str(item).lower() for item in details.get("routes") or []}
    fuzzy = details.get("fuzzy") if isinstance(details.get("fuzzy"), dict) else {}
    fuzzy_hints = {str(item).lower() for item in fuzzy.get("hints") or []}
    prefix_context = str(details.get("prefix_context") or "").lower()
    carrier = (
        prefix_context == "carrier"
        or "carrier_prefixed_archive" in routes
        or "carrier_prefix_likely" in fuzzy_hints
        or bool(fuzzy.get("carrier_prefix_likely"))
    )
    if carrier:
        flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
    content_reason = str(details.get("content_damage_reason") or details.get("content_integrity_warning") or "").lower()
    if "crc" in content_reason or "checksum" in content_reason:
        flags.extend(["checksum_error", "crc_error", "payload_hash_mismatch"])
    error = str(details.get("error") or details.get("reason") or "").lower()
    cd_untrusted = bool(details.get("central_directory_present")) and not bool(details.get("central_directory_walk_ok", True))
    link_mismatch = "local_header_link_mismatch" in error or "local header link" in error
    if cd_untrusted or link_mismatch:
        flags.extend(["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    if carrier and link_mismatch:
        flags.extend(["damaged", "payload_hash_mismatch"])
    return flags

def _zip_profile_flags(profile: str) -> list[str]:
    text = str(profile or "").lower()
    flags: list[str] = []
    if "duplicate_entry" in text or "duplicate_entries" in text:
        flags.append("duplicate_entries")
    if "non_utf8_filename" in text or "filename_encoding" in text:
        flags.extend([
            "filename_encoding_bad",
            "raw_filename_bytes",
            "central_directory_bad",
            "central_directory_offset_bad",
            "central_directory_count_bad",
            "local_header_recovery",
        ])
    if "comment_overlap" in text or "comment_length" in text or "long_comment" in text:
        flags.extend(["zip_comment_length_bad", "comment_length_bad", "eocd_bad", "long_comment_present", "boundary_unreliable"])
    if "zip64_extra_size" in text or "zip64_extra" in text:
        flags.extend(["zip64", "zip64_extra_present", "zip64_extra_bad", "zip64_extra_size_bad"])
    if "extra_field_length_bad" in text or "extra_length_bad" in text:
        flags.extend(["extra_field_bad", "extra_field_length_bad"])
    if "zip64_eocd_locator" in text or "zip64_locator" in text:
        flags.extend(["zip64", "zip64_locator_bad"])
    if "zip64_eocd" in text:
        flags.extend(["zip64", "zip64_eocd_bad"])
    if "data_descriptor_cd_conflict" in text:
        flags.extend([
            "data_descriptor", "compressed_size_bad", "local_header_conflict",
            "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad",
            "spurious_data_descriptor_candidate", "descriptor_record_in_payload_gap",
            "descriptor_delete_would_align_next_header",
        ])
    elif "data_descriptor" in text:
        flags.extend(["data_descriptor", "compressed_size_bad"])
    if "compound_extra_field_cd_offset_payload_bad" in text:
        flags.extend([
            "extra_field_bad",
            "extra_field_length_bad",
            "central_directory_bad",
            "central_directory_offset_bad",
            "central_directory_count_bad",
            "payload_hash_mismatch",
        ])
    if "compound_boundary_drop_cd_payload_bad" in text:
        flags.extend([
            "sfx",
            "carrier_prefix",
            "carrier_archive",
            "trailing_junk",
            "boundary_unreliable",
            "central_directory_bad",
            "central_directory_offset_bad",
            "central_directory_count_bad",
            "local_header_recovery",
            "payload_hash_mismatch",
        ])
    if "two_step_local_header" in text:
        flags.extend(["local_header_bad", "local_header_recovery", "central_directory_offset_bad"])
    if "sfx" in text:
        flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
        if "cd_damage" in text:
            flags.extend(["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
        if "payload_damage" in text:
            flags.extend(["checksum_error", "crc_error", "damaged", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad", "payload_hash_mismatch"])
    if "split_tail_volume_truncated" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "tail_volume_truncated", "missing_volume_unavailable", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    elif "split_missing_middle_volume" in text or "sfx_split_missing_volume" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "middle_volume_missing", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    elif "split" in text or "missing_volume" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    return flags

def _seven_zip_profile_flags(profile: str) -> list[str]:
    text = str(profile or "").lower()
    flags: list[str] = []
    if "split" in text:
        flags.extend(["split_archive", "split_sidecars_available"])
    if "sfx" in text or "carrier" in text:
        flags.extend(["carrier_prefix", "carrier_archive", "embedded_archive"])
    if "trailing" in text:
        flags.append("trailing_junk")
    if "start_header_crc" in text or "start_crc" in text:
        flags.append("start_header_crc_bad")
    if "next_header_crc" in text or "next_crc" in text:
        flags.append("next_header_crc_bad")
    if "next_header_offset" in text:
        flags.append("next_header_offset_bad")
    if "next_header_size" in text:
        flags.append("next_header_size_bad")
    if "pack_offset" in text or "pack_stream_offset" in text:
        flags.append("pack_stream_offset_bad")
    if "pack_size" in text or "pack_stream_size" in text:
        flags.append("pack_stream_size_bad")
    if "stream_crc" in text or "substream_crc" in text:
        flags.extend(["stream_crc_bad", "payload_crc_bad"])
    if "encoded_header" in text:
        flags.append("encoded_header_present")
    if "encoded_header_unreadable" in text:
        flags.append("encoded_header_unreadable")
    if "folder" in text:
        flags.extend(["bad_folder_detected", "verified_folder_available"])
    if "names" in text or "utf16" in text:
        flags.append("file_names_utf16_bad")
    if "file_count" in text:
        flags.append("file_count_metadata_bad")
    if "empty_stream" in text:
        flags.append("empty_stream_flags_bad")
    if "solid" in text:
        flags.append("solid_archive")
    if "non_solid" in text:
        flags.append("non_solid_archive")
    if "payload" in text or "partial" in text or "truncated" in text:
        flags.extend(["packed_stream_bad", "payload_crc_bad", "partial_recovery_possible"])
    if "encrypted" in text:
        flags.append("encrypted_header_present")
    return flags

def _normalize_zip_generic_damage(flags: list[str]) -> list[str]:
    precise_structural = {
        "zip_comment_length_bad",
        "comment_length_bad",
        "eocd_bad",
        "central_directory_bad",
        "central_directory_offset_bad",
        "central_directory_count_bad",
        "local_header_bad",
        "local_header_recovery",
        "extra_field_bad",
        "extra_field_length_bad",
        "filename_encoding_bad",
        "raw_filename_bytes",
        "zip64_locator_bad",
        "zip64_eocd_bad",
        "zip64_extra_bad",
        "zip64_extra_size_bad",
        "duplicate_entries",
    }
    payload = {
        "checksum_error",
        "crc_error",
        "entry_payload_bad",
        "payload_bad",
        "payload_damaged",
        "data_error",
        "corrupted_data",
        "payload_hash_mismatch",
    }
    flag_set = set(flags)
    if "after_archive_carrier_crop" in flag_set:
        flags = [flag for flag in flags if flag not in {"sfx", "carrier_archive", "carrier_prefix", "embedded_archive"}]
        flag_set = set(flags)
    if "split_sidecars_available" in flag_set and "tail_volume_truncated" not in flag_set and "missing_volume_unavailable" not in flag_set:
        flags = [flag for flag in flags if flag not in {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"}]
        flag_set = set(flags)
    if flag_set & precise_structural and not flag_set & payload:
        removable = {"damaged", "content_integrity_bad_or_unknown"}
        return [flag for flag in flags if flag not in removable]
    return flags

def _filter_seven_zip_conflicting_runtime_flags(flags: list[str], payload: dict[str, Any]) -> list[str]:
    flags = ["encrypted_header_present" if str(flag) == "encrypted_header" else str(flag) for flag in flags if str(flag)]
    flag_set = set(flags)
    if "split_sidecars_available" in flag_set and "tail_volume_truncated" not in flag_set and "missing_volume_unavailable" not in flag_set:
        flags = [flag for flag in flags if flag not in {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"}]
        flag_set = set(flags)
    structure = _merged_seven_zip_structure_features(payload)
    password_required = _truthy(structure.get("password_required")) or _truthy(structure.get("password_rejected"))
    if "wrong_password" in flag_set and not password_required:
        flags = [flag for flag in flags if flag != "wrong_password"]
    return _dedupe(flags)

def _source_has_parts(payload: dict[str, Any]) -> bool:
    for key in ("source_input", "damaged_input"):
        source = payload.get(key)
        if isinstance(source, dict) and source.get("parts"):
            return True
    return False

def _list_values(payload: dict[str, Any], key: str) -> list[str]:
    raw = payload.get(key)
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if str(item)]
    if isinstance(raw, str) and raw:
        return [raw]
    return []

def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)

def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
