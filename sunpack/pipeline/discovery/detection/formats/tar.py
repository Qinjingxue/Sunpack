from sunpack.core.analysis import TarProbeOptions
from sunpack.core.analysis.probes.tar import DEFAULT_DETECTION_ENTRIES_TO_WALK


FORMAT = "tar"


def confirm(path: str, analyzer) -> bool:
    observation = analyzer.probe_tar(
        path,
        TarProbeOptions(max_entries_to_walk=DEFAULT_DETECTION_ENTRIES_TO_WALK),
    ).to_raw_dict()
    return bool(
        observation.get("plausible")
        and observation.get("validation_scope") == "format_identity"
        and observation.get("identity_strong")
        and observation.get("fuzzy_name_nonempty")
        and observation.get("fuzzy_numeric_fields_valid")
        and observation.get("fuzzy_typeflag_valid")
        and observation.get("fuzzy_payload_in_range")
        and observation.get("stored_checksum") == observation.get("computed_checksum")
        and not observation.get("error")
    )
