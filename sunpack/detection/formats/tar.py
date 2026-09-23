from sunpack.analysis import TarProbeOptions
from sunpack.analysis.probes.tar import DEFAULT_DETECTION_ENTRIES_TO_WALK


FORMAT = "tar"


def confirm(path: str, analyzer) -> bool:
    observation = analyzer.probe_tar(
        path, TarProbeOptions(max_entries_to_walk=DEFAULT_DETECTION_ENTRIES_TO_WALK),
    ).to_raw_dict()
    return bool(observation.get("plausible") and observation.get("entry_walk_ok"))
