"""Single-file TAR and compression-stream confirmation."""

from typing import Any

from sunpack.core.analysis import ArchiveAnalyzer
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.detection.formats import CONFIRMERS


class DetectionScheduler:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.analyzer = ArchiveAnalyzer(config)

    def validate_config(self) -> list[str]:
        return []

    def confirm(self, candidate: DiscoveryCandidate) -> tuple[bool, str]:
        archive_format = str(candidate.format_hint or "").lower()
        confirmer = CONFIRMERS.get(archive_format)
        if not candidate.entry_path or confirmer is None:
            return False, ""
        try:
            accepted = bool(confirmer.confirm(candidate.entry_path, self.analyzer))
        except (OSError, ValueError):
            return False, ""
        if not accepted:
            return False, ""
        return True, f"Confirmed {archive_format} structure"
