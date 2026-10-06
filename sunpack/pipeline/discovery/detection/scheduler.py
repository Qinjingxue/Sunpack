"""Single-file TAR and compression-stream confirmation."""

from typing import Any

from sunpack.core.analysis import ArchiveAnalyzer
from sunpack.core.contracts.discovery import DiscoveryCandidate


CONFIRMABLE_FORMATS = frozenset({"tar", "gzip", "bzip2", "xz", "zstd", "lz4"})


class DetectionScheduler:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def confirm(self, candidate: DiscoveryCandidate) -> tuple[bool, str]:
        archive_format = str(candidate.format_hint or "").lower()
        if not candidate.entry_path or archive_format not in CONFIRMABLE_FORMATS:
            return False, ""
        try:
            accepted = ArchiveAnalyzer.confirm_format_identity(candidate.entry_path, archive_format)
        except (OSError, ValueError):
            return False, ""
        if not accepted:
            return False, ""
        return True, f"Confirmed {archive_format} structure"
