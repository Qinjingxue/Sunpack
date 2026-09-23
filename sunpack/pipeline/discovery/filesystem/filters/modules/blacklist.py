from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, reject


class BlacklistScanFilter:
    name = "blacklist"
    stage = "path"

    def __init__(
        self,
        blocked_extensions=None,
        blocked_files=None,
    ):
        self.blocked_files = {
            _normalize_file_name(name)
            for name in (blocked_files or [])
            if isinstance(name, str) and name.strip()
        }
        self.blocked_extensions = {
            ext if ext.startswith(".") else f".{ext}"
            for ext in (str(item).strip().lower() for item in (blocked_extensions or []))
            if ext
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(
            blocked_extensions=config.get("blocked_extensions") or [],
            blocked_files=config.get("blocked_files") or [],
        )

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        path = candidate.path
        ext = path.suffix.lower()
        if candidate.kind == "file" and ext and ext in self.blocked_extensions:
            return reject(f"Blocked extension: {ext}")
        if candidate.kind == "file" and _normalize_file_name(path.name) in self.blocked_files:
            return reject(f"Blocked file: {path.name}")
        return keep()


def _normalize_file_name(value: str) -> str:
    return str(value).strip().replace("\\", "/").split("/")[-1].lower()
