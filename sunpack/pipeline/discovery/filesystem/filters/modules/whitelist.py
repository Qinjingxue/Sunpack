import re
from pathlib import Path
from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, prune, reject


class WhitelistScanFilter:
    name = "whitelist"
    stage = "path"

    def __init__(
        self,
        allowed_extensions=None,
        allowed_files=None,
        path_globs=None,
        prune_dir_globs=None,
    ):
        self.path_globs = [
            str(pattern).strip()
            for pattern in (path_globs or [])
            if isinstance(pattern, str) and pattern.strip()
        ]
        self.prune_dir_globs = [
            str(pattern).strip()
            for pattern in (prune_dir_globs or [])
            if isinstance(pattern, str) and pattern.strip()
        ]
        self.path_patterns = [
            *[_path_glob_to_regex(pattern) for pattern in self.path_globs],
        ]
        self.file_patterns = [
            *[_file_name_to_regex(name) for name in (allowed_files or []) if isinstance(name, str) and name.strip()],
        ]
        self.patterns = [*self.path_patterns, *self.file_patterns]
        self.prune_dirs = [
            *[_dir_glob_to_regex(pattern) for pattern in self.prune_dir_globs],
        ]
        self.allowed_extensions = {
            ext if ext.startswith(".") else f".{ext}"
            for ext in (str(item).strip().lower() for item in (allowed_extensions or []))
            if ext
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(
            allowed_extensions=config.get("allowed_extensions") or [],
            allowed_files=config.get("allowed_files") or [],
            path_globs=config.get("path_globs") or [],
            prune_dir_globs=config.get("prune_dir_globs") or [],
        )

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if not self._has_rules():
            return keep()
        path = candidate.path
        candidates = self._path_candidates(path)
        if candidate.kind == "dir":
            if self._directory_allowed(candidates):
                return keep()
            return prune("Directory not in whitelist")
        if self._file_allowed(path, candidates):
            return keep()
        return reject("File not in whitelist")

    def _has_rules(self) -> bool:
        return bool(self.patterns or self.prune_dirs or self.allowed_extensions)

    def _directory_allowed(self, candidates: list[str]) -> bool:
        return self._field_allows(self.path_patterns, candidates) and self._field_allows(self.prune_dirs, candidates)

    def _file_allowed(self, path: Path, candidates: list[str]) -> bool:
        ext = path.suffix.lower()
        return (
            self._field_allows(self.path_patterns, candidates)
            and self._field_allows(self.file_patterns, candidates)
            and (not self.allowed_extensions or (bool(ext) and ext in self.allowed_extensions))
        )

    def _path_candidates(self, path: Path) -> list[str]:
        candidates = [
            path.name,
            str(path.parent),
            str(path),
        ]
        return [item.replace("\\", "/") for item in candidates if item]

    def _matches_any(self, patterns: list[str], candidates: list[str]) -> bool:
        return any(re.search(pattern, item, re.IGNORECASE) for pattern in patterns for item in candidates)

    def _field_allows(self, patterns: list[str], candidates: list[str]) -> bool:
        return not patterns or self._matches_any(patterns, candidates)


def _normalize_glob(value: str) -> str:
    return str(value).strip().replace("\\", "/").strip("/")


def _glob_body_to_regex(value: str) -> str:
    output = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "*":
            if index + 1 < len(value) and value[index + 1] == "*":
                output.append(".*")
                index += 2
                continue
            output.append("[^/]*")
        elif char == "?":
            output.append("[^/]")
        else:
            output.append(re.escape(char))
        index += 1
    return "".join(output)


def _path_glob_to_regex(value: str) -> str:
    glob = _normalize_glob(value)
    if not glob:
        return r"a\A"
    if glob.endswith("/**"):
        base = glob[:-3].rstrip("/")
        return rf"(^|/){_glob_body_to_regex(base)}($|/.*)"
    return rf"(^|/){_glob_body_to_regex(glob)}($|/)"


def _dir_glob_to_regex(value: str) -> str:
    glob = _normalize_glob(value).rstrip("/")
    if not glob:
        return r"a\A"
    return rf"^{_glob_body_to_regex(glob)}$"


def _file_name_to_regex(value: str) -> str:
    name = _normalize_glob(value).split("/")[-1]
    if not name:
        return r"a\A"
    return rf"(^|/){re.escape(name)}$"
