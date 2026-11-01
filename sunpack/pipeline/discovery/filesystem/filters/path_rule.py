from sunpack_native import NativePathRule

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, prune, reject


def validate_path_rule_config(config: dict) -> None:
    prefix = "allowed" if config.get("name") == "whitelist" else "blocked"
    fields = ("path_globs", f"{prefix}_files", f"{prefix}_extensions")
    unexpected = config.keys() - {"name", "enabled", *fields}
    if unexpected:
        raise ValueError(f"Unsupported {config.get('name')} fields: {', '.join(sorted(unexpected))}")
    for field in fields:
        values = config.get(field, [])
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError(f"{field} must be a list of strings")


class PathRuleScanFilter:
    stage = "path"

    def __init__(self, path_globs, file_globs, extensions):
        self.native_rule = NativePathRule(path_globs or [], file_globs or [], extensions or [])

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if not self.native_rule.rejects(
            str(candidate.path),
            str(candidate.root_path if candidate.root_path is not None else candidate.path.parent),
            candidate.kind == "dir",
            self.whitelist,
        ):
            return keep()
        reason = "Path excluded by whitelist" if self.whitelist else "Path excluded by blacklist"
        return prune(reason) if candidate.kind == "dir" else reject(reason)
