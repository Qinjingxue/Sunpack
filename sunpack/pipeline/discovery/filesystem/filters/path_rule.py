from sunpack_native import NativePathRule

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, prune, reject


def validate_path_rule_config(config: dict) -> None:
    unexpected = config.keys() - {"name", "enabled", "paths", "files", "extensions", "full_names"}
    if unexpected:
        raise ValueError(f"Unsupported {config.get('name')} fields: {', '.join(sorted(unexpected))}")
    for field in ("paths", "files", "extensions", "full_names"):
        values = config.get(field, [])
        if not isinstance(values, list):
            raise ValueError(f"{field} must be a list of rule objects")
        for index, item in enumerate(values):
            if (not isinstance(item, dict) or item.keys() != {"value", "regex"}
                    or not isinstance(item["value"], str) or not item["value"]
                    or not isinstance(item["regex"], bool)):
                raise ValueError(f"{field}[{index}] requires a nonempty value string and a regex boolean")


class PathRuleScanFilter:
    stage = "path"

    def __init__(self, paths=None, files=None, extensions=None, full_names=None):
        self.native_rule = NativePathRule(paths or [], files or [], extensions or [], full_names or [])

    @classmethod
    def from_config(cls, config: dict):
        validate_path_rule_config(config)
        return cls(paths=config.get("paths"), files=config.get("files"),
                   extensions=config.get("extensions"), full_names=config.get("full_names"))

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
