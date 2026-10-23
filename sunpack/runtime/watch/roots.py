"""Input-root policy shared by Watch configuration and task admission."""

from dataclasses import dataclass
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.support.path_keys import path_key


@dataclass(frozen=True)
class WatchRootEntry:
    input_root: str
    output_root: str | None = None
    deep_detect: bool = False
    initial_scanned: bool = False
    recursive: bool = False


def discovery_scopes(entries):
    """Each explicit root owns its subtree, including when it is shallow."""
    roots = {path_key(entry.input_root): entry for entry in entries}
    return {key: DiscoveryScope(entry.input_root, recursive=entry.recursive,
                excluded_subtrees=[other.input_root for other_key, other in roots.items()
                                   if other_key.startswith(key.rstrip("\\") + "\\")])
            for key, entry in roots.items()}
