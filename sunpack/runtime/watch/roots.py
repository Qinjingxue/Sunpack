"""Input-root policy shared by Watch configuration and task admission."""

from dataclasses import dataclass
import os
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.support.path_keys import path_key, path_key_is_under


def watch_path_available(path, scopes, *, availability=None):
    """A missing path is conclusive only while its configured roots are accessible."""
    key = path_key(path)
    for scope in scopes:
        root_key = path_key(scope.root)
        if not (path_key_is_under(key, root_key) or path_key_is_under(root_key, key)):
            continue
        if availability is None:
            available = os.path.isdir(scope.root)
        else:
            if root_key not in availability:
                availability[root_key] = os.path.isdir(scope.root)
            available = availability[root_key]
        if not available:
            return False
    return True


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
