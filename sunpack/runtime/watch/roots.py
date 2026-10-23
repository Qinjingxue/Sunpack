"""Input-root policy shared by Watch configuration and task admission."""

from dataclasses import dataclass
import os
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.support.path_keys import path_key, path_key_is_under


def watch_path_available(path, scopes):
    """A missing path is conclusive only while its configured roots are accessible."""
    key = path_key(path)
    return all(os.path.isdir(scope.root) for scope in scopes
               if path_key_is_under(key, path_key(scope.root))
               or path_key_is_under(path_key(scope.root), key))


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
