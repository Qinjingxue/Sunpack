"""Request-owned path mapping with component-indexed subtree removal."""

import os
from collections.abc import MutableMapping

from sunpack.core.support.path_keys import absolute_path_key


class PathMap(MutableMapping):
    """Exact lookups and subtree moves without visiting unrelated paths.

    The trie shares directory components; it retains no copies of full ancestor
    paths. Empty nodes are removed on deletion, and values keep insertion order.
    Callers provide their existing lock when sharing a map across threads.
    """

    def __init__(self):
        self._values = {}
        self._root = {}
        self._sequence = 0

    def __getitem__(self, path):
        return self._values[absolute_path_key(path)][1]

    def __setitem__(self, path, value):
        key = absolute_path_key(path)
        previous = self._values.get(key)
        if previous is not None:
            self._values[key] = (previous[0], value)
            return
        self._sequence += 1
        self._values[key] = (self._sequence, value)
        node = self._root
        for component in key.split(os.sep):
            node = node.setdefault(component, {})
        node[None] = key

    def __delitem__(self, path):
        key = absolute_path_key(path)
        del self._values[key]
        node = self._root
        parents = []
        for component in key.split(os.sep):
            parents.append((node, component))
            node = node[component]
        del node[None]
        for parent, component in reversed(parents):
            if parent[component]:
                break
            del parent[component]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def clear(self):
        self._values.clear()
        self._root.clear()
        self._sequence = 0

    def ancestors(self, path):
        """Yield stored ancestors, including the path, in root-first order."""
        node = self._root
        for component in absolute_path_key(path).split(os.sep):
            node = node.get(component)
            if node is None:
                return
            key = node.get(None)
            if key is not None:
                yield key, self._values[key][1]

    def has_under(self, root):
        """Check a subtree in O(path depth), without visiting its descendants."""
        node = self._root
        for component in absolute_path_key(root).split(os.sep):
            node = node.get(component)
            if node is None:
                return False
        return bool(node)

    def pop_under(self, root):
        node = self._root
        for component in absolute_path_key(root).split(os.sep):
            node = node.get(component)
            if node is None:
                return []
        pending = [node]
        keys = []
        while pending:
            for component, child in pending.pop().items():
                if component is None:
                    keys.append(child)
                else:
                    pending.append(child)
        keys.sort(key=lambda key: self._values[key][0])
        result = [(key, self._values[key][1]) for key in keys]
        for key in keys:
            del self[key]
        return result

    def relocate(self, result):
        for path, value in self.pop_under(result.path):
            self[result.relocate(path)] = value
