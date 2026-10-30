"""Persistent Watch exclusions; normal reservations own active output paths."""
from __future__ import annotations

import os
import threading

from sunpack_native import create_output_root, watch_path_identity
from sunpack.core.support.path_keys import path_key, resolved_path_key


class WatchOutputRoots:
    def __init__(self, state, scopes):
        self.state = state
        self.scopes = scopes
        self._lock = threading.RLock()
        self._closed = False
        self.recover_flattens()
        changes = []
        keys = set(state._native.runtime_keys("owned|"))
        for key in tuple(keys):
            record = state._native.runtime_record(key)
            paths = self._paths(record["path"])
            if not self._relevant(paths) or not self._matches(record):
                changes.append({"op": "runtime", "key": key})
            else:
                # Upgrade lexical-only records without changing their owner or
                # identity. Both namespaces share the existing WAL lifecycle.
                for path in paths:
                    alias = "owned|" + path_key(path)
                    if alias not in keys:
                        changes.append({"op": "runtime", "key": alias, "value": record})
                        keys.add(alias)
        state.commit_runtime(changes, durable=True)

    @staticmethod
    def _paths(path):
        absolute = os.path.abspath(path)
        resolved = resolved_path_key(absolute)
        return (absolute,) if path_key(absolute) == resolved else (absolute, resolved)

    def _relevant(self, paths):
        return any(any(scope.native.intersects_output(path) for scope in self.scopes)
                   or self.state._native.output_root_in_use(path) for path in paths)

    @staticmethod
    def _identity(path):
        volume, identity, _ = watch_path_identity(path)
        return f"{volume}|{identity}"

    def _matches(self, record):
        try:
            identity = self._identity(record["path"])
        except FileNotFoundError:
            from sunpack.runtime.watch.roots import watch_path_available
            return (not all(watch_path_available(path, self.scopes)
                            for path in self._paths(record["path"]))
                    or self.state._native.output_root_in_use(record["path"]))
        except OSError:
            return True
        return identity in record.get("identities", ())

    def register(self, path):
        paths = self._paths(path)
        if not self._relevant(paths):
            return
        with self._lock:
            if self._closed or any(self.protected(item) for item in paths):
                return
            # Reservations already exclude this root before mkdir emits events.
            # Only Watch-relevant outputs incur identity IO and a WAL record.
            # Exclusive creation must reject directories created by other processes.
            create_output_root(os.path.abspath(path))
            self._put(path, paths)

    def _put(self, path, paths):
        record = {"path": os.path.abspath(path), "identities": [self._identity(path)]}
        self.state.commit_runtime([{"op": "runtime", "key": "owned|" + path_key(item),
            "value": record} for item in paths], durable=True)

    def protected(self, path):
        # NativeWatchState serializes this read with record publication. Admission
        # already holds the state lock; taking the writer lock here would invert
        # register/reconcile's lock order. Reservations cover unpublished roots.
        return self.state._native.owned_root(path) is not None

    def prepare_flatten(self, owner, root, work, leaf):
        """Retain both directory identities before the first physical rename."""
        with self._lock:
            if not self._relevant(self._paths(root)):
                return
            old_identity, new_identity = self._identity(root), self._identity(leaf)
            record = dict(owner=owner, root=root, work=work, leaf=leaf,
                          old_identity=old_identity, new_identity=new_identity)
            changes = [{"op": "runtime", "key": "flatten|" + path_key(root), "value": record}]
            if owner:
                # Reuse promotion's verified-output checkpoint. Keep the active
                # record so cancellation can still revoke and remove this tree.
                changes.append({"op": "checkpoint_output", "owner": owner, "output": root})
            for path, identities in ((root, [old_identity, new_identity]), (work, [old_identity])):
                changes.extend({"op": "runtime", "key": "owned|" + path_key(alias),
                    "value": {"path": path, "identities": identities}} for alias in self._paths(path))
            self.state.commit_runtime(changes, durable=True)

    def finish_flatten(self, root):
        with self._lock:
            key = "flatten|" + path_key(root)
            record = self.state._native.runtime_record(key)
            if record is None:
                return
            work = record["work"]
            identity = self._identity(root)
            changes = []
            if identity == record["new_identity"]:
                # A failed publish can temporarily relocate active state to work.
                if record["owner"]:
                    for source in (work, record["leaf"]):
                        changes.append({"op": "relocate_output", "owner": record["owner"],
                            "source": source, "destination": root, "identity": identity})
            elif identity != record["old_identity"] or os.path.exists(work):
                return
            if os.path.exists(work):
                # Empty-wrapper cleanup failed; retain its intent for restart.
                self.state.commit_runtime(changes, durable=True)
                return
            for alias in self._paths(root):
                changes.append({"op": "runtime", "key": "owned|" + path_key(alias),
                    "value": {"path": root, "identities": [identity]}})
            changes.append({"op": "runtime", "key": key})
            changes.extend({"op": "runtime", "key": "owned|" + path_key(alias)} for alias in self._paths(work))
            self.state.commit_runtime(changes, durable=True)

    def recover_flattens(self):
        from sunpack_native import flatten_single_branch_directories

        for key in self.state._native.runtime_keys("flatten|"):
            record = self.state._native.runtime_record(key)
            root, work = record["root"], record["work"]
            try:
                root_id = self._identity(root) if os.path.exists(root) else None
                work_id = self._identity(work) if os.path.exists(work) else None
                if work_id not in (None, record["old_identity"]):
                    continue
                if root_id == record["old_identity"] and work_id is None:
                    self.finish_flatten(root)
                    continue
                if root_id not in (None, record["new_identity"]):
                    continue
                if root_id is None and work_id is None:
                    continue
                if root_id is None:
                    leaf = os.path.join(work, os.path.relpath(record["leaf"], root))
                    if self._identity(leaf) != record["new_identity"]:
                        continue
                flatten_single_branch_directories(root, work_path=work, resume_leaf=record["leaf"])
                self.finish_flatten(root)
            except OSError:
                # Offline/locked output retains its intent and exclusions.
                continue

    def reconcile(self, path, *, recursive=False):
        normalized = path_key(path)
        with self._lock:
            if self._closed:
                return
            changes = []
            # Registration indexes both namespaces, so ordinary filesystem
            # events can find a record without resolving their paths again.
            for key in self.state._native.runtime_keys("owned|" + normalized):
                root = key[len("owned|"):]
                if root != normalized and not (recursive and root.startswith(normalized + os.sep)):
                    continue
                record = self.state._native.runtime_record(key)
                if not self._matches(record):
                    aliases = {key, *("owned|" + path_key(item)
                                      for item in self._paths(record["path"]))}
                    changes.extend({"op": "runtime", "key": alias} for alias in aliases)
            self.state.commit_runtime(changes, durable=True)

    def replace(self, source, destination):
        paths = self._paths(destination)
        with self._lock:
            if self._closed:
                return
            if self._relevant(paths) and os.path.isdir(destination):
                ancestor = self.state._native.owned_root(destination)
                if ancestor is None or ancestor == path_key(destination):
                    self._put(destination, paths)
            self.reconcile(source, recursive=True)

    def close(self):
        with self._lock:
            self._closed = True
