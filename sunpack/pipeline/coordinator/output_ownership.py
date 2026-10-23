"""Pipeline output lifetime, backed by the runtime's single native WAL store."""
from __future__ import annotations

import os
import threading

from sunpack_native import watch_path_identity, watch_identity_path, create_output_root
from sunpack.core.support.path_keys import path_key


class OutputOwnership:
    def __init__(self, config):
        self.config = config
        self.gate = threading.RLock()
        self._state = None
        self._active_owners = set()

    def state_for(self, path=None):
        with self.gate:
            if self._state is None:
                from sunpack.runtime.watch.state import WatchStateStore
                from sunpack.runtime.watch.service import service_state_dir
                self._state = WatchStateStore(path or os.path.join(service_state_dir(self.config), "state.json"))
                self._recover_unfinished()
            elif path is not None and path_key(str(self._state.path)) != path_key(path):
                raise ValueError("The runtime already owns a different state path")
            return self._state

    def _recover_unfinished(self):
        from sunpack.pipeline.postprocess.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent
        state = self._state
        changes = []
        for key in state._native.runtime_keys("owned|"):
            record = state._native.runtime_record(key)
            if not record["owner"]:
                continue
            if not record["identities"]:
                changes.append({"op":"runtime", "key":key})
                continue
            try:
                volume, identity, _ = watch_path_identity(record["path"])
            except FileNotFoundError:
                changes.extend(self._recover_location(key, record))
                continue
            except OSError:
                record.update(owner="", state="quarantined")
            else:
                if f"{volume}|{identity}" not in record["identities"]:
                    changes.extend(self._recover_location(key, record))
                    continue
                if record["state"] == "writing":
                    result = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(record["path"],
                        event=OutputCleanupEvent.EXTRACTION_ABORT, planned_output_dir=record["path"])
                    if result.cleaned or result.already_absent:
                        changes.append({"op":"runtime", "key":key})
                        continue
                    record["state"] = "quarantined"
                record["owner"] = ""
            changes.append({"op":"runtime", "key":key, "value":record})
        state.commit_runtime(changes, durable=True)

    def begin(self, path, owner, *, identities=()):
        state = self.state_for()
        record = {"path": os.path.abspath(path), "owner": owner, "identities": list(identities), "state": "writing"}
        operation = {"op": "runtime", "key": "owned|" + path_key(path), "value": record}
        with self.gate:
            if state._native.runtime_record(operation["key"]) is not None:
                raise FileExistsError(f"Output is already owned: {path}")
            self._active_owners.add(owner)
            state._native.apply(state._native.decode_operations([operation]))
        try:
            state.commit_runtime([operation], durable=True)
            if not identities:
                create_output_root(os.path.abspath(path))
                self.bind(path)
        except BaseException:
            state.commit_runtime([{"op": "runtime", "key": operation["key"]}], durable=True)
            raise

    def seal(self, path, *, succeeded):
        state = self.state_for()
        key = "owned|" + path_key(path)
        record = state._native.runtime_record(key)
        if record is not None:
            record["state"] = "sealed" if succeeded else "quarantined"
            state.commit_runtime([{"op":"runtime", "key":key, "value":record}], durable=True)

    def bind(self, path):
        state = self.state_for()
        key = "owned|" + path_key(path)
        record = state._native.runtime_record(key)
        if record is None:
            return
        try:
            volume, identity, _ = watch_path_identity(path)
        except FileNotFoundError:
            return
        record["identities"] = [f"{volume}|{identity}"]
        state.commit_runtime([{"op": "runtime", "key": key, "value": record}], durable=True)

    def prepare_flatten(self, root, owner, reservations):
        from sunpack_native import flatten_leaf
        leaf = flatten_leaf(root)
        if leaf is None:
            return None
        volume, identity, _ = watch_path_identity(root)
        _, leaf_identity, _ = watch_path_identity(leaf)
        root_key = "owned|" + path_key(root)
        state = self.state_for()
        record = state._native.runtime_record(root_key)
        if record is None:
            return None
        record["identities"] = [f"{volume}|{identity}", f"{volume}|{leaf_identity}"]
        state.commit_runtime([{"op":"runtime", "key":root_key, "value":record}], durable=True)
        work = reservations.reserve(root + ".__sunpack_flatten_work__",owner,set())
        self.begin(work, owner, identities=[f"{volume}|{identity}"])
        return work

    def protected(self, path):
        return self.state_for()._native.owned_root(path) is not None

    def reconcile(self, path, *, recursive=False):
        state = self.state_for()
        normalized = path_key(path)
        operations = []
        for key in state._native.runtime_keys("owned|" + normalized):
            root = key[len("owned|"):]
            if root != normalized and not (recursive and root.startswith(normalized + os.sep)):
                continue
            record = state._native.runtime_record(key)
            if record["owner"] in self._active_owners:
                continue
            if not record["identities"]:
                # No worker starts until binding is durable. An interrupted
                # mkdir intent cannot establish ownership of somebody's folder.
                operations.append({"op":"runtime","key":key})
                continue
            try:
                volume, identity, _ = watch_path_identity(record["path"])
            except FileNotFoundError:
                operations.extend(self._recover_location(key, record))
            except OSError:
                continue
            else:
                if f"{volume}|{identity}" not in record["identities"]:
                    operations.extend(self._recover_location(key, record))
        state.commit_runtime(operations, durable=True)

    def _recover_location(self, key, record):
        from sunpack.runtime.watch.service import _read_watch_root_entries
        from sunpack.core.contracts.discovery_scope import DiscoveryScope
        scopes = [DiscoveryScope(entry.input_root, recursive=True) for entry in _read_watch_root_entries()]
        for identity in record["identities"]:
            volume, file_id = identity.rsplit("|", 1)
            try:
                target = watch_identity_path(volume, file_id)
            except FileNotFoundError:
                continue
            except OSError:
                # Keep unresolved ownership until a later structural event.
                return []
            if target and any(scope.contains(target) for scope in scopes):
                record.update(path=target, owner="", state="retained", identities=[identity])
                return [{"op":"runtime", "key":key},
                    {"op":"runtime", "key":"owned|"+path_key(target), "value":record}]
        return [{"op":"runtime", "key":key}]

    def relocate(self, source, destination):
        state = self.state_for()
        source_key = path_key(source)
        changes = []
        for key in state._native.runtime_keys("owned|" + source_key):
            record = state._native.runtime_record(key)
            if record["owner"] in self._active_owners:
                continue  # Pipeline moves already publish both sides before rename.
            if not (path_key(record["path"]) == source_key or path_key(record["path"]).startswith(source_key + os.sep)):
                continue
            target = os.path.join(destination, os.path.relpath(record["path"], source))
            try:
                volume, identity, _ = watch_path_identity(target)
            except OSError:
                continue
            if f"{volume}|{identity}" in record["identities"]:
                record["path"] = os.path.normpath(target)
                changes.extend([{"op":"runtime","key":key},
                    {"op":"runtime","key":"owned|"+path_key(target),"value":record}])
        state.commit_runtime(changes, durable=True)

    def finish(self, owner):
        state = self._state
        if state is None:
            return
        from sunpack.runtime.watch.service import _read_watch_root_entries
        from sunpack.core.contracts.discovery_scope import DiscoveryScope
        scopes = [DiscoveryScope(entry.input_root, recursive=True) for entry in _read_watch_root_entries()]
        changes = []
        for key in state._native.runtime_owner_keys(owner):
            record = state._native.runtime_record(key)
            if record.get("owner") != owner:
                continue
            try:
                volume, identity, _ = watch_path_identity(record["path"])
            except FileNotFoundError:
                changes.append({"op": "runtime", "key": key})
                continue
            except OSError:
                record.update(owner="", state="quarantined")
            else:
                if not record["identities"] or f"{volume}|{identity}" not in record["identities"] or not any(scope.contains(record["path"]) for scope in scopes):
                    changes.append({"op": "runtime", "key": key})
                    continue
                record.update(owner="", state="quarantined" if record["state"] == "writing" else "retained",
                              identities=[f"{volume}|{identity}"])
            changes.append({"op": "runtime", "key": key, "value": record})
        state.commit_runtime(changes, durable=True)
        self._active_owners.discard(owner)

    def retain_scopes(self, scopes):
        """Drop removed roots' catalogs and outputs in one existing WAL transaction."""
        state = self.state_for()
        state.commit_runtime(state._native.prune_runtime_scopes([scope.native for scope in scopes]), durable=True)

    def close(self):
        if self._state is not None:
            self._state.close()
            self._state = None
        self._active_owners.clear()
