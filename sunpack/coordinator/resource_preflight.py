import os
from types import SimpleNamespace

from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.scheduling.resource_model import build_resource_profile_key, estimate_resource_demand
from sunpack.passwords import PasswordSession
from sunpack.passwords.resolver import archive_structure_password_state, archive_structure_requires_password
from sunpack.rename.scheduler import RenameScheduler
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.sevenzip_bridge import cached_analyze_archive_resources


class ResourcePreflightInspector:
    def __init__(
        self,
        password_session: PasswordSession | None = None,
        rename_scheduler: RenameScheduler | None = None,
        precise_resource_min_size_mb: int = 256,
    ):
        self.password_session = password_session
        self.rename_scheduler = rename_scheduler or RenameScheduler()
        self.precise_resource_min_size_bytes = max(0, int(precise_resource_min_size_mb or 0)) * 1024 * 1024

    def inspect(self, task: ArchiveTask) -> ArchiveTask:
        archive_size = self._archive_size(task)
        if archive_structure_requires_password(task.fact_bag):
            # A validated format structure is enough to route password
            # resolution, but not enough to inspect encrypted payload data
            # without a password.  Keep resource estimation independent of a
            # second backend pass.
            return self.record_estimated_profile(
                task,
                reason="archive structure requires password resolution",
                archive_size=archive_size,
            )
        existing_analysis = knowledge_view.resource_analysis(task)
        if isinstance(existing_analysis, dict) and existing_analysis:
            analysis = SimpleNamespace(ok=not bool(existing_analysis.get("is_broken")), **existing_analysis)
            self.record_resource_demand(task, analysis)
            return task
        precise_analysis = self._precise_resource_analysis(task, archive_size)
        if precise_analysis is not None:
            task.fact_bag.set("resource.analysis", precise_analysis)
            self._write_resource_payload(task, analysis=precise_analysis)
            analysis = SimpleNamespace(ok=not bool(precise_analysis.get("is_broken")), **precise_analysis)
            self.record_resource_demand(task, analysis)
            return task
        reason = (
            "estimated small-archive resource profile"
            if archive_size < self.precise_resource_min_size_bytes
            else "estimated resource profile; archive analysis is owned by analysis layer"
        )
        return self.record_estimated_profile(task, reason=reason, archive_size=archive_size)

    def record_resource_demand(self, task: ArchiveTask, analysis) -> None:
        demand = estimate_resource_demand(analysis)
        profile_key = build_resource_profile_key(analysis)
        task.fact_bag.set("resource.tokens", demand.as_dict())
        task.fact_bag.set("resource.token_cost", demand.scalar_cost)
        task.fact_bag.set("resource.profile_key", profile_key)
        self._write_resource_payload(
            task,
            tokens=demand.as_dict(),
            token_cost=demand.scalar_cost,
            profile_key=profile_key,
        )

    def record_estimated_profile(
        self,
        task: ArchiveTask,
        *,
        reason: str = "estimated resource profile",
        archive_size: int | None = None,
        profile_suffix: str = "estimated",
    ) -> ArchiveTask:
        archive_size = self._archive_size(task) if archive_size is None else archive_size
        archive_type = self._archive_type_for(task)
        analysis = {
            "status": 0,
            "is_archive": True,
            "is_encrypted": archive_structure_password_state(task.fact_bag) == "required",
            "is_broken": False,
            "solid": False,
            "item_count": 0,
            "file_count": 0,
            "dir_count": 0,
            "archive_size": archive_size,
            "total_unpacked_size": 0,
            "total_packed_size": archive_size,
            "largest_item_size": 0,
            "largest_dictionary_size": 0,
            "archive_type": archive_type,
            "dominant_method": "",
            "message": reason,
        }
        task.fact_bag.set("resource.analysis", analysis)
        self._write_resource_payload(task, analysis=analysis)
        tokens = self._estimated_tokens_for_size(archive_size)
        token_cost = max(tokens.values())
        profile_key = f"{archive_type or 'unknown'}|{profile_suffix}|size<{self.precise_resource_min_size_bytes // (1024 * 1024)}m"
        task.fact_bag.set("resource.tokens", tokens)
        task.fact_bag.set("resource.token_cost", token_cost)
        task.fact_bag.set("resource.profile_key", profile_key)
        self._write_resource_payload(task, tokens=tokens, token_cost=token_cost, profile_key=profile_key)
        return task

    def record_estimated_single_task_profile(self, task: ArchiveTask) -> ArchiveTask:
        return self.record_estimated_profile(
            task,
            reason="estimated single-task resource profile",
            profile_suffix="estimated|single",
        )

    def _precise_resource_analysis(self, task: ArchiveTask, archive_size: int) -> dict | None:
        if archive_size < self.precise_resource_min_size_bytes:
            return None
        if self._needs_offset_detection(task):
            return None
        try:
            part_paths = (task.all_parts if task.all_parts and len(task.all_parts) > 1 else None) or None
            analysis = cached_analyze_archive_resources(
                task.main_path,
                password=self._password_for(task),
                part_paths=part_paths,
            )
        except Exception:
            return None
        if not getattr(analysis, "is_archive", False):
            return None
        return {
            "status": int(getattr(analysis, "status", 0) or 0),
            "is_archive": bool(getattr(analysis, "is_archive", False)),
            "is_encrypted": bool(getattr(analysis, "is_encrypted", False)),
            "is_broken": bool(getattr(analysis, "is_broken", False)),
            "solid": bool(getattr(analysis, "solid", False)),
            "item_count": int(getattr(analysis, "item_count", 0) or 0),
            "file_count": int(getattr(analysis, "file_count", 0) or 0),
            "dir_count": int(getattr(analysis, "dir_count", 0) or 0),
            "archive_size": int(getattr(analysis, "archive_size", 0) or archive_size),
            "total_unpacked_size": int(getattr(analysis, "total_unpacked_size", 0) or 0),
            "total_packed_size": int(getattr(analysis, "total_packed_size", 0) or archive_size),
            "largest_item_size": int(getattr(analysis, "largest_item_size", 0) or 0),
            "largest_dictionary_size": int(getattr(analysis, "largest_dictionary_size", 0) or 0),
            "archive_type": str(getattr(analysis, "archive_type", "") or self._archive_type_for(task)),
            "dominant_method": str(getattr(analysis, "dominant_method", "") or ""),
            "message": str(getattr(analysis, "message", "") or "precise native resource analysis"),
        }

    @staticmethod
    def _needs_offset_detection(task: ArchiveTask) -> bool:
        try:
            descriptor = task.archive_state().to_archive_input_descriptor()
        except (TypeError, ValueError):
            return False
        return descriptor.open_mode != "file"

    def _password_for(self, task: ArchiveTask) -> str:
        if self.password_session is None:
            return ""
        return self.password_session.get_resolved(task.key) or ""

    def _record_unknown(self, task: ArchiveTask) -> ArchiveTask:
        task.fact_bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
        task.fact_bag.set("resource.token_cost", 1)
        task.fact_bag.set("resource.profile_key", "unknown")
        self._write_resource_payload(task, tokens={"cpu": 1, "io": 1, "memory": 1}, token_cost=1, profile_key="unknown")
        return task

    def _archive_type_for(self, task: ArchiveTask) -> str:
        archive_type = str(knowledge_view.selected_format(task) or "").strip().lower().lstrip(".")
        if archive_type in {"seven_zip", "7zip"}:
            archive_type = "7z"
        if archive_type and archive_type not in {"pe", "unknown"}:
            return archive_type
        try:
            state_format = str(task.archive_state().format_hint or "").strip().lower().lstrip(".")
        except (AttributeError, TypeError, ValueError):
            state_format = ""
        if state_format in {"seven_zip", "7zip"}:
            state_format = "7z"
        if state_format and state_format not in {"pe", "unknown"}:
            return state_format
        detected_ext = str(knowledge_view.get(task, "filesystem.detected_ext", "") or os.path.splitext(task.main_path)[1]).lower()
        return detected_ext.lstrip(".") or archive_type or "unknown"

    def _archive_size(self, task: ArchiveTask) -> int:
        archive_size = 0
        for path in list(task.all_parts or [task.main_path]):
            try:
                archive_size += os.path.getsize(path)
            except OSError:
                pass
        return archive_size

    def _estimated_tokens_for_size(self, archive_size: int) -> dict[str, int]:
        archive_mb = max(0, int(archive_size or 0)) / (1024 * 1024)
        io = 1
        if archive_mb >= 4096:
            io = 4
        elif archive_mb >= 1024:
            io = 3
        elif archive_mb >= 256:
            io = 2
        return {"cpu": 1, "io": io, "memory": 1}

    def _write_resource_payload(
        self,
        task: ArchiveTask,
        *,
        analysis: dict | None = None,
        tokens: dict | None = None,
        token_cost: int | None = None,
        profile_key: str = "",
    ) -> None:
        knowledge = ensure_knowledge(task)
        if analysis:
            write_payload(knowledge, "resource.analysis", dict(analysis), source_layer="resource", source_module="preflight")
        if tokens:
            write_payload(knowledge, "resource.tokens", dict(tokens), source_layer="resource", source_module="preflight")
        if token_cost is not None:
            write_payload(knowledge, "resource", {"token_cost": int(token_cost or 0)}, source_layer="resource", source_module="preflight")
        if profile_key:
            write_payload(knowledge, "resource", {"profile_key": profile_key}, source_layer="resource", source_module="preflight")
        commit_task_knowledge(task, knowledge)
