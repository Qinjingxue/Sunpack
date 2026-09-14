from sunpack.contracts.filesystem import DirectorySnapshot
from sunpack.relations.internal.group_builder import RelationsGroupBuilder
from sunpack.relations.internal.models import CandidateGroup


class RelationsScheduler:
    """Public facade for relation grouping.

    The relation layer is intentionally a black box to callers: it receives a
    directory snapshot and returns logical archive candidates. Internal filename
    parsing, split expansion, and companion discovery live under
    sunpack.relations.internal.
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._builder = RelationsGroupBuilder(self.config)

    def set_password_callback(self, callback) -> None:
        """Forward discovered-password notifications to the watch scheduler."""
        self._builder.set_password_callback(callback)

    def refresh_password_sources(self) -> None:
        """Synchronize the relation prober's store with live sources."""
        self._builder.refresh_password_sources()

    def build_candidate_groups(
        self,
        snapshot: DirectorySnapshot,
        path_passwords: dict[str, str] | None = None,
    ) -> list[CandidateGroup]:
        return self._builder.build_candidate_groups(snapshot, path_passwords=path_passwords)

    def resolve_volume_once(
        self,
        current_paths: list[str],
        candidate_paths: list[str],
        *,
        format_hint: str = "",
        path_passwords: dict[str, str] | None = None,
    ) -> CandidateGroup | None:
        return self._builder.resolve_volume_once(
            current_paths,
            candidate_paths,
            format_hint=format_hint,
            path_passwords=path_passwords,
        )

    def resolve_volume_once_in_directory(
        self,
        current_paths: list[str],
        *,
        format_hint: str = "",
    ) -> CandidateGroup | None:
        return self._builder.resolve_volume_once_in_directory(
            current_paths,
            format_hint=format_hint,
        )

    def detect_split_role(self, filename: str) -> str | None:
        return self._builder.detect_split_role(filename)

    def logical_name_for_archive(self, filename: str) -> str:
        return self._builder.get_logical_name(filename, is_archive=True)

    def select_first_volume(self, paths: list[str]) -> str:
        return self._builder.select_first_volume(paths)

    def should_scan_split_siblings(self, archive: str, *, is_split: bool = False, is_sfx_stub: bool = False) -> bool:
        return self._builder.should_scan_split_siblings(archive, is_split=is_split, is_sfx_stub=is_sfx_stub)

    def find_standard_split_siblings(self, archive: str) -> list[str]:
        return self._builder.find_standard_split_siblings(archive)

    def parse_numbered_volume(self, path: str):
        return self._builder.parse_numbered_volume(path)
