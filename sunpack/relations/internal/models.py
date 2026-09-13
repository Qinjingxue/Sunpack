from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class FileRelation:
    filename: str
    logical_name: str
    split_role: Optional[str] = None
    is_split_member: bool = False
    has_generic_001_head: bool = False
    is_plain_numeric_member: bool = False
    has_split_companions: bool = False
    is_split_exe_companion: bool = False
    is_disguised_split_exe_companion: bool = False
    is_split_related: bool = False
    match_rar_disguised: bool = False
    match_rar_head: bool = False
    match_001_head: bool = False
    split_family: str = ""
    split_index: int = 0


@dataclass
class SplitVolumeEntry:
    path: str
    number: int
    role: str = "member"
    source: str = "standard"
    style: str = ""
    prefix: str = ""
    width: int = 3


@dataclass
class CandidateGroup:
    head_path: str
    logical_name: str
    relation: FileRelation
    input_paths: List[str]
    is_split_candidate: bool = False
    head_size: int | None = None
    split_volumes: List[SplitVolumeEntry] = None
    split_group_complete: bool | None = None
    split_missing_reason: str = ""
    split_missing_indices: List[int] = None
    split_observed_missing_ranges: List[tuple[int, int]] = None
    split_layout_status: str = "ambiguous"
    split_completeness_status: str = "ambiguous"
    split_completeness_confidence: str = "hint"
    split_completeness_basis: List[str] = None
    head_metadata: Dict[str, Any] | None = None
    encrypted_unresolved: bool = False
    # Launcher-only SFX files are related to a split archive, but are not
    # archive input volumes. Keep them outside input_paths so the archive
    # descriptor and backend never receive the PE carrier as data.
    companion_paths: List[str] = None
    carrier_path: str = ""
    carrier_size: int | None = None
    format_reject_mask: int = 0

    @property
    def kind(self) -> str:
        return "split_archive" if self.is_split_candidate or self.relation.is_split_related else "file"

    @property
    def entry_path(self) -> str:
        return self.head_path

    @property
    def owned_paths(self) -> List[str]:
        """Return data inputs plus non-input companions owned by this group."""
        return list(dict.fromkeys([*self.input_paths, *(self.companion_paths or [])]))
