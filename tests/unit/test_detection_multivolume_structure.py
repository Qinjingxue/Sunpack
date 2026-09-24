from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.relations.resolver import RelationResolver
from sunpack.core.support.path_keys import path_key


def _candidate(path, metadata, members=None, *, is_split=None):
    member_paths = tuple(str(item) for item in (members or [path]))
    archive_input = ArchiveInputDescriptor(
        entry_path=str(path),
        format_hint=str(metadata.get("format") or ""),
        logical_name=path.name,
        parts=[ArchiveInputPart(extent=InputExtent(str(item))) for item in member_paths],
    )
    return DiscoveryCandidate(
        archive_input=archive_input,
        carrier_path=str(path),
        cleanup_paths=member_paths,
        route="relations",
        relation_anchor=dict(metadata),
        is_split=(
            bool(metadata.get("multivolume"))
            if is_split is None
            else bool(is_split)
        ),
    )


def test_confirmed_disguised_split_family_is_one_input(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.txt"
    candidate = _candidate(first, {
        "format": "7z", "relation_confirmed": True, "multivolume": True,
        "structure_offset": 0,
    }, [first, second])

    result = RelationResolver().resolve([candidate])

    assert len(result.resolved_tasks) == 1
    assert result.claimed_paths == {path_key(str(first)), path_key(str(second))}


def test_incomplete_split_family_is_blocked_from_embedded(tmp_path):
    first = tmp_path / "first.001"
    candidate = _candidate(first, {
        "format": "rar", "relation_confirmed": False, "multivolume": True,
    })

    result = RelationResolver().resolve([candidate])

    assert result.blocked_paths == {path_key(str(first))}
    assert result.residual_paths == set()


def test_unconfirmed_single_file_multivolume_hint_reaches_embedded(tmp_path):
    first = tmp_path / "truncated-sfx.exe"
    candidate = _candidate(first, {
        "format": "7z", "relation_confirmed": False, "multivolume": True,
    }, is_split=False)

    result = RelationResolver().resolve([candidate])

    assert result.blocked_paths == set()
    assert result.residual_paths == {path_key(str(first))}


def test_unconfirmed_structural_rar_tail_member_is_blocked(tmp_path):
    tail = tmp_path / "archive.part6.rar"
    candidate = _candidate(tail, {
        "format": "rar",
        "relation_confirmed": False,
        "multivolume": True,
        "internal_volume_number": 6,
        "continuation_from_previous": True,
        "anchor_roles": ["any_volume", "member"],
    }, is_split=False)

    result = RelationResolver().resolve([candidate])

    assert result.blocked_paths == {path_key(str(tail))}
    assert result.residual_paths == set()


def test_confirmed_password_required_family_reaches_password_planning(tmp_path):
    first = tmp_path / "encrypted.part1"
    candidate = _candidate(first, {
        "format": "rar", "relation_confirmed": True,
        "needs_password": True, "multivolume": True,
    })

    result = RelationResolver().resolve([candidate])

    assert len(result.resolved_tasks) == 1
    assert result.blocked_paths == set()


def test_unknown_relation_candidate_can_reach_embedded(tmp_path):
    path = tmp_path / "unknown"
    candidate = _candidate(path, {"format": ""})

    result = RelationResolver().resolve([candidate])

    assert result.residual_paths == {path_key(str(path))}
