from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.discovery import DiscoveryCandidate
from sunpack.relations.resolver import RelationResolver
from sunpack.support.path_keys import path_key


def _candidate(path, metadata, members=None):
    member_paths = tuple(str(item) for item in (members or [path]))
    confirmed = bool(metadata.get("relation_confirmed"))
    archive_input = (
        ArchiveInputDescriptor.from_parts(
            archive_path=str(path),
            format_hint=str(metadata.get("format") or ""),
            logical_name=path.name,
        )
        if confirmed else None
    )
    return DiscoveryCandidate(
        entry_path=str(path),
        member_paths=member_paths,
        logical_name=path.name,
        carrier_path=str(path),
        cleanup_paths=member_paths,
        route="relations",
        format_hint=str(metadata.get("format") or ""),
        archive_input=archive_input,
        relation_anchor=dict(metadata),
        is_split=bool(metadata.get("multivolume")),
    )


def test_confirmed_disguised_split_family_is_one_input(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.txt"
    candidate = _candidate(first, {
        "format": "7z", "relation_confirmed": True, "multivolume": True,
        "structure_offset": 0,
    }, [first, second])

    result = RelationResolver().resolve([candidate])

    assert len(result.resolved_inputs) == 1
    assert result.claimed_paths == {path_key(str(first)), path_key(str(second))}


def test_incomplete_split_family_is_blocked_from_embedded(tmp_path):
    first = tmp_path / "first.001"
    candidate = _candidate(first, {
        "format": "rar", "relation_confirmed": False, "multivolume": True,
    })

    result = RelationResolver().resolve([candidate])

    assert result.blocked_paths == {path_key(str(first))}
    assert result.residual_paths == set()


def test_confirmed_password_required_family_reaches_password_planning(tmp_path):
    first = tmp_path / "encrypted.part1"
    candidate = _candidate(first, {
        "format": "rar", "relation_confirmed": True,
        "needs_password": True, "multivolume": True,
    })

    result = RelationResolver().resolve([candidate])

    assert len(result.resolved_inputs) == 1
    assert result.blocked_paths == set()


def test_unknown_relation_candidate_can_reach_embedded(tmp_path):
    path = tmp_path / "unknown"
    candidate = _candidate(path, {"format": ""})

    result = RelationResolver().resolve([candidate])

    assert result.residual_paths == {path_key(str(path))}
