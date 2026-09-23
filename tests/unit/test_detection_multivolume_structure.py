from sunpack.contracts.detection import FactBag
from sunpack.relations.resolver import RelationResolver
from sunpack.support.path_keys import path_key


def _bag(path, metadata, members=None):
    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(item) for item in (members or [path])])
    bag.set("candidate.cleanup_paths", [str(item) for item in (members or [path])])
    bag.set("relation.volume_anchor", metadata)
    return bag


def test_confirmed_disguised_split_family_is_one_input(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.txt"
    bag = _bag(first, {
        "format": "7z", "relation_confirmed": True, "multivolume": True,
        "structure_offset": 0,
    }, [first, second])
    result, decisions = RelationResolver().resolve([bag])
    assert len(result.resolved_inputs) == 1
    assert result.claimed_paths == {path_key(str(first)), path_key(str(second))}
    assert len(decisions) == 1


def test_incomplete_split_family_is_blocked_from_embedded(tmp_path):
    first = tmp_path / "first.001"
    bag = _bag(first, {
        "format": "rar", "relation_confirmed": False, "multivolume": True,
    })
    result, decisions = RelationResolver().resolve([bag])
    assert result.blocked_paths == {path_key(str(first))}
    assert result.residual_paths == set()
    assert decisions == []


def test_confirmed_password_required_family_reaches_password_planning(tmp_path):
    first = tmp_path / "encrypted.part1"
    bag = _bag(first, {
        "format": "rar", "relation_confirmed": True,
        "needs_password": True, "multivolume": True,
    })
    result, decisions = RelationResolver().resolve([bag])
    assert len(result.resolved_inputs) == 1
    assert len(decisions) == 1
    assert result.blocked_paths == set()


def test_unknown_relation_candidate_can_reach_embedded(tmp_path):
    file = tmp_path / "unknown"
    bag = _bag(file, {"format": ""})
    result, _ = RelationResolver().resolve([bag])
    assert result.residual_paths == {path_key(str(file))}
