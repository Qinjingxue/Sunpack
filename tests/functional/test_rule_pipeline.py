from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.detection import DetectionScheduler
from sunpack.detection.validation import validate_detection_contracts
from sunpack.detection.pipeline.rules.precheck.tar_structure_accept import TarStructureAcceptRule
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_minimal_7z, make_zip


def _rule_pipeline_config():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "blacklist", "enabled": True, "blocked_files": []},
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
        {"name": "seven_zip_structure_accept", "enabled": True},
        {"name": "embedded_payload_identity", "enabled": True},
    ])


@pytest.mark.parametrize(
    ("relative_path", "content", "expected_extract"),
    [
        ("archive.zip", make_zip({"inside.txt": "hello"}), True),
        ("notes.txt", b"plain text", False),
        ("game/www/audio/bgm.7z", make_minimal_7z(), True),
    ],
    ids=["zip archive", "plain text", "runtime archive"],
)
def test_rule_pipeline_evaluates_generated_files(tmp_path, relative_path, content, expected_extract):
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    if "game/" in relative_path:
        (tmp_path / "game" / "game.exe").write_bytes(b"MZ")
        (tmp_path / "game" / "www" / "data").mkdir(parents=True, exist_ok=True)
        (tmp_path / "game" / "www" / "data" / "Map001.json").write_text("{}", encoding="utf-8")

    bag = FactBag()
    bag.set("file.path", str(target))
    decision = DetectionScheduler(_rule_pipeline_config()).evaluate_bag(bag)

    assert decision.should_extract is expected_extract


def test_logical_extension_promotes_matching_precheck_ahead_of_config_order(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(make_zip({"inside.txt": "hello"}))

    def fail_if_called(self, facts, config):
        raise AssertionError("unrelated TAR precheck ran before routed ZIP precheck")

    monkeypatch.setattr(TarStructureAcceptRule, "evaluate", fail_if_called)
    config = with_detection_pipeline(precheck=[
        {"name": "tar_structure_accept", "enabled": True},
        {"name": "zip_structure_accept", "enabled": True},
    ])
    bag = FactBag()
    bag.set("file.path", str(target))
    bag.set("candidate.logical_name", "archive.zip")

    decision = DetectionScheduler(config).evaluate_bag(bag)

    assert decision.should_extract is True
    assert decision.deciding_rule == "zip_structure_accept"


def test_removed_confirmation_layer_is_rejected():
    result = validate_detection_contracts({
        "detection": {
                "rule_pipeline": {
                    "precheck": [],
                    "confirmation": [],
            }
        }
    })

    assert result["errors"] == ["Unknown detection.rule_pipeline field(s): confirmation"]

