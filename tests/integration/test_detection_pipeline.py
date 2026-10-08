import tempfile
import unittest
from pathlib import Path

from sunpack.core.config.schema import normalize_config
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_config import with_detection_pipeline


def minimal_config():
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }, precheck=[
        {"name": "blacklist", "enabled": True, "blocked_files": []},
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
    ]))


class DetectionPipelineTests(unittest.TestCase):
    def test_relations_confirms_zip_without_detection_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.zip"
            archive_path.write_bytes(b"PK\x05\x06" + b"\0" * 18)

            result = ArchiveTaskProvider(minimal_config()).discover_targets([str(archive_path)])
            self.assertEqual(len(result.resolved_tasks), 1)
            self.assertEqual(result.resolved_tasks[0].discovery_source, "relations")

if __name__ == "__main__":
    unittest.main()
