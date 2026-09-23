import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.helpers.pipeline_engine import execute_pipeline
from sunpack.config.schema import normalize_config
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.rename.scheduler import RenameScheduler
from sunpack.coordinator.task_provider import ArchiveTaskProvider
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
            self.assertEqual(len(result.resolved_inputs), 1)
            self.assertEqual(result.resolved_inputs[0].source, "relations")

    def test_archive_task_keeps_physical_path_and_exposes_format_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fake_doc.txt"
            source.write_text("not really a zip", encoding="utf-8")

            bag = FactBag()
            bag.set("file.path", str(source))
            bag.set("candidate.entry_path", str(source))
            bag.set("candidate.member_paths", [str(source)])
            bag.set("candidate.logical_name", "fake_doc")
            bag.set("file.detected_ext", ".zip")
            task = ArchiveTask.from_fact_bag(bag)

            self.assertTrue(source.exists())
            self.assertEqual(os.path.normcase(task.main_path), os.path.normcase(str(source)))
            self.assertEqual(task.archive_input().format_hint, "zip")
            self.assertFalse((root / "fake_doc.zip").exists())

    def test_pipeline_can_scan_and_extract_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("hello.txt", "hello from SunPack")

            summary = execute_pipeline(minimal_config(), str(root))

            self.assertEqual(summary.success_count, 1)
            self.assertEqual(summary.failed_tasks, [])
            self.assertTrue((root / "sample" / "hello.txt").exists())


if __name__ == "__main__":
    unittest.main()
