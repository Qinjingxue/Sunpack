import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from sunpack.contracts.detection import FactBag
from sunpack.coordinator.detection_diagnostics import DetectionDiagnostics
from sunpack.coordinator.nested_extraction_policy import select_single_candidate_ratio
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.detection import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


def config_with_rules():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[{"name": "size_range", "enabled": True, "gte": 0}])


def embedded_config(*, ratio=1.0):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {
            "name": "embedded_payload_identity",
            "enabled": True,
            "deep_scan_single_candidate_ratio": ratio,
        },
    ])


def zip_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("inside.txt", "hello")
    return output.getvalue()


class DetectionBehaviorTests(unittest.TestCase):
    def test_group_builder_sets_split_relation_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "game.part1.rar"
            second = root / "game.part2.rar"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            (root / "orphan.002").write_bytes(b"alone")

            groups = build_fact_bags_for_targets([str(root)], config=config_with_rules())
            split_group = next(group for group in groups if group.get("file.logical_name") == "game")
            orphan = next(group for group in groups if group.get("file.path", "").endswith("orphan.002"))
            self.assertTrue(split_group.get("relation.is_split_related"))
            self.assertEqual(split_group.get("candidate.entry_path"), str(first))
            self.assertEqual(split_group.get("candidate.member_paths"), [str(first), str(second)])
            self.assertFalse(orphan.get("relation.is_split_related"))

    def test_inspect_uses_target_grouping_for_directory_split_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "game.part1.rar"
            second = root / "game.part2.rar"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            results = DetectionDiagnostics(config_with_rules()).collect([str(root)])
            split_result = next(result for result in results if result.fact_bag.get("file.logical_name") == "game")
            self.assertEqual(split_result.path, str(first))
            self.assertEqual(split_result.fact_bag.get("file.split_members"), [str(second)])

    def test_unresolved_extensionless_file_gets_reliable_full_embedded_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "movie.mp4"
            carrier.write_bytes(b"video-prefix" + zip_bytes())
            results = ArchiveTaskProvider(embedded_config()).detect_targets([str(carrier)])
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertTrue(result.decision.should_extract)
            self.assertEqual(result.fact_bag.get("file.detected_ext"), ".zip")
            self.assertTrue(result.fact_bag.get("file.embedded_archive_found"))
            self.assertTrue(result.fact_bag.get("analysis.signature_prepass", {}).get("full_scan_complete"))

    def test_embedded_scan_precedes_precheck_for_nonzero_offset_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "carrier.bin"
            carrier.write_bytes(b"carrier-prefix" + zip_bytes())
            config = with_detection_pipeline(
                {
                    "thresholds": {
                        "archive_score_threshold": 5,
                        "maybe_archive_threshold": 3,
                    },
                },
                precheck=[{
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "deep_scan_single_candidate_ratio": 1.0,
                }],
            )

            results = ArchiveTaskProvider(config).detect_targets([str(carrier)])

            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertTrue(result.decision.should_extract)
            self.assertEqual(result.decision.decision_stage, "precheck")
            self.assertEqual(result.decision.deciding_rule, "embedded_payload_identity")
            self.assertTrue(result.fact_bag.get("candidate.embedded_scan_allowed"))
            self.assertTrue(result.fact_bag.get("analysis.signature_prepass", {}).get("full_scan_complete"))

    def test_relations_volume_anchor_is_opaque_to_detection(self):
        bag = FactBag()
        bag.set("file.path", "payload.part5.zip.hidden-5")
        bag.set("file.size", 8192)
        bag.set("candidate.entry_path", "payload.part5.zip.hidden-5")
        bag.set("candidate.embedded_scan_allowed", True)
        bag.set("relation.volume_anchor", {
            "format": "zip",
            "confidence": "strong",
            "multivolume": True,
            "anchor_roles": ["terminal"],
        })
        bag.set("embedded_archive.analysis", {
            "found": True,
            "complete": True,
            "signature_scan_complete": True,
            "logical_resolution_complete": True,
            "raw_hit_count": 1,
            "budget_exhausted": False,
            "read_bytes": 8192,
            "file_size": 8192,
            "hits": [{"name": "7z", "offset": 2048, "source": "embedded_scan"}],
            "candidates": [{
                "format": "7z",
                "detected_ext": ".7z",
                "offset": 2048,
                "end_offset": 6144,
                "confidence": 1.0,
                "validation": "next-header-crc",
                "candidate_kind": "logical_archive",
                "boundary_kind": "exact",
                "range_end_offset": 6144,
                "extractable": True,
                "contained_anchor_count": 0,
            }],
        })

        decision = DetectionScheduler(embedded_config()).evaluate_bag(bag)

        self.assertTrue(decision.should_extract)
        self.assertEqual(bag.get("file.detected_ext"), ".7z")
        self.assertEqual(bag.get("file.probe_offset"), 2048)
        self.assertTrue(bag.get("file.embedded_archive_found"))

    def test_relations_volume_anchor_cannot_accept_a_candidate(self):
        bag = FactBag()
        bag.set("file.path", "opaque-volume.bin")
        bag.set("candidate.entry_path", "opaque-volume.bin")
        bag.set("relation.volume_anchor", {
            "format": "7z",
            "confidence": "strong",
            "multivolume": True,
            "anchor_roles": ["first"],
        })
        bag.set("7z.structure", {
            "magic_matched": False,
            "plausible": False,
            "strong_accept": False,
        })
        config = with_detection_pipeline(
            {"thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3}},
            precheck=[{"name": "seven_zip_structure_accept", "enabled": True}],
        )

        decision = DetectionScheduler(config).evaluate_bag(bag)

        self.assertFalse(decision.should_extract)
        self.assertEqual(decision.matched_rules, [])

    def test_shared_embedded_scan_switch_disables_detection_and_analysis_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "movie.mp4"
            carrier.write_bytes(b"video-prefix" + zip_bytes())
            config = embedded_config()
            config["embedded_scan"] = {"enabled": False}

            results = ArchiveTaskProvider(config).detect_targets([str(carrier)])

            self.assertFalse(results[0].decision.should_extract)
            self.assertFalse(results[0].fact_bag.get("candidate.embedded_scan_allowed"))

    def test_single_candidate_ratio_selects_every_candidate_at_or_above_threshold(self):
        bags = []
        for name, size in (("large", 40), ("medium", 30), ("small", 30)):
            bag = FactBag()
            bag.set("file.path", name)
            bag.set("file.size", size)
            bags.append(bag)
        self.assertEqual(
            [bag.get("file.path") for bag in select_single_candidate_ratio(bags, 0.3)],
            ["large", "medium", "small"],
        )
        self.assertEqual(
            [bag.get("file.path") for bag in select_single_candidate_ratio(bags, 0.31)],
            ["large"],
        )

    def test_single_candidate_ratio_counts_split_group_once_at_logical_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "game.001"
            second = root / "game.002"
            other = root / "other.bin"
            first.write_bytes(b"a" * 40)
            second.write_bytes(b"b" * 30)
            other.write_bytes(b"c" * 30)

            split = FactBag()
            split.set("file.path", str(first))
            split.set("file.size", 40)
            split.set("candidate.member_paths", [str(first), str(second), str(first)])
            ordinary = FactBag()
            ordinary.set("file.path", str(other))
            ordinary.set("file.size", 30)

            selected = select_single_candidate_ratio([split, ordinary], 0.7)
            self.assertEqual(selected, [split])

    def test_single_candidate_ratio_skips_empty_or_disabled_selection(self):
        empty = FactBag()
        empty.set("file.path", "empty")
        empty.set("file.size", 0)
        self.assertEqual(select_single_candidate_ratio([empty], 0.3), [])
        self.assertEqual(select_single_candidate_ratio([empty], 0.0), [])

    def test_recursive_candidate_selection_gates_the_entire_embedded_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selected_path = root / "large.bin"
            skipped_path = root / "small.exe"
            selected_path.write_bytes(b"x" * 70)
            skipped_path.write_bytes(b"y" * 30)

            results = ArchiveTaskProvider(embedded_config(ratio=0.6)).detect_targets(
                [str(selected_path), str(skipped_path)],
                is_recursive_scan=True,
            )
            by_name = {
                Path(result.fact_bag.get("file.path")).name: result.fact_bag
                for result in results
            }

            self.assertTrue(
                by_name["large.bin"].get("candidate.embedded_scan_allowed")
            )
            self.assertTrue(by_name["large.bin"].has("executable.carrier"))
            self.assertFalse(
                by_name["small.exe"].get("candidate.embedded_scan_allowed")
            )
            self.assertFalse(by_name["small.exe"].has("executable.carrier"))

    def test_structurally_invalid_magic_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "payload.data"
            carrier.write_bytes(b"prefix" + b"PK\x03\x04not-a-local-header")
            results = ArchiveTaskProvider(embedded_config()).detect_targets([str(carrier)])
            self.assertFalse(results[0].decision.should_extract)

    def test_pe_overlay_remains_an_ordinary_detection_result(self):
        bag = FactBag()
        bag.set("file.path", "installer.exe")
        bag.set("candidate.embedded_scan_allowed", True)
        bag.set("embedded_archive.analysis", {"found": False})
        bag.set("pe.overlay_structure", {
            "is_pe": True,
            "archive_like": True,
            "format": "7z",
            "detected_ext": ".7z",
            "overlay_offset": 434176,
            "archive_offset": 434176,
        })
        decision = DetectionScheduler(embedded_config()).evaluate_bag(bag)
        self.assertTrue(decision.should_extract)
        self.assertEqual(bag.get("file.container_type"), "pe")
        self.assertEqual(bag.get("file.probe_offset"), 434176)

    def test_zero_start_zip_identity_precedes_recursive_embedded_scan(self):
        bag = FactBag()
        bag.set("file.path", "application.exe")
        bag.set("candidate.entry_path", "application.exe")
        bag.set("candidate.embedded_scan_allowed", True)
        bag.set("executable.carrier", {
            "kind": "runtime_bundle",
            "runtime_profile": "par_packer",
            "is_executable": True,
        })
        bag.set("zip.eocd_structure", {
            "plausible": True,
            "central_directory_present": True,
            "central_directory_walk_ok": True,
            "local_header_links_ok": True,
            "archive_offset": 0,
            "archive_starts_at_zero": True,
        })
        config = with_detection_pipeline(
            {"thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3}},
            precheck=[
                {"name": "zip_structure_accept", "enabled": True},
                {"name": "embedded_payload_identity", "enabled": True},
            ],
        )

        decision = DetectionScheduler(config).evaluate_bag(bag)

        self.assertTrue(decision.should_extract)
        self.assertEqual(decision.deciding_rule, "zip_structure_accept")
        self.assertNotIn("par_packer", decision.stop_reason)

    def test_prefixed_zip_identity_defers_to_runtime_bundle(self):
        bag = FactBag()
        bag.set("file.path", "application.exe")
        bag.set("candidate.entry_path", "application.exe")
        bag.set("candidate.embedded_scan_allowed", True)
        bag.set("executable.carrier", {
            "kind": "runtime_bundle",
            "runtime_profile": "par_packer",
            "is_executable": True,
        })
        bag.set("zip.eocd_structure", {
            "plausible": True,
            "central_directory_present": True,
            "central_directory_walk_ok": True,
            "local_header_links_ok": True,
            "archive_offset": 0,
            "archive_starts_at_zero": False,
        })
        config = with_detection_pipeline(
            {"thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3}},
            precheck=[
                {"name": "zip_structure_accept", "enabled": True},
                {"name": "embedded_payload_identity", "enabled": True},
            ],
        )

        decision = DetectionScheduler(config).evaluate_bag(bag)

        self.assertFalse(decision.should_extract)
        self.assertEqual(decision.deciding_rule, "embedded_payload_identity")
        self.assertIn("par_packer", decision.stop_reason)


if __name__ == "__main__":
    unittest.main()
