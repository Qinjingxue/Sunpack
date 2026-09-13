import json
import os
from pathlib import Path
from time import perf_counter

import pytest

from sunpack.config.detection_view import scan_filters_config
from sunpack.config.loader import clear_config_cache, load_config
from sunpack.coordinator.nested_extraction_policy import NestedExtractionPolicy
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.coordinator.task_provider import ArchiveTaskProvider


GAME_TREE_ROOT = Path(os.environ.get("SUNPACK_GAME_TREE_ROOT", r"D:\game"))

pytestmark = pytest.mark.skipif(
    os.environ.get("SUNPACK_RUN_GAME_TREE_TEST") != "1",
    reason="set SUNPACK_RUN_GAME_TREE_TEST=1 to scan the local game tree",
)


def test_game_tree_resources_are_not_authorized_for_recursive_extraction(monkeypatch):
    if not GAME_TREE_ROOT.is_dir():
        pytest.skip(f"game tree is not available: {GAME_TREE_ROOT}")

    output_dirs = sorted(
        (path for path in GAME_TREE_ROOT.iterdir() if path.is_dir()),
        key=lambda path: os.path.normcase(str(path)),
    )
    if not output_dirs:
        pytest.skip(f"game tree has no child directories: {GAME_TREE_ROOT}")

    # tests/conftest.py disables size filtering for small generated fixtures.
    # This corpus test must exercise the repository's real recursive-scan
    # configuration, including the current r > 0 B range.
    monkeypatch.delenv("SUNPACK_CONFIG_OVERRIDES", raising=False)
    clear_config_cache()
    try:
        config = load_config()
        size_filter = next(
            item
            for item in scan_filters_config(config)
            if item.get("name") == "size_range"
        )
        assert size_filter["enabled"] is True
        assert size_filter["range"] == "r > 0 B"

        timings = {}
        output_scan = NestedOutputScanPolicy(config)
        started = perf_counter()
        scan_roots = output_scan.scan_roots_from_outputs(
            [str(path) for path in output_dirs]
        )
        timings["output_scan_policy_seconds"] = perf_counter() - started
        expected_roots = {
            os.path.normcase(str(path.resolve())) for path in output_dirs
        }
        assert {
            os.path.normcase(str(Path(path).resolve())) for path in scan_roots
        } == expected_roots

        scan_session = output_scan.take_scan_session(scan_roots)
        assert scan_session is not None

        # Detection is run against the real tree, but no extractor is invoked:
        # this is only the same recursive output scan used after extraction.
        import sunpack.coordinator.task_provider as task_provider_module
        from sunpack.coordinator.scan_session import DetectionScanSession
        from sunpack.detection.pipeline.facts.batch_provider import BatchFactProvider
        from sunpack.detection.pipeline.processors.runner import ProcessingCoordinator
        from sunpack.detection.pipeline.rules.manager import RuleManager
        from sunpack.detection.scheduler import DetectionScheduler
        import sunpack.relations.internal.group_builder as group_builder_module
        from sunpack.relations.internal.group_builder import RelationsGroupBuilder
        from sunpack.relations.scheduler import RelationsScheduler

        detailed_timings = {}
        detailed_counts = {}

        def add_timing(name, elapsed):
            detailed_timings[name] = detailed_timings.get(name, 0.0) + elapsed

        def add_count(name, value=1):
            detailed_counts[name] = detailed_counts.get(name, 0) + value

        original_file_head_facts = scan_session.file_head_facts_for_paths

        def timed_file_head_facts(paths, *args, **kwargs):
            before = len(scan_session._file_head_facts)
            started = perf_counter()
            result = original_file_head_facts(paths, *args, **kwargs)
            add_timing("file_head_facts_for_paths_seconds", perf_counter() - started)
            add_count("file_head_facts_for_paths_calls")
            add_count("file_head_facts_requested", len(paths))
            add_count("file_head_facts_newly_cached", len(scan_session._file_head_facts) - before)
            return result

        monkeypatch.setattr(scan_session, "file_head_facts_for_paths", timed_file_head_facts)

        original_prefill_facts = BatchFactProvider.prefill_facts

        def timed_prefill_facts(self, *args, **kwargs):
            started = perf_counter()
            result = original_prefill_facts(self, *args, **kwargs)
            add_timing("batch_prefill_facts_seconds", perf_counter() - started)
            add_count("batch_prefill_facts_calls")
            return result

        monkeypatch.setattr(BatchFactProvider, "prefill_facts", timed_prefill_facts)

        original_ensure_facts = ProcessingCoordinator.ensure_facts

        def timed_ensure_facts(self, *args, **kwargs):
            started = perf_counter()
            result = original_ensure_facts(self, *args, **kwargs)
            add_timing("processing_ensure_facts_seconds", perf_counter() - started)
            add_count("processing_ensure_facts_calls")
            return result

        monkeypatch.setattr(ProcessingCoordinator, "ensure_facts", timed_ensure_facts)

        original_ensure_fact = ProcessingCoordinator.ensure_fact

        def timed_ensure_fact(self, fact_bag, fact_name, stack):
            started = perf_counter()
            result = original_ensure_fact(self, fact_bag, fact_name, stack)
            add_timing(f"processing_ensure_fact::{fact_name}::seconds", perf_counter() - started)
            add_count(f"processing_ensure_fact::{fact_name}::calls")
            return result

        monkeypatch.setattr(ProcessingCoordinator, "ensure_fact", timed_ensure_fact)

        original_snapshot = DetectionScanSession.snapshot_for_directory

        def timed_snapshot(self, directory):
            started = perf_counter()
            result = original_snapshot(self, directory)
            add_timing("snapshot_for_directory_seconds", perf_counter() - started)
            return result

        monkeypatch.setattr(DetectionScanSession, "snapshot_for_directory", timed_snapshot)

        original_relation_groups = DetectionScanSession.relation_groups_for_directory

        def timed_relation_groups(self, directory, *args, **kwargs):
            started = perf_counter()
            result = original_relation_groups(self, directory, *args, **kwargs)
            add_timing("relation_groups_for_directory_seconds", perf_counter() - started)
            add_count("relation_group_directory_calls")
            add_count("relation_group_count", len(result))
            return result

        monkeypatch.setattr(
            DetectionScanSession,
            "relation_groups_for_directory",
            timed_relation_groups,
        )

        original_fact_bags_for_directory = DetectionScanSession.fact_bags_for_directory

        def timed_fact_bags_for_directory(self, directory):
            started = perf_counter()
            result = original_fact_bags_for_directory(self, directory)
            add_timing("fact_bags_for_directory_seconds", perf_counter() - started)
            add_count("fact_bag_directory_calls")
            return result

        monkeypatch.setattr(
            DetectionScanSession,
            "fact_bags_for_directory",
            timed_fact_bags_for_directory,
        )

        original_build_candidate_groups = RelationsScheduler.build_candidate_groups

        def timed_build_candidate_groups(self, *args, **kwargs):
            started = perf_counter()
            result = original_build_candidate_groups(self, *args, **kwargs)
            add_timing("relations_build_candidate_groups_seconds", perf_counter() - started)
            add_count("relations_build_candidate_groups_calls")
            return result

        monkeypatch.setattr(
            RelationsScheduler,
            "build_candidate_groups",
            timed_build_candidate_groups,
        )

        original_native_build_groups = group_builder_module._native_build_candidate_groups

        def timed_native_build_groups(*args, **kwargs):
            started = perf_counter()
            result = original_native_build_groups(*args, **kwargs)
            add_timing("relations_native_build_candidate_groups_seconds", perf_counter() - started)
            add_count("relations_native_build_candidate_groups_calls")
            return result

        monkeypatch.setattr(
            group_builder_module,
            "_native_build_candidate_groups",
            timed_native_build_groups,
        )

        original_build_groups_without_discovery = (
            RelationsGroupBuilder.build_candidate_groups_without_discovery
        )

        def timed_build_groups_without_discovery(self, *args, **kwargs):
            started = perf_counter()
            result = original_build_groups_without_discovery(self, *args, **kwargs)
            add_timing(
                "relations_build_candidate_groups_without_discovery_seconds",
                perf_counter() - started,
            )
            add_count("relations_build_candidate_groups_without_discovery_calls")
            return result

        monkeypatch.setattr(
            RelationsGroupBuilder,
            "build_candidate_groups_without_discovery",
            timed_build_groups_without_discovery,
        )

        original_evaluate_pool = DetectionScheduler.evaluate_pool

        def timed_evaluate_pool(self, *args, **kwargs):
            started = perf_counter()
            result = original_evaluate_pool(self, *args, **kwargs)
            add_timing("detection_evaluate_pool_seconds", perf_counter() - started)
            return result

        monkeypatch.setattr(DetectionScheduler, "evaluate_pool", timed_evaluate_pool)

        original_rule_evaluate_pool = RuleManager.evaluate_pool

        def timed_rule_evaluate_pool(self, *args, **kwargs):
            started = perf_counter()
            result = original_rule_evaluate_pool(self, *args, **kwargs)
            add_timing("rule_manager_evaluate_pool_seconds", perf_counter() - started)
            return result

        monkeypatch.setattr(RuleManager, "evaluate_pool", timed_rule_evaluate_pool)

        original_run_precheck = RuleManager._run_precheck

        def timed_run_precheck(self, *args, **kwargs):
            started = perf_counter()
            result = original_run_precheck(self, *args, **kwargs)
            add_timing("rule_manager_run_precheck_seconds", perf_counter() - started)
            return result

        monkeypatch.setattr(RuleManager, "_run_precheck", timed_run_precheck)

        original_ensure_pool_facts = DetectionScheduler._ensure_pool_facts

        def timed_ensure_pool_facts(self, fact_bags, required_facts, fact_configs=None):
            started = perf_counter()
            result = original_ensure_pool_facts(
                self,
                fact_bags,
                required_facts,
                fact_configs,
            )
            elapsed = perf_counter() - started
            add_timing("detection_ensure_pool_facts_seconds", elapsed)
            add_count("detection_ensure_pool_facts_calls")
            key = ",".join(sorted(required_facts)) or "<none>"
            add_timing(f"ensure_pool_facts::{key}::seconds", elapsed)
            add_count(f"ensure_pool_facts::{key}::calls")
            return result

        monkeypatch.setattr(
            DetectionScheduler,
            "_ensure_pool_facts",
            timed_ensure_pool_facts,
        )

        original_evaluate_precheck_rule = RuleManager._evaluate_precheck_rule

        def timed_evaluate_precheck_rule(self, bag, rule):
            started = perf_counter()
            result = original_evaluate_precheck_rule(self, bag, rule)
            name = getattr(rule, "name", "<unknown>")
            add_timing(f"precheck_rule::{name}::seconds", perf_counter() - started)
            add_count(f"precheck_rule::{name}::calls")
            return result

        monkeypatch.setattr(
            RuleManager,
            "_evaluate_precheck_rule",
            timed_evaluate_precheck_rule,
        )

        original_build_fact_bags = task_provider_module.build_fact_bags_for_targets

        def timed_build_fact_bags(*args, **kwargs):
            started = perf_counter()
            result = original_build_fact_bags(*args, **kwargs)
            timings["build_fact_bags_seconds"] = perf_counter() - started
            timings["fact_bag_count"] = len(result)
            return result

        monkeypatch.setattr(
            task_provider_module,
            "build_fact_bags_for_targets",
            timed_build_fact_bags,
        )

        provider = ArchiveTaskProvider(config)
        original_evaluate_bags = provider.detector.evaluate_bags

        def timed_evaluate_bags(*args, **kwargs):
            started = perf_counter()
            result = original_evaluate_bags(*args, **kwargs)
            timings["evaluate_bags_seconds"] = perf_counter() - started
            timings["detection_result_count"] = len(result)
            return result

        monkeypatch.setattr(provider.detector, "evaluate_bags", timed_evaluate_bags)

        started = perf_counter()
        tasks = provider.scan_targets(
            scan_roots,
            scan_session=scan_session,
            is_recursive_scan=True,
        )
        timings["scan_targets_seconds"] = perf_counter() - started
        timings["task_count"] = len(tasks)
        assert tasks, "the corpus should exercise at least one archive candidate"

        started = perf_counter()
        authorization = NestedExtractionPolicy(config).authorize_batch(
            tasks,
            scan_roots,
            scan_session,
            round_index=2,
        )
        timings["authorize_batch_seconds"] = perf_counter() - started
        timings["authorized_task_count"] = len(authorization.allowed_tasks)
        timings["internal_timings"] = detailed_timings
        timings["internal_counts"] = detailed_counts

        def rounded(value):
            if isinstance(value, float):
                return round(value, 3)
            if isinstance(value, dict):
                return {key: rounded(item) for key, item in value.items()}
            return value

        print(
            "game_tree_recursive_scan_timing "
            + json.dumps(
                rounded(timings),
                ensure_ascii=False,
                sort_keys=True,
            )
        )

        assert authorization.allowed_tasks == [], [
            task.main_path for task in authorization.allowed_tasks
        ]
    finally:
        clear_config_cache()
