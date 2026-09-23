from pathlib import Path

from sunpack.pipeline.coordinator.scanner import ScanOrchestrator
from tests.helpers.performance_fixtures import build_pressure_corpus, pressure_scan_config


def test_pressure_scan_finds_expected_archives_in_mixed_corpus(tmp_path):
    expected = build_pressure_corpus(tmp_path)

    results = ScanOrchestrator(pressure_scan_config()).scan(str(tmp_path))
    actual = sorted(Path(result.main_path).name for result in results)

    assert actual == expected
