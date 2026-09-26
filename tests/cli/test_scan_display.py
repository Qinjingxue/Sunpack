import io
import json
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.discovery import DiscoveryFinding
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.commands import scan


@pytest.mark.parametrize("language", ["zh", "en"])
@pytest.mark.parametrize("json_mode", [False, True])
def test_scan_localizes_discovery_without_changing_machine_results(monkeypatch, tmp_path, language, json_mode):
    path = str(tmp_path / "carrier.jpg")
    findings = [
        DiscoveryFinding(
            entry_path=path, source="embedded", format="rar", status="blocked",
            reason="embedded_password_required", part_paths=(path,), offset=904331,
        ),
        DiscoveryFinding(
            entry_path=path, source="embedded", format="zip", status="resolved",
            part_paths=(path,), offset=100, end_offset=200, extractable=True,
        ),
        DiscoveryFinding(
            entry_path=str(tmp_path / "split.7z"), source="relations", format="7z",
            status="resolved", part_paths=("split.7z.001", "split.7z.002"), extractable=True,
        ),
        DiscoveryFinding(
            entry_path=str(tmp_path / "stream.gz"), source="detection", format="gzip",
            status="resolved", extractable=True,
        ),
    ]
    calls = []

    def scan_report(paths):
        calls.append(paths)
        return SimpleNamespace(tasks=[], findings=findings)

    monkeypatch.setattr(scan, "load_request_config", lambda _cwd: {})
    monkeypatch.setattr(scan, "ScanOrchestrator", lambda *_args: SimpleNamespace(scan_report=scan_report))
    output = io.StringIO()
    reporter = CliReporter(json_mode=json_mode, stdout=output)
    ctx = CliContext(language=language, cwd=str(tmp_path), reporter=reporter)
    args = SimpleNamespace(paths=[str(tmp_path)], deep_detect=False, json=json_mode)

    code, result = scan.handle(args, ctx)

    assert code == 0
    assert calls == [[str(tmp_path)]]
    assert result.summary["finding_count"] == 4
    assert result.summary["blocked_finding_count"] == 1
    assert {item["status"] for item in result.items} == {"resolved", "blocked"}
    assert {item["discovery_source"] for item in result.items} == {"embedded", "relations", "detection"}
    if json_mode:
        assert output.getvalue() == ""
        reporter.emit_result(result)
        payload = json.loads(output.getvalue())
        assert payload["items"] == result.items
        assert payload["summary"] == result.summary
    else:
        text = output.getvalue()
        assert "[904331, ?)" in text
        assert "[100, 200)" in text
        if language == "zh":
            assert "发现 4 个归档：3 个可尝试解压，1 个暂无法进入解压" in text
            for label in ("发现方式=嵌入扫描", "发现方式=归档关系识别", "发现方式=格式确认",
                          "发现状态=可尝试解压", "发现状态=暂无法进入解压", "原因：压缩包需要密码", "分卷数=2"):
                assert label in text
            for internal in ("resolved", "blocked", "embedded", "relations", "detection"):
                assert internal not in text
        else:
            assert "Found 4 archive(s): 3 ready for extraction attempt, 1 blocked" in text
            for label in ("Discovery method=Embedded scan", "Discovery method=Archive relationship resolution",
                          "Discovery method=Format confirmation", "Discovery status=Ready for extraction attempt",
                          "Discovery status=Blocked", "Reason: Archive password is required", "Parts=2"):
                assert label in text
