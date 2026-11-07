from collections.abc import Sequence
from unittest.mock import patch

from sunpack.core.contracts.failure_report import FailureReportPayloads
from sunpack.core.contracts.failures import FailureInfo, FailureKind


def test_failure_report_views_preserve_wire_fields_without_copying_diagnostics():
    # Existing report tests use dictionaries: only this catches a lazy view that
    # silently drops/renames FailureInfo fields or copies diagnostic dictionaries.
    cause = FailureInfo(FailureKind.DAMAGED, "extract", "broken", details={"offset": 7})
    failure = FailureInfo(
        FailureKind.INPUTS_FAILED, "batch", "failed", "failure.inputs_failed",
        {"count": 1}, "Retry", (cause,), {"path": "carrier.fake"},
    )
    source = [failure, cause]
    view = FailureReportPayloads(source)
    assert view == [item.to_dict() for item in source]
    assert view[::-1] == [cause.to_dict(), failure.to_dict()]
    assert view[0]["message"] is failure.message
    assert view[0]["message_params"] is failure.message_params
    assert view[0]["details"] is failure.details
    assert view[0]["causes"][0]["details"] is cause.details
    try:
        view[0]["message"] = "changed"
    except TypeError:
        pass
    else:
        raise AssertionError("Failure payload must be read-only")
    try:
        view[0]["not_a_field"]
    except KeyError:
        pass
    else:
        raise AssertionError("Unknown fields must fail")


def test_failure_report_views_do_not_visit_wide_or_deep_failures_eagerly():
    # Serialization equality cannot detect eager copies or Python recursion on
    # deep input. A guarded virtual source makes either regression fail cheaply.
    failure = FailureInfo(FailureKind.DAMAGED, "extract", "错" * 100_000)
    for _ in range(2000):
        failure = FailureInfo(FailureKind.INPUTS_FAILED, "nested", "failed", causes=(failure,))

    class Failures(Sequence):
        def __len__(self):
            return 1_000_000

        def __getitem__(self, index):
            assert index == 0, "Only the requested failure should be accessed"
            return failure

    with patch.object(FailureInfo, "to_dict", side_effect=AssertionError("Do not materialize")):
        view = FailureReportPayloads(Failures())
        assert len(view) == 1_000_000
        assert len(view[:100_000]) == 100_000
        payload = view[0]
        for _ in range(2000):
            payload = payload["causes"][0]
        assert payload["message"] == "错" * 100_000
