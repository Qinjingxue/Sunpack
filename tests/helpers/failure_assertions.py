from sunpack.core.contracts.failures import FailureKind


def assert_failure_kind(failures, expected: FailureKind | tuple[FailureKind, ...]) -> None:
    """Require every reported cause to be expected, including wrappers."""
    expected_kinds = {expected} if isinstance(expected, FailureKind) else set(expected)
    assert failures, f"expected {expected_kinds}, got no failures"
    for failure in failures:
        allowed = expected_kinds | {FailureKind.INPUTS_FAILED} if failure.causes else expected_kinds
        assert failure.kind in allowed, failure.to_dict()
        if failure.causes:
            assert_failure_kind(failure.causes, expected)
