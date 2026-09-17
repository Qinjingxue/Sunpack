from sunpack.config.fields.coordinator import normalize_recursive_extract
from sunpack.coordinator.recursion import RecursionController


def test_unbounded_recursion_modes_do_not_store_or_apply_round_limit():
    assert normalize_recursive_extract("*") == {"mode": "infinite"}
    assert normalize_recursive_extract("?") == {"mode": "prompt"}

    for mode in ("infinite", "prompt"):
        controller = RecursionController(mode)
        assert controller.max_rounds is None
        for round_index in (999, 1000, 1_000_000):
            assert controller.should_continue(round_index, True)
        assert not controller.should_continue(1_000_000, False)


def test_fixed_recursion_keeps_explicit_round_limit():
    assert normalize_recursive_extract("3") == {"mode": "fixed", "max_rounds": 3}

    controller = RecursionController("fixed", 3)
    assert controller.max_rounds == 3
    assert controller.should_continue(1, True)
    assert controller.should_continue(2, True)
    assert not controller.should_continue(3, True)
