import asyncio
import io
from types import SimpleNamespace

from sunpack.core.config.fields.coordinator import normalize_recursive_extract
from sunpack.pipeline.coordinator.engine import _RequestRuntime
from sunpack.pipeline.coordinator.recursion import RecursionController


def test_unbounded_recursion_modes_do_not_store_or_apply_depth_limit():
    assert normalize_recursive_extract("*") == {"mode": "infinite"}
    assert normalize_recursive_extract("?") == {"mode": "prompt"}

    for mode in ("infinite", "prompt"):
        controller = RecursionController(mode)
        assert controller.max_depth is None
        for depth in (999, 1000, 1_000_000):
            assert controller.allows_children(depth)


def test_fixed_recursion_keeps_explicit_depth_limit():
    assert normalize_recursive_extract("3") == {"mode": "fixed", "max_rounds": 3}

    controller = RecursionController("fixed", 3)
    assert controller.max_depth == 3
    assert controller.allows_children(1)
    assert controller.allows_children(2)
    assert not controller.allows_children(3)


def test_prompt_recursion_uses_request_local_async_input():
    prompts = []
    output = io.StringIO()

    async def readline(prompt):
        prompts.append(prompt)
        return "yes\n"

    runtime = object.__new__(_RequestRuntime)
    runtime.recursion = RecursionController("prompt")
    runtime.submission = SimpleNamespace(input_reader=readline, stdout=output)
    runtime._prompt_gates = {}

    assert asyncio.run(runtime._allow_recursive_depth(2)) is True
    assert len(prompts) == 1
    assert "1" in prompts[0]


def test_prompt_recursion_without_request_input_stops_cleanly():
    output = io.StringIO()
    controller = RecursionController("prompt")

    assert asyncio.run(
        controller.prompt_continue(1, readline=None, stdout=output)
    ) is False
    assert output.getvalue()
