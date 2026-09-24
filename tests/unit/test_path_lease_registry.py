import asyncio

from sunpack.pipeline.coordinator.engine import _PathLeaseRegistry


def test_conflicting_path_lease_is_woken_by_release(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        path = tmp_path / "shared.zip"
        await registry.acquire("first", (path,))

        waiting = asyncio.create_task(registry.acquire("second", (path,)))
        await asyncio.sleep(0)
        assert not waiting.done()

        await registry.release("first")
        await asyncio.wait_for(waiting, timeout=0.1)
        assert registry._owned == {"second": {str(path)}}

    asyncio.run(scenario())


def test_replacing_path_lease_notifies_waiters_for_released_paths(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_path = tmp_path / "first.zip"
        second_path = tmp_path / "second.zip"
        await registry.acquire("first", (first_path,))

        waiting = asyncio.create_task(registry.acquire("second", (first_path,)))
        await asyncio.sleep(0)
        assert not waiting.done()

        await registry.replace("first", (second_path,))
        await asyncio.wait_for(waiting, timeout=0.1)
        assert registry._owned == {
            "first": {str(second_path)},
            "second": {str(first_path)},
        }

    asyncio.run(scenario())


def test_resolved_family_replace_cannot_deadlock_on_partial_owners(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_part = tmp_path / "archive.7z.001"
        second_part = tmp_path / "archive.7z.002"
        family = (first_part, second_part)

        # Model the old Watch behaviour: each request owns one member before
        # discovery expands both requests to the same physical family.
        await registry.acquire("first", (first_part,))
        await registry.acquire("second", (second_part,))

        first = asyncio.create_task(registry.replace("first", family))
        second = asyncio.create_task(registry.replace("second", family))
        await asyncio.sleep(0)

        done = [task for task in (first, second) if task.done()]
        assert len(done) == 1

        winner = "first" if first.done() else "second"
        loser = second if first.done() else first
        await registry.release(winner)
        await asyncio.wait_for(loser, timeout=0.1)

        assert registry._owned in (
            {"first": {str(first_part), str(second_part)}},
            {"second": {str(first_part), str(second_part)}},
        )

    asyncio.run(scenario())


def test_watch_can_coalesce_exact_resolved_family_without_waiting(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_part = tmp_path / "archive.7z.001"
        second_part = tmp_path / "archive.7z.002"
        family = (first_part, second_part)
        first_part.write_bytes(b"first")
        second_part.write_bytes(b"second")

        assert await registry.replace("first", family, coalesce_exact=True) is None
        owner = await asyncio.wait_for(
            registry.replace("second", family, coalesce_exact=True),
            timeout=0.1,
        )

        assert owner == "first"
        assert registry._owned == {
            "first": {str(first_part), str(second_part)},
        }

    asyncio.run(scenario())



def test_watch_does_not_coalesce_newer_resolved_family_version(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_part = tmp_path / "archive.7z.001"
        second_part = tmp_path / "archive.7z.002"
        family = (first_part, second_part)
        first_part.write_bytes(b"first")
        second_part.write_bytes(b"second")

        assert await registry.replace("first", family, coalesce_exact=True) is None

        # Same physical family, newer bytes. The later Watch request must not
        # inherit the result produced for the previous version.
        second_part.write_bytes(b"second-new-version")
        waiting = asyncio.create_task(
            registry.replace("second", family, coalesce_exact=True)
        )
        await asyncio.sleep(0)
        assert not waiting.done()

        await registry.release("first")
        owner = await asyncio.wait_for(waiting, timeout=0.1)

        assert owner is None
        assert registry._owned == {
            "second": {str(first_part), str(second_part)},
        }

    asyncio.run(scenario())

def test_completed_watch_generation_reuses_only_the_exact_unchanged_family(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_part = tmp_path / "archive.7z.001"
        second_part = tmp_path / "archive.7z.002"
        output = tmp_path / "out" / "archive"
        output.mkdir(parents=True)
        first_part.write_bytes(b"first")
        second_part.write_bytes(b"second")
        family = (first_part, second_part)

        assert await registry.replace("first", family, coalesce_exact=True) is None
        version = registry.ownership_version_for("first", family)
        assert version
        registry.remember_completed_watch(version, str(output))
        assert registry.completed_watch_output(version) == str(output)

        await registry.release("first")
        second_part.write_bytes(b"second-new-version")
        assert await registry.replace("second", family, coalesce_exact=True) is None
        newer = registry.ownership_version_for("second", family)
        assert newer and newer != version
        assert registry.completed_watch_output(newer) == ""

    asyncio.run(scenario())


def test_completed_watch_generation_is_not_reused_after_output_disappears(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_part = tmp_path / "archive.zip.001"
        second_part = tmp_path / "archive.zip.002"
        output = tmp_path / "out" / "archive"
        output.mkdir(parents=True)
        first_part.write_bytes(b"first")
        second_part.write_bytes(b"second")
        family = (first_part, second_part)

        assert await registry.replace("first", family, coalesce_exact=True) is None
        version = registry.ownership_version_for("first", family)
        registry.remember_completed_watch(version, str(output))
        output.rmdir()

        assert registry.completed_watch_output(version) == ""

    asyncio.run(scenario())

