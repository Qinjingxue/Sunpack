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



def test_directory_lease_blocks_descendants_and_descendant_blocks_parent(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        root = tmp_path / "tree"
        root.mkdir()
        child = root / "archive.zip"
        child.write_bytes(b"payload")

        await registry.acquire("directory", (root,))
        waiting_child = asyncio.create_task(registry.acquire("child", (child,)))
        await asyncio.sleep(0)
        assert not waiting_child.done()

        await registry.release("directory")
        await asyncio.wait_for(waiting_child, timeout=0.1)
        await registry.release("child")

        await registry.acquire("child", (child,))
        waiting_directory = asyncio.create_task(registry.acquire("directory", (root,)))
        await asyncio.sleep(0)
        assert not waiting_directory.done()

        await registry.release("child")
        await asyncio.wait_for(waiting_directory, timeout=0.1)
        assert registry._owned == {"directory": {str(root)}}

    asyncio.run(scenario())


def test_release_only_wakes_waiters_blocked_by_that_owner(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        first_path = tmp_path / "first.zip"
        second_path = tmp_path / "second.zip"
        first_path.write_bytes(b"first")
        second_path.write_bytes(b"second")
        await registry.acquire("hold-first", (first_path,))
        await registry.acquire("hold-second", (second_path,))

        checks = []
        original = registry._blocking_owners

        def counted(owner, candidates):
            checks.append(owner)
            return original(owner, candidates)

        registry._blocking_owners = counted
        waiting_first = asyncio.create_task(registry.acquire("wait-first", (first_path,)))
        waiting_second = asyncio.create_task(registry.acquire("wait-second", (second_path,)))
        await asyncio.sleep(0)
        assert set(registry._waiters_by_blocker) == {"hold-first", "hold-second"}

        checks.clear()
        await registry.release("hold-first")
        await asyncio.wait_for(waiting_first, timeout=0.1)
        await asyncio.sleep(0)

        assert "wait-first" in checks
        assert "wait-second" not in checks
        assert not waiting_second.done()

        waiting_second.cancel()
        try:
            await waiting_second
        except asyncio.CancelledError:
            pass
        assert "hold-second" not in registry._waiters_by_blocker
        assert not registry._waiter_blockers

    asyncio.run(scenario())


def test_release_clears_path_lease_indexes(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        root = tmp_path / "tree"
        root.mkdir()
        child = root / "part.001"
        child.write_bytes(b"payload")

        await registry.acquire("owner", (root, child))
        assert registry._exact_owners
        assert registry._directory_owners
        assert registry._prefix_owners

        await registry.release("owner")

        assert not registry._owned
        assert not registry._lease_paths
        assert not registry._exact_owners
        assert not registry._entries_by_key
        assert not registry._directory_owners
        assert not registry._prefix_owners

    asyncio.run(scenario())


def test_reacquiring_owned_path_reuses_snapshotted_path_facts(tmp_path):
    async def scenario() -> None:
        registry = _PathLeaseRegistry()
        path = tmp_path / "archive.zip"
        path.write_bytes(b"payload")

        await registry.acquire("owner", (path,))
        first = next(iter(registry._lease_paths["owner"].values()))
        await registry.acquire("owner", (path,))
        second = next(iter(registry._lease_paths["owner"].values()))

        assert second is first
        assert registry._owned == {"owner": {str(path)}}

    asyncio.run(scenario())
