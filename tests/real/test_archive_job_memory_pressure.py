"""Exercise competing decoder commitments through a capped Windows process tree."""

import random
import shutil
from pathlib import Path

import psutil
import pytest

from tests.helpers.native_fixture import file_inventory
from tests.helpers.package import Package
from tests.helpers.real_archives import create_7z_archive
from tests.helpers.windows_job import WindowsJob
from tests.real.archive_boundary import extract_report
from tests.real.plan7_watch_downloads.plan7_support import watch_setup


MIB = 1024 * 1024
# One 32 MiB decoder and ordinary process overhead fit. A second decoder plus
# the launcher, runtime and worker will contend for the same commit budget.
JOB_LIMIT = 72 * MIB


class _CappedPackage(Package):
    def __init__(self, package, job):
        super().__init__(package.launcher, package.data, package.tools, package.env)
        self.job = job

    def run(self, *arguments, cwd=None, input=None, timeout=60):
        assert input is None
        return self.job.run([self.launcher, *arguments], cwd=cwd or self.data,
                            env=self.env, timeout=timeout)


@pytest.fixture(scope="module")
def decoder_archives(tmp_path_factory):
    root = tmp_path_factory.mktemp("decoder-archives")
    archives = root / "archives"
    archives.mkdir()
    expected = {}
    for index in range(3):
        source = root / f"source-{index}"
        source.mkdir()
        name = f"payload-{index}.dat"
        block = random.Random(index).randbytes(MIB)
        with (source / name).open("wb") as payload:
            for _ in range(40):
                payload.write(block)
        archive = archives / f"decoder-{index}.7z"
        create_7z_archive(source, archive, compression_method="LZMA2:d=32m:fb=16:mf=hc4",
                          compression_level=1)
        expected[name] = file_inventory(source)[name]
        shutil.rmtree(source)
    return archives, expected


def _assert_runtime_in_job(package, job):
    state, = package.data.glob("runtime-*.state")
    owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
    assert job.contains(owner.pid), owner
    return owner


def _assert_workers_in_job(owner, job):
    workers = [child for child in owner.children() if child.name() == "sunpack_sevenzip_worker.exe"]
    assert workers and all(job.contains(worker.pid) for worker in workers), workers


def _shutdown(package, owner):
    result = package.run("--persistent-shutdown")
    assert result.returncode == 0, (result.stdout, result.stderr)
    owner.wait(timeout=30)


def _assert_output(output, expected):
    inventory = file_inventory(output)
    actual = {Path(path).name: details for path, details in inventory.items()}
    assert len(inventory) == len(expected) and actual == expected, (inventory, expected)


def test_cli_extracts_concurrent_decoders_with_capped_commit(package, tmp_path, decoder_archives):
    source, expected = decoder_archives
    output = tmp_path / "output"
    with WindowsJob(JOB_LIMIT) as job:
        capped = _CappedPackage(package, job)
        report = extract_report(capped, source, output)
        assert report["summary"]["success_count"] == len(expected), report
        owner = _assert_runtime_in_job(capped, job)
        _assert_workers_in_job(owner, job)
        _assert_output(output, expected)
        _shutdown(capped, owner)


@pytest.mark.requires_watch_broker
def test_watch_extracts_concurrent_decoders_with_capped_commit(package, tmp_path, decoder_archives):
    source, expected = decoder_archives
    with WindowsJob(JOB_LIMIT) as job:
        capped = _CappedPackage(package, job)
        watch = watch_setup(capped, tmp_path, passwords=(), start=False)
        for archive in source.iterdir():
            shutil.copyfile(archive, watch.root / archive.name)
        with capped.watch_session():
            owner = _assert_runtime_in_job(capped, job)
            for archive in source.iterdir():
                capped.await_watch_event("done", path=archive.name)
            _assert_workers_in_job(owner, job)
            watch.assert_no_terminal_failures()
            _assert_output(watch.output, expected)
        _shutdown(capped, owner)
