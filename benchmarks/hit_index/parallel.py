"""Bounded process orchestration; native children retain their own worker counts."""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from itertools import islice


DEFAULT_PARALLEL_JOBS = 16


def run_jobs(function, jobs, *, parallel_jobs: int = DEFAULT_PARALLEL_JOBS):
    """Yield completed results without queuing the entire evaluation matrix."""
    if parallel_jobs < 1:
        raise ValueError("parallel_jobs must be positive")
    if parallel_jobs == 1:
        for job in jobs:
            yield function(job)
        return
    iterator = iter(jobs)
    with ThreadPoolExecutor(max_workers=parallel_jobs, thread_name_prefix="hit-index") as pool:
        pending = {pool.submit(function, job) for job in islice(iterator, parallel_jobs)}
        while pending:
            completed, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in completed:
                result = future.result()
                try:
                    job = next(iterator)
                except StopIteration:
                    pass
                else:
                    pending.add(pool.submit(function, job))
                yield result
