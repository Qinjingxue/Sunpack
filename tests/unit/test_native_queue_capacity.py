from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeQueueCapacity


def test_rejected_job_waits_for_an_admitted_job_to_finish():
    capacity = _NativeQueueCapacity()
    resubmitted = []

    capacity.park("rejected", lambda: resubmitted.append("rejected"), other_jobs_active=True)
    # The rejected job's own job_finished frees no queue slot.
    capacity.release("rejected")
    assert resubmitted == []

    capacity.release("admitted")
    assert resubmitted == ["rejected"]


def test_each_freed_slot_resubmits_one_parked_job_in_order():
    capacity = _NativeQueueCapacity()
    resubmitted = []
    for job_id in ("first", "second"):
        capacity.park(job_id, lambda job_id=job_id: resubmitted.append(job_id), other_jobs_active=True)
        capacity.release(job_id)

    capacity.release("admitted-a")
    assert resubmitted == ["first"]
    capacity.release("admitted-b")
    assert resubmitted == ["first", "second"]
    capacity.release("admitted-c")
    assert resubmitted == ["first", "second"]


def test_rejected_job_resubmits_immediately_when_nothing_else_can_finish():
    capacity = _NativeQueueCapacity()
    resubmitted = []

    capacity.park("rejected", lambda: resubmitted.append("rejected"), other_jobs_active=False)

    assert resubmitted == ["rejected"]
    # The later job_finished of the rejection itself must not wake anyone.
    capacity.park("other", lambda: resubmitted.append("other"), other_jobs_active=True)
    capacity.release("rejected")
    assert resubmitted == ["rejected"]


def test_worker_exit_flushes_parked_jobs_so_they_fail_instead_of_hanging():
    capacity = _NativeQueueCapacity()
    resubmitted = []
    capacity.park("a", lambda: resubmitted.append("a"), other_jobs_active=True)
    capacity.park("b", lambda: resubmitted.append("b"), other_jobs_active=True)

    capacity.flush()

    assert resubmitted == ["a", "b"]
    capacity.release("admitted")
    assert resubmitted == ["a", "b"]
