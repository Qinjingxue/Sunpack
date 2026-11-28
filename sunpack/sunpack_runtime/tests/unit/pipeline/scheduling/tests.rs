use super::*;
use std::time::Duration;

fn single_slot() -> Arc<Scheduler> {
    Scheduler::with_capacity(1)
}

#[test]
fn lifecycle_gate_wakes_one_waiter_and_hands_off_after_drop() {
    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
    }
    let gate = AsyncGate::new();
    let held = block_on(gate.lock());
    let counters: [_; 3] = std::array::from_fn(|_| Arc::new(WakeCount::default()));
    let wakes = counters.clone().map(Waker::from);
    let mut first = Box::pin(gate.lock());
    let mut abandoned = Box::pin(gate.lock());
    let mut last = Box::pin(gate.lock());
    assert!(first.as_mut().poll(&mut Context::from_waker(&wakes[0])).is_pending());
    assert!(abandoned.as_mut().poll(&mut Context::from_waker(&wakes[1])).is_pending());
    assert!(last.as_mut().poll(&mut Context::from_waker(&wakes[2])).is_pending());
    drop(abandoned);
    assert_eq!(Arc::strong_count(&counters[1]), 2);

    drop(held);
    let count = |i: usize| counters[i].0.load(Ordering::Relaxed);
    assert_eq!([count(0), count(1), count(2)], [1, 0, 0]);
    drop(first);
    assert_eq!([count(0), count(1), count(2)], [1, 0, 1]);
    assert!(last.as_mut().poll(&mut Context::from_waker(&wakes[2])).is_ready());
}

#[test]
fn failed_pool_retry_keeps_parallel_stage_progress() {
    let scheduler = Scheduler::with_capacity(2);
    scheduler.fail_pool.store(1, Ordering::Relaxed);
    let cancel = Cancellation::new();
    scheduler.run(1, Origin::Foreground, &cancel, |spawner| {
        let cancel = cancel.clone();
        Box::pin(async move {
            assert!(stage("first", &cancel).await.is_err());
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let jobs: Vec<_> = (0..2).map(|_| {
                let barrier = Arc::clone(&barrier);
                let cancel = cancel.clone();
                spawner.spawn(Box::pin(async move {
                    stage("extract", &cancel).await.unwrap();
                    barrier.wait();
                }))
            }).collect();
            for job in jobs { job.wait().await; }
        })
    });
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);
}

#[test]
fn initialization_failure_settles_requests_and_allows_later_retry() {
    let scheduler = Scheduler::with_capacity(1);
    let cancel = Cancellation::new();
    scheduler.fail_driver.store(true, Ordering::Relaxed);
    assert!(scheduler.prepare_submit().is_err());
    assert!(scheduler.driver.get().is_none());
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);
    scheduler.fail_pool.store(1, Ordering::Relaxed);
    let child_cancel = cancel.clone();
    let failed = scheduler.prepare_submit().unwrap().submit(1, Origin::Watch, &cancel,
        move |_| Box::pin(async move { stage("extract", &child_cancel).await }));
    assert!(failed.join().unwrap().is_err());
    assert!(!scheduler.pool.is_retained());
    assert_eq!(scheduler.state.lock().unwrap().active, 0);
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);
    let result = scheduler.run(2, Origin::Foreground, &cancel, |_| Box::pin(async {
        stage("extract", &cancel).await
    }));
    assert!(result.is_ok());
    assert_eq!(scheduler.state.lock().unwrap().active, 0);
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);
    let fresh = Scheduler::with_capacity(1);
    fresh.fail_pool.store(1, Ordering::Relaxed);
    let result = fresh.run(3, Origin::Foreground, &cancel, |_| Box::pin(async {
        stage("extract", &cancel).await
    }));
    assert!(result.is_err());
    assert_eq!(fresh.state.lock().unwrap().pending, 0);
    assert_eq!(fresh.state.lock().unwrap().active, 0);
}

#[test]
fn concurrent_first_stage_initializes_one_shared_pool() {
    let scheduler = Scheduler::new();
    let pools = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..8).map(|_| {
            let scheduler = &scheduler;
            scope.spawn(move || scheduler.pool().unwrap())
        }).collect();
        jobs.into_iter().map(|job| job.join().unwrap()).collect::<Vec<_>>()
    });
    assert!(pools.iter().all(|pool| Arc::ptr_eq(pool, &pools[0])));
    assert_eq!(pools[0].current_num_threads(), scheduler.capacity);
}

#[test]
fn lightweight_root_does_not_initialize_stage_pool() {
    let scheduler = Scheduler::new();
    assert!(!scheduler.pool.is_retained());
    let result = scheduler.run(1, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async { 42 }));
    assert_eq!(result, 42);
    assert!(!scheduler.pool.is_retained());
    let error: Result<(), &str> = scheduler.run(2, Origin::Foreground, &Cancellation::new(),
        |_| Box::pin(async { Err("parse failure") }));
    assert_eq!(error, Err("parse failure"));
    assert!(!scheduler.pool.is_retained());
    let result = scheduler.run(2, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async {
        stage("test", &Cancellation::new()).await.unwrap(); 43
    }));
    assert_eq!(result, 43);
    assert!(scheduler.pool.is_retained());
}

#[test]
fn owned_requests_park_without_holding_host_slots() {
    let scheduler = single_slot();
    let gate = Arc::new(Mutex::new((false, Vec::<Waker>::new())));
    let (parked, arrivals) = mpsc::channel();
    let mut joins = Vec::new();
    for id in 1..=64 {
        let gate = Arc::clone(&gate);
        let parked = parked.clone();
        joins.push(scheduler.submit(id, Origin::Watch, &Cancellation::new(), |_| {
            Box::pin(async move {
                poll_fn(|cx| {
                    let mut gate = gate.lock().unwrap();
                    if gate.0 { Poll::Ready(()) } else {
                        gate.1.push(cx.waker().clone());
                        parked.send(()).unwrap();
                        Poll::Pending
                    }
                }).await;
                id
            })
        }));
    }
    for _ in 0..64 { arrivals.recv_timeout(Duration::from_secs(10)).unwrap(); }
    let foreground = scheduler.submit(65, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async { 7 }));
    assert_eq!(foreground.blocking_wait(), 7);
    let wakes = {
        let mut gate = gate.lock().unwrap();
        gate.0 = true;
        std::mem::take(&mut gate.1)
    };
    for wake in wakes { wake.wake(); }
    for (index, join) in joins.into_iter().enumerate() {
        assert_eq!(join.blocking_wait(), index as u64 + 1);
    }
}

#[test]
fn owned_control_wake_progresses_while_only_stage_slot_is_blocked() {
    let scheduler = single_slot();
    let (blocked, blocked_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let (waiting, waiting_rx) = mpsc::channel();
    let (progress, progress_rx) = mpsc::channel();
    let gate = Arc::new(Mutex::new((false, None::<Waker>)));
    let signal = Arc::clone(&gate);
    let join = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |spawner| Box::pin(async move {
        let slow = spawner.spawn(Box::pin(async move {
            stage("scan", &Cancellation::new()).await.unwrap();
            blocked.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        let ready = spawner.spawn(Box::pin(async move {
            poll_fn(|cx| {
                let mut gate = gate.lock().unwrap();
                if gate.0 { Poll::Ready(()) } else {
                    if gate.1.is_none() { waiting.send(()).unwrap(); }
                    gate.1 = Some(cx.waker().clone());
                    Poll::Pending
                }
            }).await;
            progress.send(()).unwrap();
        }));
        slow.wait().await;
        ready.wait().await;
    }));
    blocked_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let wake = {
        let mut gate = signal.lock().unwrap();
        gate.0 = true;
        gate.1.take().unwrap()
    };
    // Coalescing repeated wakes must neither poll concurrently nor lose the wake.
    for _ in 0..100 { wake.wake_by_ref(); }
    let independent = progress_rx.recv_timeout(Duration::from_secs(10));
    release.send(()).unwrap();
    join.blocking_wait();
    independent.expect("a scoped poll wave blocked its independently woken sibling");
}

#[test]
fn cancelled_queued_stage_settles_without_waiting_for_busy_stage() {
    let scheduler = single_slot();
    let (entered, entered_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let active = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |_| Box::pin(async move {
        stage("scan", &Cancellation::new()).await.unwrap();
        entered.send(()).unwrap();
        release_rx.recv().unwrap();
    }));
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let cancel = Cancellation::new();
    let token = cancel.clone();
    let (settled, settled_rx) = mpsc::channel();
    let pending = scheduler.submit(2, Origin::Watch, &cancel, |_| Box::pin(async move {
        let cancelled = stage("cleanup", &token).await.is_err();
        settled.send(cancelled).unwrap();
    }));
    // The shared driver's FIFO Start handling has admitted request 2 before
    // this control-only request completes, despite the occupied worker.
    scheduler.submit(3, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async {})).blocking_wait();
    assert_eq!(scheduler.state.lock().unwrap().pending, 2);
    cancel.cancel();
    let result = settled_rx.recv_timeout(Duration::from_secs(10));
    release.send(()).unwrap();
    active.blocking_wait();
    pending.blocking_wait();
    assert_eq!(result.unwrap(), true);
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);
}

#[test]
fn owned_panic_cancels_and_joins_other_request_writers() {
    let scheduler = single_slot();
    let cancel = Cancellation::new();
    let observed = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&observed);
    let token = cancel.clone();
    let join = scheduler.submit(1, Origin::Watch, &cancel, |spawner| Box::pin(async move {
        let child = spawner.spawn(Box::pin(async move {
            let mut subscription = None;
            poll_fn(|cx| {
                if token.cancelled() { return Poll::Ready(()); }
                let wake = cx.waker().clone();
                subscription = token.subscribe(move || wake.wake_by_ref());
                if token.cancelled() { Poll::Ready(()) } else { Poll::Pending }
            }).await;
            drop(subscription);
            stage("cancel_cleanup", &Cancellation::new()).await.unwrap();
            Cancellation::check_current_io().expect("cleanup must use its own uncancelled native scope");
            finished.store(true, Ordering::Release);
        }));
        let failed = spawner.spawn(Box::pin(async { panic!("owned task panic"); }));
        failed.wait().await;
        child.wait().await;
    }));
    let (notified, notification) = mpsc::channel();
    let at_completion = Arc::clone(&observed);
    join.on_ready(move || notified.send(at_completion.load(Ordering::Acquire)).unwrap());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join.blocking_wait())).is_err());
    assert!(cancel.cancelled());
    assert!(observed.load(Ordering::Acquire), "root completed before its writer settled");
    assert!(notification.recv_timeout(Duration::from_secs(10)).unwrap(),
        "done callback overtook a child writer's cleanup");
}

#[test]
fn parked_watch_releases_the_only_host_slot_until_its_event_arrives() {
    // No elapsed-time assumption: an external event is withheld until the
    // foreground poll has completed on the only host slot.
    let scheduler = single_slot();
    let (parked, parked_rx) = mpsc::sync_channel(1);
    let event = Arc::new(Mutex::new((false, None::<Waker>)));
    let signal = Arc::clone(&event);
    let watch = Arc::clone(&scheduler);
    let watch = std::thread::spawn(move || {
        watch.run(1, Origin::Watch, &Cancellation::new(), |spawner| {
            Box::pin(async move {
                spawner
                    .spawn(Box::pin(poll_fn(move |cx| {
                        let mut event = event.lock().unwrap();
                        if event.0 {
                            Poll::Ready(42)
                        } else {
                            if event.1.is_none() {
                                parked.send(()).unwrap();
                            }
                            event.1 = Some(cx.waker().clone());
                            Poll::Pending
                        }
                    })))
                    .wait()
                    .await
            })
        })
    });
    parked_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let (finished, finished_rx) = mpsc::sync_channel(1);
    let foreground = std::thread::spawn(move || {
        scheduler.run(2, Origin::Foreground, &Cancellation::new(), |_| {
            Box::pin(async move {
                finished.send(()).unwrap();
            })
        });
    });
    let independent = finished_rx.recv_timeout(Duration::from_secs(10));
    {
        let mut event = signal.lock().unwrap();
        event.0 = true;
        event.1.take().unwrap().wake();
    }
    assert_eq!(watch.join().unwrap(), 42);
    foreground.join().unwrap();
    independent.expect("foreground needed a host slot held by suspended Watch work");
}

#[test]
fn bounded_consumers_drain_past_slow_items_and_recurse_inline() {
    // Two consumers, more items than permits: item zero cannot finish
    // until a later item runs. Nested work must not await another permit.
    let scheduler = single_slot();
    let results = scheduler.run(1, Origin::Foreground, &Cancellation::new(), |spawner| {
        Box::pin(async move {
            spawner.consumers.store(2, Ordering::Release);
            let gate = Arc::new(Mutex::new((false, None::<Waker>)));
            let children = spawner.clone();
            let results = spawner.bounded_map(0..8, move |item| {
                let gate = Arc::clone(&gate);
                let children = children.clone();
                Box::pin(async move {
                    assert_eq!(children.consumers.load(Ordering::Acquire), 0);
                    if item == 0 {
                        poll_fn(|cx| {
                            let mut gate = gate.lock().unwrap();
                            if gate.0 { Poll::Ready(()) } else {
                                gate.1 = Some(cx.waker().clone());
                                Poll::Pending
                            }
                        }).await;
                    } else if item == 1 {
                        let nested = children.bounded_map(10..12, |value| {
                            Box::pin(async move { value })
                        }).await;
                        assert_eq!(nested, [10, 11]);
                    } else if item == 2 {
                        let mut gate = gate.lock().unwrap();
                        gate.0 = true;
                        if let Some(waker) = gate.1.take() { waker.wake(); }
                    }
                    item
                })
            }).await;
            assert_eq!(spawner.consumers.load(Ordering::Acquire), 2);
            results
        })
    });
    assert_eq!(results, (0..8).collect::<Vec<_>>());
}

#[test]
fn cancelled_batches_stop_the_tail_and_join_started_consumers() {
    for capacity in [0, 2] {
        let scheduler = single_slot();
        let cancel = Cancellation::new();
        let token = cancel.clone();
        let results = scheduler.run(1, Origin::Foreground, &cancel, |spawner| {
            Box::pin(async move {
                spawner.consumers.store(capacity, Ordering::Release);
                let gate = Arc::new(Mutex::new((false, None::<Waker>)));
                let results = spawner.bounded_map(0..100, move |item| {
                    let gate = Arc::clone(&gate);
                    let token = token.clone();
                    Box::pin(async move {
                        if capacity == 2 && item == 0 {
                            poll_fn(|cx| {
                                let mut gate = gate.lock().unwrap();
                                if gate.0 { Poll::Ready(()) } else {
                                    gate.1 = Some(cx.waker().clone()); Poll::Pending
                                }
                            }).await;
                        } else {
                            token.cancel();
                            let mut gate = gate.lock().unwrap();
                            gate.0 = true;
                            if let Some(waker) = gate.1.take() { waker.wake(); }
                        }
                        item
                    })
                }).await;
                assert_eq!(spawner.consumers.load(Ordering::Acquire), capacity);
                results
            })
        });
        assert_eq!(results, if capacity == 0 { vec![0] } else { vec![0, 1] });
    }
}

#[test]
fn control_self_wakes_do_not_starve_new_requests() {
    let scheduler = single_slot();
    let released = Arc::new(AtomicBool::new(false));
    let gate = Arc::clone(&released);
    let (started, started_rx) = mpsc::channel();
    let busy = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |_| Box::pin(async move {
        let mut started = Some(started);
        poll_fn(|cx| {
            if let Some(started) = started.take() { started.send(()).unwrap(); }
            if gate.load(Ordering::Acquire) { Poll::Ready(()) }
            else { cx.waker().wake_by_ref(); Poll::Pending }
        }).await
    }));
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let (finished, finished_rx) = mpsc::channel();
    let other = scheduler.submit(2, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
        finished.send(()).unwrap();
    }));
    let result = finished_rx.recv_timeout(Duration::from_secs(10));
    released.store(true, Ordering::Release);
    busy.blocking_wait();
    other.blocking_wait();
    result.expect("a self-waking control task monopolized the shared driver");
}

#[test]
fn stage_pool_keeps_main_minimum_capacity_and_nested_rayon_progress() {
    let small_host = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let scheduler = small_host.install(|| Scheduler::with_capacity(4));
    assert_eq!(scheduler.pool().unwrap().current_num_threads(), 4);
    let (entered, entered_rx) = mpsc::channel();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let held = Arc::clone(&gate);
    let request = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |spawner| Box::pin(async move {
        spawner.bounded_map(0..4, move |index| {
            let gate = Arc::clone(&held);
            let entered = entered.clone();
            Box::pin(async move {
                stage("scan", &Cancellation::new()).await.unwrap();
                entered.send(()).unwrap();
                drop(gate.1.wait_while(gate.0.lock().unwrap(), |ready| !*ready).unwrap());
                let (a, b) = rayon::join(|| index + 1, || index + 2);
                a + b
            })
        }).await
    }));
    let progress = (0..4).try_for_each(|_| entered_rx.recv_timeout(Duration::from_secs(10)));
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert_eq!(request.blocking_wait(), vec![3, 5, 7, 9]);
    progress.expect("stage executor inherited a smaller unrelated Rayon pool");
}

#[test]
fn global_stage_budget_releases_cancelled_admission_to_oldest_waiter() {
    let scheduler = single_slot();
    let (tx, rx) = mpsc::channel();
    let signals = Signals { tx, driver: None };
    let first = scheduler.acquire_or_queue(1, Origin::Watch, 0, &signals, "scan").unwrap();
    for id in 1..=MAX_PENDING_JOBS {
        assert!(scheduler.acquire_or_queue(1, Origin::Watch, id, &signals, "scan").is_none());
    }
    {
        let state = scheduler.state.lock().unwrap();
        assert_eq!(state.pending, MAX_PENDING_JOBS);
        assert_eq!(state.waiting.len(), 1);
        assert_eq!(state.sequence, MAX_PENDING_JOBS as u64);
    }
    assert!(scheduler.withdraw(1, 1));
    {
        let state = scheduler.state.lock().unwrap();
        assert_eq!(state.pending, MAX_PENDING_JOBS);
        assert!(state.waiting.is_empty());
        assert_eq!(state.sequence, MAX_PENDING_JOBS as u64 + 1);
    }
    drop(first);
    for _ in 1..MAX_PENDING_JOBS {
        let Signal::Granted(id, slot) = rx.recv().unwrap() else { panic!("grant") };
        assert_ne!(id, 1);
        drop(slot);
    }
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);
    assert!(rx.try_recv().is_err());
}

#[test]
fn stage_priority_aging_and_handshake_capacity_match_main() {
    let scheduler = Scheduler::with_capacity(2);
    let (tx, rx) = mpsc::channel();
    let signals = Signals { tx, driver: None };
    scheduler.configure_capacity(100);
    assert_eq!(scheduler.state.lock().unwrap().limit, Some(2));
    let first = scheduler.acquire_or_queue(1, Origin::Watch, 0, &signals, "scan").unwrap();
    let second = scheduler.acquire_or_queue(1, Origin::Watch, 1, &signals, "scan").unwrap();
    scheduler.configure_capacity(1);
    assert!(scheduler.acquire_or_queue(1, Origin::Watch, 2, &signals, "background_scan").is_none());
    assert!(scheduler.acquire_or_queue(1, Origin::Watch, 3, &signals, "cleanup").is_none());
    drop(first);
    assert!(rx.try_recv().is_err(), "lowered capacity must wait for executing work");
    drop(second);
    let Signal::Granted(id, slot) = rx.recv().unwrap() else { panic!("grant") };
    assert_eq!(id, 3);
    drop(slot);
    let Signal::Granted(id, slot) = rx.recv().unwrap() else { panic!("grant") };
    assert_eq!(id, 2);
    drop(slot);
    assert_eq!(scheduler.state.lock().unwrap().pending, 0);

    // main selects six FIFO bucket heads by priority + sequence_age / 32,
    // breaking ties toward the oldest job, rather than permanently starving background work.
    let mut queue = StageQueue::default();
    queue.push(Grant { id: 10, tx: signals.clone(), priority: stage_priority("background"), sequence: 1 });
    queue.push(Grant { id: 11, tx: signals, priority: stage_priority("cleanup"), sequence: 1601 });
    assert_eq!(queue.pop(1601).id, 10);
    assert_eq!(queue.pop(1601).id, 11);
}

#[test]
fn ready_batches_drain_in_order_after_foreground_work() {
    let scheduler = single_slot();
    let (tx, rx) = mpsc::channel();
    let signals = Signals { tx, driver: None };
    let first = scheduler.acquire_or_queue(0, Origin::Watch, 0, &signals, "scan").unwrap();
    for (request, origin, index) in [
        (1, Origin::Watch, 1),
        (1, Origin::Watch, 2),
        (2, Origin::Watch, 3),
        (3, Origin::Foreground, 4),
    ] {
        assert!(scheduler.acquire_or_queue(request, origin, index, &signals, "scan").is_none());
    }
    drop(first);
    let mut order = Vec::new();
    while let Ok(Signal::Granted(id, slot)) = rx.try_recv() {
        order.push(id);
        drop(slot);
    }
    assert_eq!(order, [4, 1, 2, 3]);
}
