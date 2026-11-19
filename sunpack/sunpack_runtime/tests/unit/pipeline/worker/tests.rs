use super::super::{scheduling::Scheduler, Origin};
use super::*;
use std::future::Future;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn native_worker_accepts_chunked_request_then_an_ordinary_request() {
    let executable = crate::test_support::built_worker().unwrap();
    let config = WorkerConfig { space_poll_interval_ms: None, space_status_report_interval_ms: None };
    let process = Process::start(&executable, &config, ProcessMode::Normal).unwrap();
    let cancellation = Cancellation::new();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(b"chunked worker request").unwrap();
    let path = crate::test_support::temp_file("chunked_worker_request", &gzip.finish().unwrap());
    let archive = Arc::new(ArchiveInput::file(
        path.to_string_lossy().into_owned(), "gzip".into(), "item.gz".into(),
    ));
    let result = super::super::scheduling::block_on(async {
        process.ready(&cancellation).await?;
        let candidate: Arc<str> = Arc::from("candidate".repeat(96));
        for count in [1400, 1] {
            let request = WorkerRequest {
                job_id: count.to_string(),
                operation: "scan",
                origin: "foreground",
                output_dir: String::new(),
                output_volume_key: String::new(),
                archive_input: Arc::clone(&archive),
                password_candidates: Arc::new(vec![Arc::clone(&candidate); count]),
                layout_passwords: Default::default(),
                password: None,
                password_verified: false,
                encrypted: None,
                codepage: None,
                report_progress: false,
                output_inventory: false,
            };
            assert_eq!(small_request(&request)?.is_some(), count == 1);
            let result = process.submit(request, &cancellation, WorkerUpdates::None, |_| {}).await?;
            assert_eq!(result.summary["status"], "ok", "{}", result.summary);
            assert_eq!(result.summary["archive_type"], "gzip");
        }
        Ok::<_, io::Error>(())
    });
    drop(process);
    std::fs::remove_file(path).unwrap();
    result.unwrap();
}

#[test]
fn native_extraction_requests_inventory_rows_only_for_recursion() {
    let executable = crate::test_support::built_worker().unwrap();
    let config = WorkerConfig { space_poll_interval_ms: None, space_status_report_interval_ms: None };
    let process = Process::start(&executable, &config, ProcessMode::Normal).unwrap();
    let cancellation = Cancellation::new();
    let content = b"output inventory prefix";
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(content).unwrap();
    let path = crate::test_support::temp_file("worker_inventory", &gzip.finish().unwrap());
    let archive = Arc::new(ArchiveInput::file(
        path.to_string_lossy().into_owned(), "gzip".into(), "item.gz".into(),
    ));
    let result = super::super::scheduling::block_on(async {
        process.ready(&cancellation).await?;
        for output_inventory in [false, true] {
            let output = path.with_extension(if output_inventory { "recursive" } else { "leaf" });
            let output_dir = output.to_string_lossy().into_owned();
            let request = WorkerRequest {
                job_id: output_inventory.to_string(),
                operation: "extract",
                origin: "foreground",
                output_dir: output_dir.clone(),
                output_volume_key: String::new(),
                archive_input: Arc::clone(&archive),
                password_candidates: Arc::default(),
                layout_passwords: Default::default(),
                password: None,
                password_verified: false,
                encrypted: None,
                codepage: None,
                report_progress: false,
                output_inventory,
            };
            let frame = process.submit(request, &cancellation, WorkerUpdates::None, |_| {}).await?;
            std::fs::remove_dir_all(output)?;
            assert_eq!(frame.summary["status"], "ok", "{}", frame.summary);
            let manifest = frame.manifest.expect("verified output");
            assert_eq!(manifest.records().is_some(), output_inventory);
            if output_inventory {
                let records = manifest.records().unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].magic.as_ref(), content);
            }
            let stats = manifest.into_output_stats(&output_dir, output_inventory).unwrap();
            assert_eq!(stats.file_count, 1);
            assert_eq!(stats.total_size, content.len() as u64);
            assert_eq!(stats.inventory.is_some(), output_inventory);
        }
        Ok::<_, io::Error>(())
    });
    drop(process);
    std::fs::remove_file(path).unwrap();
    result.unwrap();
}

struct GatedInput {
    entered: mpsc::SyncSender<Vec<u8>>,
    release: mpsc::Receiver<()>,
    barriers: usize,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for GatedInput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.barriers != 0 {
            self.entered.send(bytes.to_vec()).unwrap();
            self.release.recv().unwrap();
            self.barriers -= 1;
        }
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn foreground(
    scheduler: &Arc<Scheduler>,
    request: u64,
) -> (JoinHandle<()>, mpsc::Receiver<()>) {
    let scheduler = Arc::clone(scheduler);
    let (done, finished) = mpsc::channel();
    let task = thread::spawn(move || {
        scheduler.run(request, Origin::Foreground, &Cancellation::new(), |_| {
            Box::pin(async move {
                done.send(()).unwrap();
            })
        });
    });
    (task, finished)
}

fn readiness(
    scheduler: &Arc<Scheduler>,
    process: &Arc<Process>,
    cancel: &Cancellation,
    id: u64,
) -> (JoinHandle<io::Result<usize>>, mpsc::Receiver<()>) {
    let scheduler = Arc::clone(scheduler);
    let process = Arc::clone(process);
    let cancel = cancel.clone();
    let (pending, parked) = mpsc::channel();
    let task = thread::spawn(move || {
        scheduler.run(id, Origin::Watch, &cancel, |_| {
            Box::pin(async {
                let mut ready = Box::pin(process.ready(&cancel));
                let mut pending = Some(pending);
                poll_fn(|cx| {
                    let result = ready.as_mut().poll(cx);
                    if result.is_pending() {
                        if let Some(pending) = pending.take() {
                            let _ = pending.send(());
                        }
                    }
                    result
                }).await
            })
        })
    });
    (task, parked)
}

#[test]
fn slow_ready_shares_waiters_cancellation_and_startup_mode_without_host_slots() {
    // Transport-write tests start with a ready process and miss both
    // readiness wake fan-out and cancellation losing sibling wakes.
    // One gated handshake also covers desired-mode reconciliation/refusal.
    let timeout = Duration::from_secs(10);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let scheduler = pool.install(Scheduler::new);
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (entered, writing) = mpsc::sync_channel(1);
    let (release, released) = mpsc::channel();
    let process = Process::with_test_input(GatedInput {
        entered, release: released, barriers: 1, bytes: Arc::clone(&bytes),
    });
    {
        let mut state = process.shared.state.lock().unwrap();
        state.ready = false;
        state.startup_mode = Some(ProcessMode::Normal);
    }
    let cancelled = Cancellation::new();
    let (first, first_pending) = readiness(&scheduler, &process, &cancelled, 1);
    first_pending.recv_timeout(timeout).unwrap();
    let (second, second_pending) = readiness(&scheduler, &process, &Cancellation::new(), 2);
    second_pending.recv_timeout(timeout).unwrap();
    let (third, third_pending) = readiness(&scheduler, &process, &Cancellation::new(), 3);
    third_pending.recv_timeout(timeout).unwrap();
    let (independent, finished) = foreground(&scheduler, 4);
    let responsive = finished.recv_timeout(timeout);
    cancelled.cancel();
    assert!(crate::io::cancellation::is_cancellation(&first.join().unwrap().unwrap_err()));
    assert!(process.alive());
    assert!(!process.startup_abandoned());
    assert_eq!(process.shared.state.lock().unwrap().ready_waiters.len(), 2);

    let changing = Arc::clone(&process);
    let control = scheduler.submit(100, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
        changing.set_process_mode_async(ProcessMode::High).await
    }));
    {
        let state = process.shared.state.lock().unwrap();
        let (state, timeout) = process.shared.changed.wait_timeout_while(state, timeout, |state| {
            state.startup_mode != Some(ProcessMode::High)
        }).unwrap();
        assert!(!timeout.timed_out());
        assert_eq!(state.startup_mode, Some(ProcessMode::High));
    }
    process.test_event(json!({
        "type": "worker_ready", "process_mode": "normal", "process_mode_applied": true,
        "thread_capacity": 7,
    }));
    let mode_write = writing.recv_timeout(timeout).unwrap();
    assert_eq!(mode_write, encode_worker_frame(&json!({
        "worker_command": "set_process_mode", "mode": "high",
    })).unwrap());
    assert!(!process.shared.state.lock().unwrap().ready);
    let (during_mode, mode_finished) = foreground(&scheduler, 5);
    let mode_responsive = mode_finished.recv_timeout(timeout);
    release.send(()).unwrap();
    process.test_event(json!({"type":"process_mode_ack", "mode":"high", "applied":false}));
    assert_eq!(second.join().unwrap().unwrap(), 7);
    assert_eq!(third.join().unwrap().unwrap(), 7);
    assert!(!control.join().unwrap().unwrap());
    assert!(process.shared.state.lock().unwrap().ready_waiters.is_empty());
    assert!(process.shared.state.lock().unwrap().startup_command.is_none());
    independent.join().unwrap();
    during_mode.join().unwrap();
    responsive.expect("slow ready retained the shared host slot");
    mode_responsive.expect("startup mode retained the shared host slot");
    drop(process);
    let shutdown = encode_worker_frame(&json!({"worker_command":"shutdown"})).unwrap();
    assert_eq!(*bytes.lock().unwrap(), [mode_write, shutdown].concat());
}

#[test]
fn process_mode_write_ack_and_exit_do_not_block_shared_control() {
    // The startup test exercises its special handshake path. This covers
    // an already-ready worker: both stdin backpressure and the ACK must
    // suspend control polls, and process exit must wake the pending setter.
    let timeout = Duration::from_secs(10);
    let scheduler = Scheduler::new();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (entered, writing) = mpsc::sync_channel(1);
    let (release, released) = mpsc::channel();
    let process = Process::with_test_input(GatedInput {
        entered, release: released, barriers: 1, bytes,
    });
    let changing = Arc::clone(&process);
    let control = scheduler.submit(100, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
        changing.set_process_mode_async(ProcessMode::High).await
    }));
    writing.recv_timeout(timeout).unwrap();
    let probe = |id| {
        let (send, receive) = mpsc::channel();
        let task = scheduler.submit(id, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
            send.send(()).unwrap();
        }));
        (task, receive.recv_timeout(timeout))
    };
    let (during_write, write_responsive) = probe(101);
    release.send(()).unwrap();
    let (during_ack, ack_responsive) = probe(102);
    process.test_event(json!({"type":"process_mode_ack", "mode":"high", "applied":true}));
    assert!(control.join().unwrap().unwrap());
    during_write.join().unwrap();
    during_ack.join().unwrap();
    write_responsive.expect("process mode write blocked the control driver");
    ack_responsive.expect("process mode ACK blocked the control driver");

    let changing = Arc::clone(&process);
    let (send, pending) = mpsc::channel();
    let control = scheduler.submit(103, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
        let mut change = Box::pin(changing.set_process_mode_async(ProcessMode::Normal));
        let mut send = Some(send);
        poll_fn(|cx| {
            let result = change.as_mut().poll(cx);
            if result.is_pending() {
                if let Some(send) = send.take() { send.send(()).unwrap(); }
            }
            result
        }).await
    }));
    pending.recv_timeout(timeout).unwrap();
    process.test_exit();
    assert!(control.join().unwrap().is_err());
    assert!(process.shared.state.lock().unwrap().mode_waiter.is_none());
}

#[test]
fn last_startup_cancellation_releases_a_waiting_mode_setter() {
    // A mode setter is not a worker borrower. Counting it as one keeps a
    // never-ready worker alive after every actual request has cancelled.
    let timeout = Duration::from_secs(10);
    let scheduler = Scheduler::new();
    let process = Process::with_test_input(Vec::new());
    {
        let mut state = process.shared.state.lock().unwrap();
        state.ready = false;
        state.startup_mode = Some(ProcessMode::Normal);
    }
    let cancel = Cancellation::new();
    let (borrower, pending) = readiness(&scheduler, &process, &cancel, 1);
    pending.recv_timeout(timeout).unwrap();
    let changing = Arc::clone(&process);
    let (completed, completion) = mpsc::channel();
    let control = thread::spawn(move || {
        completed.send(changing.set_process_mode(ProcessMode::High)).unwrap();
    });
    {
        let state = process.shared.state.lock().unwrap();
        let (_state, timed_out) = process.shared.changed.wait_timeout_while(state, timeout, |state| {
            state.startup_mode != Some(ProcessMode::High)
        }).unwrap();
        assert!(!timed_out.timed_out());
    }
    cancel.cancel();
    assert!(crate::io::cancellation::is_cancellation(&borrower.join().unwrap().unwrap_err()));
    let result = completion.recv_timeout(timeout);
    if result.is_err() {
        process.test_exit();
    }
    control.join().unwrap();
    assert!(result.expect("mode setter kept abandoned startup alive").is_err());
    assert!(!process.alive());
    assert!(process.shared.state.lock().unwrap().ready_waiters.is_empty());
}

#[test]
fn slow_spawn_failure_wakes_all_and_abandoned_owner_reaps_after_drop() {
    // A fake ready event cannot detect blocking Command::spawn, a consumed
    // startup error, or teardown missing a child that did not exist yet.
    let timeout = Duration::from_secs(10);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let scheduler = pool.install(Scheduler::new);
    let (entered, spawning) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (published, process_rx) = mpsc::channel();
    let starter_scheduler = Arc::clone(&scheduler);
    let starter = thread::spawn(move || {
        starter_scheduler.run(1, Origin::Watch, &Cancellation::new(), |_| {
            Box::pin(async move {
                let process = Process::with_test_start(move || {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    Err(io::Error::new(io::ErrorKind::NotFound, "injected spawn failure"))
                });
                published.send(Arc::clone(&process)).unwrap();
                process.ready(&Cancellation::new()).await
            })
        })
    });
    spawning.recv_timeout(timeout).unwrap();
    let process = process_rx.recv_timeout(timeout).expect("spawn blocked its scheduler poll");
    let (second, pending) = readiness(&scheduler, &process, &Cancellation::new(), 2);
    pending.recv_timeout(timeout).unwrap();
    let (independent, completed) = foreground(&scheduler, 3);
    let responsive = completed.recv_timeout(timeout);
    release.send(()).unwrap();
    for result in [starter.join().unwrap(), second.join().unwrap()] {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }
    assert!(!process.alive());
    assert!(process.shared.state.lock().unwrap().ready_waiters.is_empty());
    independent.join().unwrap();
    responsive.expect("slow spawn retained the shared host slot");

    let (entered, spawning) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let process = Process::with_test_start(move || {
        entered.send(()).unwrap();
        released.recv().unwrap();
        Command::new(std::env::current_exe().unwrap()).arg("--list")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
    });
    spawning.recv_timeout(timeout).unwrap();
    let shared = Arc::clone(&process.shared);
    let child = Arc::clone(&process.child);
    let cancel = Cancellation::new();
    let mut borrower = Box::pin(process.ready(&cancel));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(borrower.as_mut().poll(&mut cx).is_pending());
    cancel.cancel();
    assert!(borrower.as_mut().poll(&mut cx).is_pending(), "last cancellation skipped child cleanup");
    assert!(process.startup_abandoned());
    assert!(process.alive(), "unfinished cleanup became replaceable");
    release.send(()).unwrap();
    let state = shared.state.lock().unwrap();
    let (state, timed_out) = shared.changed.wait_timeout_while(state, timeout, |state| {
        state.closed.is_none()
    }).unwrap();
    assert!(!timed_out.timed_out());
    assert!(state.owner.is_none(), "failed startup retained its thread handle");
    drop(state);
    assert!(matches!(*child.lock().unwrap(), ChildState::Exited(_)), "reaped startup retained its process handle");
    let Poll::Ready(result) = borrower.as_mut().poll(&mut cx) else {
        panic!("reaped startup did not finish cancellation");
    };
    assert!(crate::io::cancellation::is_cancellation(&result.unwrap_err()));
    drop(borrower);
    assert!(shared.state.lock().unwrap().ready_waiters.is_empty());
    drop(process);

    // Engine teardown can also happen before any readiness future is
    // polled. In that case Drop itself must retire the pending startup.
    let (release, released) = mpsc::channel();
    let process = Process::with_test_start(move || {
        released.recv().unwrap();
        Err(io::Error::other("owner dropped before spawn finished"))
    });
    let shared = Arc::clone(&process.shared);
    drop(process);
    assert!(shared.state.lock().unwrap().startup_abandoned);
    release.send(()).unwrap();
    let state = shared.state.lock().unwrap();
    let (_state, timed_out) = shared.changed.wait_timeout_while(state, timeout, |state| {
        state.closed.is_none()
    }).unwrap();
    assert!(!timed_out.timed_out());
}

#[test]
fn stdin_first_worker_death_keeps_worker_lost() {
    struct ClosedPipe;
    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    // This fixture owns a real, already-reaped child and only an stdin
    // dispatcher, so stdout cannot win publication and hide the regression.
    let process = Process::with_test_input(ClosedPipe);
    let mailbox = register(&process.shared, "admitted");
    let write = process.shared.send(Arc::new(vec![1]));
    let error = write.wait_blocking().unwrap_err();
    assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, "worker_lost");
    let error = mailbox.updates.lock().unwrap().result.take().unwrap().err().unwrap();
    assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, "worker_lost");
    assert!(matches!(*process.child.lock().unwrap(), ChildState::Exited(Some(_))),
        "failed stdin retained the process handle or lost its exit status for stdout");
}

#[test]
fn communication_failures_keep_the_report_kind() {
    for kind in ["worker_lost", "process_io"] {
        let error = WorkerExit { message: "worker failed".into(), kind: io::ErrorKind::BrokenPipe, failure_kind: kind }.error();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "worker failed");
        assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, kind);
    }
}

#[test]
fn job_protocol_errors_cancel_once_and_wait_for_native_completion() {
    for malformed in [
        // A frame boundary and job route survive a malformed event body.
        json!({"type": "progress", "job_id": "bad", "rows": "invalid"}),
        // A valid body can still fail manifest sequence validation.
        json!({"type": "manifest_chunk", "job_id": "bad", "seq": 1, "rows": []}),
    ] {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (entered, writing) = mpsc::sync_channel(1);
        let (release, released) = mpsc::channel();
        let process = Process::with_test_input(GatedInput {
            entered,
            release: released,
            barriers: 1,
            bytes: Arc::clone(&bytes),
        });
        let mailbox = register(&process.shared, "bad");
        let sibling = register(&process.shared, "sibling");
        let cancellation = Cancellation::new();
        let mut on_update = |_| {};
        let mut waiting = Box::pin(process.wait(
            "bad", &mailbox, &cancellation, &mut on_update,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        dispatch(&process.shared, malformed.clone());
        assert!(mailbox.updates.lock().unwrap().result.is_none());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        let cancel = writing.recv_timeout(Duration::from_secs(10)).unwrap();
        let expected = encode_worker_frame(
            &json!({"worker_command": "cancel", "job_id": "bad"}),
        ).unwrap();
        assert_eq!(cancel, expected);
        // Neither repeated broken events nor user cancellation duplicate it.
        dispatch(&process.shared, malformed);
        cancellation.cancel();
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        finish(&process.shared, "sibling", false);
        assert!(sibling.updates.lock().unwrap().result.take().unwrap().is_ok());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        release.send(()).unwrap();
        finish(&process.shared, "bad", false);
        let Poll::Ready(result) = waiting.as_mut().poll(&mut cx) else {
            panic!("job_finished did not deliver the protocol error");
        };
        let error = result.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, "process_io");
        drop(waiting);
        drop(process);
        let shutdown = encode_worker_frame(&json!({"worker_command": "shutdown"})).unwrap();
        assert_eq!(*bytes.lock().unwrap(), [expected, shutdown].concat());
    }
}

#[test]
fn blocked_submit_and_cancel_release_the_only_host_slot_and_drain_in_order() {
    // Unlike a mailbox-only test, exercise Process::submit and its cancel
    // path on a real one-slot Scheduler. Neither pipe write is released
    // until an independent foreground request has had a chance to run.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let scheduler = pool.install(Scheduler::new);
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (entered, writing) = mpsc::sync_channel(2);
    let (release, released) = mpsc::channel();
    let input = GatedInput {
        entered,
        release: released,
        barriers: 2,
        bytes: Arc::clone(&bytes),
    };
    let process = Process::with_test_input(input);
    let shared = Arc::clone(&process.shared);
    let cancellation = Cancellation::new();
    let watch_cancel = cancellation.clone();
    let watch_process = Arc::clone(&process);
    let watch_scheduler = Arc::clone(&scheduler);
    let request = json!({
        "job_id": "slow", "operation": "extract", "password": "x".repeat(128 * 1024),
    });
    let mut expected_request = request.clone();
    expected_request["report_progress"] = Value::Bool(false);
    let expected = encode_worker_frame(&expected_request).unwrap();
    let payload = InputPayload::Frame(Arc::new(expected.clone()));
    let (completed, completion) = mpsc::channel();
    let watch = thread::spawn(move || {
        let result = watch_scheduler.run(1, Origin::Watch, &watch_cancel, |_| {
            Box::pin(watch_process.submit_payload(
                "slow", payload, &watch_cancel, WorkerUpdates::None, |_| {},
            ))
        });
        completed.send(result.is_ok()).unwrap();
        result
    });
    let submitted = writing.recv_timeout(Duration::from_secs(10)).unwrap();
    let (first, first_done) = foreground(&scheduler, 2);
    let submit_independent = first_done.recv_timeout(Duration::from_secs(10));
    cancellation.cancel();
    release.send(()).unwrap();
    let cancel = writing.recv_timeout(Duration::from_secs(10)).unwrap();
    let (second, second_done) = foreground(&scheduler, 3);
    let cancel_independent = second_done.recv_timeout(Duration::from_secs(10));
    let retained_lease = completion.try_recv().is_err();
    release.send(()).unwrap();
    finish(&shared, "slow", false);
    watch.join().unwrap().unwrap();
    first.join().unwrap();
    second.join().unwrap();
    drop(process); // Ordered shutdown, pipe close and writer join.

    submit_independent.expect("blocked submit retained the shared host slot");
    cancel_independent.expect("blocked cancellation retained the shared host slot");
    assert!(
        retained_lease,
        "cancellation returned before native job_finished",
    );
    assert_eq!(submitted, expected);
    let expected_cancel =
        encode_worker_frame(&json!({"worker_command": "cancel", "job_id": "slow"})).unwrap();
    assert_eq!(cancel, expected_cancel);
    let shutdown = encode_worker_frame(&json!({"worker_command": "shutdown"})).unwrap();
    assert_eq!(
        *bytes.lock().unwrap(),
        [expected, expected_cancel, shutdown].concat(),
    );
    assert!(shared.state.lock().unwrap().writes.is_empty());
    assert_eq!(
        Arc::strong_count(&shared), 1,
        "writer retained the process after shutdown",
    );
}

#[test]
fn partial_write_failure_reaps_before_waking_senders_and_exit_stops_idle_writer() {
    // Completion/retry tests cannot detect leases released after a partial
    // frame, stranded queued senders, or an idle stdin thread leaked on EOF.
    struct PartialFailure(bool);
    impl Write for PartialFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.0, false) {
                Ok(bytes.len().min(2))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected partial write",
                ))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let shared = Arc::new(Shared::default());
    let mailbox = register(&shared, "admitted");
    let first = shared.send(Arc::new(vec![1; 8]));
    let queued = shared.send(Arc::new(vec![2; 8]));
    let (stopping, stopped) = mpsc::channel();
    let (reap, reaped) = mpsc::channel();
    let owner = Arc::clone(&shared);
    let writer = thread::spawn(move || {
        dispatch_stdin(PartialFailure(true), &owner, |error| {
            stopping.send(()).unwrap();
            reaped.recv().unwrap();
            owner.fail(error.to_string(), io::ErrorKind::BrokenPipe);
        });
    });
    stopped.recv_timeout(Duration::from_secs(10)).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(first.poll(&mut cx).is_pending());
    assert!(queued.poll(&mut cx).is_pending());
    assert!(mailbox.updates.lock().unwrap().result.is_none());
    reap.send(()).unwrap();
    writer.join().unwrap();
    for write in [first, queued, shared.send(Arc::new(vec![3]))] {
        assert_eq!(
            write.wait_blocking().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe,
        );
    }
    assert_eq!(
        mailbox.updates.lock().unwrap().result.take().unwrap().err().unwrap().kind(),
        io::ErrorKind::BrokenPipe,
    );
    {
        let state = shared.state.lock().unwrap();
        assert_eq!(state.writes.capacity(), 0);
        assert_eq!(state.jobs.capacity(), 0);
    }

    let idle = Arc::new(Shared::default());
    let owner = Arc::clone(&idle);
    let (finished, done) = mpsc::channel();
    let writer = thread::spawn(move || {
        dispatch_stdin(Vec::new(), &owner, |_| panic!("unexpected write failure"));
        finished.send(()).unwrap();
    });
    idle.fail("worker stdout exited".into(), io::ErrorKind::BrokenPipe);
    done.recv_timeout(Duration::from_secs(10))
        .expect("EOF left an idle writer asleep");
    writer.join().unwrap();
    assert_eq!(Arc::strong_count(&idle), 1);
}

#[test]
fn worker_transport_diagnostic_survives_unrelated_results() {
    let shared = Shared::default();
    let job = register(&shared, "unrelated");
    // Process stderr has no job ID. Even after another job has completed, its
    // latest bytes belong to the process exit only. Cross a pipe read boundary
    // inside a UTF-8 sequence and exceed the opaque stderr safety window.
    let text = "密".repeat(STDERR_TAIL_BYTES);
    let history = pump_stderr(io::Cursor::new(text.as_bytes()));
    finish(&shared, "unrelated", false);
    let frame = job.updates.lock().unwrap().result.take().unwrap().unwrap();
    assert!(frame.summary.get("stderr_tail").is_none());

    // Structured errors use the regular worker frame and keep the entire
    // message, even when a child process could not report it through stderr.
    let detail = "invalid worker request ".repeat(STDERR_TAIL_BYTES);
    let bytes = encode_worker_frame(&json!({
        "type": "worker_fatal",
        "message": detail,
    })).unwrap();
    let error = dispatch_stdout(io::Cursor::new(bytes), &shared).unwrap_err();
    assert_eq!(error.to_string(), detail);

    let mut fallback = String::new();
    assert!(history.bytes.len() <= STDERR_TAIL_BYTES);
    history.append_diagnostic(&mut fallback);
    assert_eq!(fallback, format!("\nWorker stderr (earlier output omitted)\n{}",
        "密".repeat(STDERR_TAIL_BYTES / "密".len())));
}

fn dispatch(shared: &Shared, summary: Value) {
    let bytes = encode_worker_frame(&summary).unwrap();
    let mut decoder = NativeWorkerFrameDecoder::default();
    for frame in decoder.feed(&bytes).unwrap() {
        shared.event(frame);
    }
    decoder.finish().unwrap();
}

fn register(shared: &Shared, id: &str) -> Arc<Mailbox> {
    let mailbox = Arc::new(Mailbox::default());
    shared.register(id, Arc::clone(&mailbox)).unwrap();
    mailbox
}

fn finish(shared: &Shared, id: &str, backpressure: bool) {
    dispatch(
        shared,
        json!({
            "type": "result", "job_id": id, "retryable": backpressure,
            "native_status": if backpressure { "backpressure" } else { "ok" },
        }),
    );
    dispatch(
        shared,
        json!({"type": "native_event", "event": "job_finished", "job_id": id}),
    );
}

fn take_rejection(mailbox: &Mailbox) {
    let result = mailbox
        .updates
        .lock()
        .unwrap()
        .result
        .take()
        .unwrap()
        .unwrap();
    assert!(rejected(&result));
}

fn take_retry(
    shared: &Shared,
    id: &str,
    mailbox: &Mailbox,
    cancel: &Cancellation,
) -> io::Result<()> {
    match shared.poll_retry(id, mailbox, cancel, &mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("retry should have settled"),
    }
}

#[test]
fn each_completion_grants_one_retry_and_cancellation_passes_its_slot() {
    let shared = Shared::default();
    register(&shared, "active");
    let first = register(&shared, "first");
    let second = register(&shared, "second");
    let third = register(&shared, "third");
    for (id, mailbox) in [("first", &first), ("second", &second), ("third", &third)] {
        finish(&shared, id, true);
        take_rejection(mailbox);
        assert!(!mailbox.updates.lock().unwrap().retry_granted);
    }

    finish(&shared, "active", false);
    assert!(first.updates.lock().unwrap().retry_granted);
    assert!(!second.updates.lock().unwrap().retry_granted);
    assert!(!third.updates.lock().unwrap().retry_granted);

    let cancelled = Cancellation::new();
    cancelled.cancel();
    assert_eq!(
        take_retry(&shared, "first", &first, &cancelled)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other,
    );
    assert!(second.updates.lock().unwrap().retry_granted);
    assert!(!third.updates.lock().unwrap().retry_granted);

    shared.fail("worker exited".into(), io::ErrorKind::BrokenPipe);
    for (id, mailbox) in [("second", &second), ("third", &third)] {
        assert_eq!(
            take_retry(&shared, id, mailbox, &Cancellation::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe,
        );
    }
}

#[test]
fn rejection_retries_immediately_when_no_other_job_can_finish() {
    let shared = Shared::default();
    let mailbox = register(&shared, "retry");
    let bytes = Arc::new(vec![1; 1024]);
    let payload_lifetime = Arc::downgrade(&bytes);
    mailbox.updates.lock().unwrap().retry_payload = Some(InputPayload::Frame(bytes));
    finish(&shared, "retry", true);
    take_rejection(&mailbox);
    assert!(mailbox.updates.lock().unwrap().retry_granted);
    take_retry(&shared, "retry", &mailbox, &Cancellation::new()).unwrap();
    assert!(payload_lifetime.upgrade().is_some());

    dispatch(&shared, json!({
        "type": "native_event", "event": "job_accepted", "job_id": "retry",
    }));
    assert!(payload_lifetime.upgrade().is_none());
    assert!(mailbox.updates.lock().unwrap().result.is_none());

    finish(&shared, "retry", false);
    assert!(mailbox
        .updates
        .lock()
        .unwrap()
        .result
        .take()
        .unwrap()
        .is_ok());
}

#[test]
fn completion_before_rejection_can_be_claimed_once() {
    let shared = Shared::default();
    register(&shared, "active");
    register(&shared, "paused");
    let first = register(&shared, "first");
    let second = register(&shared, "second");
    finish(&shared, "active", false);
    finish(&shared, "first", true);
    finish(&shared, "second", true);
    take_rejection(&first);
    take_rejection(&second);
    assert!(first.updates.lock().unwrap().retry_granted);
    assert!(!second.updates.lock().unwrap().retry_granted);
}

// Feed real binary frame decoding and mailbox coalescing to CLI tests.
// One batch represents frames arriving before the submission is polled.
pub(crate) fn coalesced_wait_batches(batches: &[Vec<Value>]) -> Vec<ResourceWait> {
    let shared = Shared::default();
    let mailbox = register(&shared, "active");
    batches.iter().map(|batch| {
        for summary in batch {
            let mut summary = summary.clone();
            summary["job_id"] = json!("active");
            dispatch(&shared, summary);
        }
        mailbox.updates.lock().unwrap().resources.take().unwrap()
    }).collect()
}

#[test]
fn resource_wait_tracks_independent_episodes_through_binary_frames() {
    let shared = Shared::default();
    let mailbox = register(&shared, "active");
    let take_wait = || mailbox.updates.lock().unwrap().resources.take();
    dispatch(
        &shared,
        json!({
            "type": "progress", "event": "space_blocked", "job_id": "active", "episode_id": 1,
            "volume_query_ok": false, "volume_query_error": 21,
        }),
    );
    dispatch(
        &shared,
        json!({"type": "native_memory", "event": "memory_blocked", "job_id": "active", "episode_id": 3}),
    );
    dispatch(
        &shared,
        json!({"type": "progress", "job_id": "active", "completed_bytes": 4, "total_bytes": 8}),
    );
    assert_eq!(
        take_wait(),
        Some(ResourceWait {
            disk: true,
            disk_episode: 1,
            memory: true,
            volume_error: Some(21)
        }),
    );
    assert_eq!(
        mailbox.updates.lock().unwrap().progress.unwrap().completed,
        4
    );

    for event in ["space_resumed", "space_status", "space_blocked"] {
        dispatch(
            &shared,
            json!({"type": "progress", "event": event, "job_id": "active", "episode_id": 1}),
        );
    }
    dispatch(
        &shared,
        json!({"type": "native_memory", "event": "memory_resumed", "job_id": "active", "episode_id": 2}),
    );
    assert_eq!(
        take_wait(),
        Some(ResourceWait {
            disk: false,
            disk_episode: 1,
            memory: true,
            volume_error: None
        }),
    );
    dispatch(
        &shared,
        json!({"type": "native_memory", "event": "memory_resumed", "job_id": "active", "episode_id": 3}),
    );
    assert_eq!(take_wait(), Some(ResourceWait { disk_episode: 1, ..Default::default() }));
}
