use crate::io::archive_state::archive_input_slices;
use super::*;

impl Outcome {
    fn succeeded(&self) -> usize {
        self.archives.iter().filter(|archive| archive.failure.is_none() || archive.partial).count()
    }
    fn failed(&self) -> usize {
        self.archives.len() - self.succeeded() + self.errors.len()
    }
}

#[test]
fn shared_cleanup_waits_for_every_owner_and_preserves_failed_sources() {
    let registry = Arc::new(Mutex::new(CleanupRefs::default()));
    let paths = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect::<Vec<_>>();
    let key = |path: &str| namespace_key(Path::new(path));
    let mut first = CleanupOwner::new(&registry, &paths(&["a.001", "tail.002"]));
    let mut second = CleanupOwner::new(&registry, &paths(&["b.001", "tail.002"]));
    assert_eq!(first.release(true), HashSet::from([key("a.001")]));
    assert_eq!(second.release(true), HashSet::from([key("b.001"), key("tail.002")]));
    assert!(registry.lock().unwrap().paths.is_empty());

    let first = CleanupOwner::new(&registry, &paths(&["a.001", "tail.002"]));
    let mut second = CleanupOwner::new(&registry, &paths(&["b.001", "tail.002"]));
    drop(first); // Includes cancelled and never-dispatched batch owners.
    assert_eq!(second.release(true), HashSet::from([key("b.001")]));
    assert!(registry.lock().unwrap().paths.is_empty());

    let mut first = CleanupOwner::new(&registry, &paths(&["a.001", "old.002"]));
    let mut second = CleanupOwner::new(&registry, &paths(&["b.001", "new.002"]));
    first.refresh(&paths(&["a.001", "new.002"]));
    assert!(!registry.lock().unwrap().paths.contains_key(&key("old.002")));
    assert_eq!(second.release(true), HashSet::from([key("b.001")]));
    assert_eq!(first.release(true), HashSet::from([key("a.001"), key("new.002")]));
    assert!(registry.lock().unwrap().paths.is_empty());
}

#[test]
fn request_read_pins_share_sources_but_mutation_and_other_requests_wait() {
    use std::future::Future;
    use std::task::{Context, Wake};
    struct Noop;
    impl Wake for Noop { fn wake(self: Arc<Self>) {} }
    let leases = Arc::new(Leases::default());
    let cancel = Cancellation::new();
    let keys = || HashSet::from([Arc::from("tail.002")]);
    let first = super::super::scheduling::block_on(leases.acquire_shared(keys(), 1, &cancel)).unwrap();
    let second = super::super::scheduling::block_on(leases.acquire_shared(keys(), 1, &cancel)).unwrap();
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    let mut other = Box::pin(leases.acquire_shared(keys(), 2, &cancel));
    let mut mutation = Box::pin(leases.acquire(keys(), &cancel));
    assert!(other.as_mut().poll(&mut cx).is_pending());
    assert!(mutation.as_mut().poll(&mut cx).is_pending());
    drop(first);
    assert!(mutation.as_mut().poll(&mut cx).is_pending());
    drop(second);
    let exclusive = match mutation.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(lease)) => lease,
        _ => panic!("all readers retired"),
    };
    assert!(other.as_mut().poll(&mut cx).is_pending());
    drop(exclusive);
    assert!(matches!(other.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
    drop(other);
    drop(mutation);
    let state = leases.state.lock().unwrap();
    assert!(state.active.is_empty() && state.waiters.is_empty() && state.blocked_by.is_empty());
}

#[test]
fn lease_notifications_follow_blockers_and_unregister_cancelled_waiters() {
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake};

    #[derive(Default)]
    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let leases = Arc::new(Leases::default());
    let cancel = Cancellation::new();
    let keys = |paths: &[&str]| paths.iter().copied().map(Arc::from).collect();
    let first = super::super::scheduling::block_on(leases.acquire(keys(&["a"]), &cancel)).unwrap();
    let second = super::super::scheduling::block_on(leases.acquire(keys(&["b"]), &cancel)).unwrap();
    let unrelated = super::super::scheduling::block_on(leases.acquire(keys(&["c"]), &cancel)).unwrap();
    let wakes = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    let mut waiting = Box::pin(leases.acquire(keys(&["a", "b"]), &cancel));
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    drop(unrelated);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    drop(first);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    drop(second);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    let held = match waiting.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(lease)) => lease,
        _ => panic!("released family remained blocked"),
    };
    drop(waiting);

    // Cancellation and dropping a pending future remove both directions
    // of the dependency index, not just its stored waker.
    let stopped = Cancellation::new();
    let mut cancelled = Box::pin(leases.acquire(keys(&["a"]), &stopped));
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    stopped.cancel();
    assert!(matches!(cancelled.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    drop(cancelled);
    let mut abandoned = Box::pin(leases.acquire(keys(&["b"]), &cancel));
    assert!(abandoned.as_mut().poll(&mut cx).is_pending());
    drop(abandoned);
    let state = leases.state.lock().unwrap();
    assert!(state.waiters.is_empty());
    assert!(state.blocked_by.is_empty());
    drop(state);
    drop(held);
}

#[test]
fn request_notifications_are_separate_from_physical_family_leases() {
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake};

    #[derive(Default)]
    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let leases = Arc::new(Leases::default());
    let cancel = Cancellation::new();
    let first_path = [PathBuf::from("claim-family.7z.001")];
    let other_path = [PathBuf::from("claim-family.7z.002")];
    let first = leases.reserve_request(1, Origin::Foreground, &first_path, &cancel).unwrap();
    let family: HashSet<_> = ["claim-family.7z.001", "claim-family.7z.002"]
        .into_iter().map(Arc::from).collect();
    let held = super::super::scheduling::block_on(leases.acquire(family.clone(), &cancel)).unwrap();
    // A different original volume remains admissible while the resolved
    // physical family is in use; the same original selection is still busy.
    let other = leases.reserve_request(2, Origin::Foreground, &other_path, &cancel).unwrap();
    assert!(matches!(leases.reserve_request(3, Origin::Foreground, &first_path, &cancel),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    let request_wakes = Arc::new(CountWake::default());
    let request_waker = Waker::from(Arc::clone(&request_wakes));
    let mut request_cx = Context::from_waker(&request_waker);
    let mut request = Box::pin(leases.reserve_request_async(4, Origin::Watch, &first_path, &cancel));
    assert!(request.as_mut().poll(&mut request_cx).is_pending());
    let physical_wakes = Arc::new(CountWake::default());
    let physical_waker = Waker::from(Arc::clone(&physical_wakes));
    let mut physical_cx = Context::from_waker(&physical_waker);
    let mut physical = Box::pin(leases.acquire(family, &cancel));
    assert!(physical.as_mut().poll(&mut physical_cx).is_pending());
    drop(other);
    assert_eq!(request_wakes.0.load(Ordering::SeqCst), 0);
    assert_eq!(physical_wakes.0.load(Ordering::SeqCst), 0);
    drop(first);
    assert_eq!(request_wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(physical_wakes.0.load(Ordering::SeqCst), 0);
    let claim = match request.as_mut().poll(&mut request_cx) {
        Poll::Ready(Ok(claim)) => claim,
        _ => panic!("released original request remained blocked"),
    };
    drop(held);
    assert_eq!(physical_wakes.0.load(Ordering::SeqCst), 1);
    assert!(matches!(physical.as_mut().poll(&mut physical_cx), Poll::Ready(Ok(_))));
    drop(request);
    drop(physical);
    drop(claim);
    let state = leases.state.lock().unwrap();
    assert!(state.waiters.is_empty());
    assert!(state.blocked_by.is_empty());
}

#[test]
fn split_failure_suffixes_preserve_disguises_and_unicode_decimal_digits() {
    for path in [r"C:\folder.part1.rar\archive.PaRt١٢.RaR.cover", "archive.z０१", "archive.९८७.bin", "archive.001"] {
        assert!(looks_like_split_archive_name(path), "{path}");
    }
    for path in [r"C:\folder.part1.rar\archive.bin", "archive.z01.bin", "archive.¹²³", "archive.001.", "archive.part1.rar.bin.txt"] {
        assert!(!looks_like_split_archive_name(path), "{path}");
    }
}

#[test]
fn worker_failure_proof_survives_json_and_streamed_report() {
    let cases = [
        (json!({"failure_kind":"resource_unavailable", "hresult":-2147024882i64}), None,
            json!({"hresult":-2147024882i64})),
        (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error",
            "password_crc_proven_items":2}), Some("zipcrypto_header_byte"),
            json!({"classification_evidence":"entry_crc_proven_before_failure", "password_crc_proven_items":2})),
        (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error"}), Some("zipcrypto_header_byte"),
            json!({"classification_evidence":"zipcrypto_failure_without_password_proof", "backend_operation_result":"crc_error"})),
        (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error"}), Some("zip_pkware_strong_padding"),
            json!({"classification_evidence":"pkware_strong_failure_without_password_proof", "backend_operation_result":"crc_error"})),
        (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error", "encrypted":true}), Some("empty_password_direct"),
            json!({"classification_evidence":"empty_password_failed_without_crc_proof", "backend_operation_result":"crc_error"})),
    ];
    for (worker, proof, expected) in cases {
        let mut failure = classify_worker_failure(&worker, proof, false);
        failure.evidence = worker_evidence(&worker, proof);
        let mut report = Vec::new();
        crate::failure_report::stream_json(&mut report, &failure, false, &Cancellation::new()).unwrap();
        let value: Value = serde_json::from_slice(&report).unwrap();
        for (key, expected) in expected.as_object().unwrap() {
            assert_eq!(&value["evidence"][key], expected);
        }
        let restored: Failure = serde_json::from_value(value).unwrap();
        assert_eq!(restored.kind, failure.kind);
        assert_eq!(restored.is_password_retry(), failure.is_password_retry());
    }
}

#[test]
fn password_evidence_controls_retry_without_reclassifying_weak_crc_damage() {
    // A kind-only test cannot distinguish the two inconclusive outcomes.
    // Exercise worker classification, retained evidence, serialization and
    // the shared physical-input projection used by Watch and notifications.
    let cases = [
        (serde_json::json!({"failure_kind": "checksum_error", "operation_result_name": "crc_error"}),
            Some("zipcrypto_header_byte"), FailureKind::PasswordInconclusive, false),
        (serde_json::json!({"failure_kind": "password_or_volume_inconclusive"}),
            Some("zipcrypto_header_byte"), FailureKind::PasswordInconclusive, true),
        (serde_json::json!({"failure_kind": "checksum_error", "operation_result_name": "crc_error",
            "password_crc_proven_items": 1}),
            Some("zipcrypto_header_byte"), FailureKind::Damaged, false),
        (serde_json::json!({"failure_kind": "checksum_error", "encrypted": true}),
            Some("empty_password_direct"), FailureKind::WrongPassword, true),
        (serde_json::json!({"password_candidates_all_rejected": true}),
            Some("zipcrypto_header_byte"), FailureKind::WrongPassword, true),
        (serde_json::json!({"failure_kind": "checksum_error"}),
            Some("strong_password_proof"), FailureKind::Damaged, false),
    ];
    for (worker, evidence, kind, retry) in cases {
        let mut failure = classify_worker_failure(&worker, evidence, true);
        failure.evidence = worker_evidence(&worker, evidence);
        assert_eq!(failure.kind, kind, "{worker}");
        let failure: Failure = serde_json::from_value(serde_json::to_value(&failure).unwrap()).unwrap();
        assert_eq!(failure.is_password_retry(), retry, "{worker}");
        let outcome = PublicOutcome {
            archives: vec![ArchiveResult {
                path: "carrier.bin".into(), format: "zip".into(), output: None,
                failure: Some(failure), files: 0, bytes: 0, encrypted: Some(true),
                depth: 1, offset: 123, end_offset: None, volume_completeness: None,
                volume_attempts: None, source_paths: vec!["carrier.bin".into()],
                password: None, discovery_source: DiscoverySource::Embedded,
                partial: false, retained: false,
                recovered_complete_files: 0,   scan_layout: Default::default(),
            }],
            ..PublicOutcome::default()
        };
        let failures = outcome.input_failures();
        let failure = failures.values().next().unwrap();
        assert_eq!(failure.retryable(), retry, "{worker}");
        assert_eq!(failure.terminal.is_some(), !retry, "{worker}");
    }
}

#[test]
fn requests_wait_for_startup_even_when_discovery_would_be_empty() {
    use std::time::Duration;
    let timeout = Duration::from_secs(10);
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let process = Process::with_test_start(move || {
        entered.send(()).unwrap();
        gate.recv().unwrap();
        Err(io::Error::new(io::ErrorKind::NotFound, "startup gate failure"))
    });
    started.recv_timeout(timeout).unwrap();
    engine.worker.lock().unwrap().process = Some(process);
    let observer = Arc::new(|_: Event| panic!("discovery preceded the startup handshake"));
    let first = engine.submit(Request::new(Vec::new(), Mode::Scan), Arc::clone(&observer), |result| result);
    let second = engine.submit(Request::new(Vec::new(), Mode::Scan), observer, |result| result);
    assert!(!first.is_finished());
    assert!(!second.is_finished());
    release.send(()).unwrap();
    for handle in [first, second] {
        let error = handle.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
    let missing = Engine::new(PathBuf::from("sunpack-missing-worker-for-startup-test.exe"));
    let error = missing.submit(Request::new(Vec::new(), Mode::Scan), Arc::new(|_: Event| {}), |result| result)
        .join().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
}

#[test]
fn cancelled_startup_is_shared_until_cleanup_then_live_borrowers_retry() {
    use std::future::Future;
    use std::thread;
    use std::time::Duration;

    // Process-only tests cannot catch Engine publishing a second process
    // before cleanup, returning another request's cancellation, or retaining
    // a failed generation forever. Exercise both borrow paths on one slot.
    fn borrow(
        scheduler: &Arc<Scheduler>, engine: &Arc<Engine>, cancel: &Cancellation, id: u64,
    ) -> (thread::JoinHandle<io::Result<Arc<Process>>>, mpsc::Receiver<()>) {
        let scheduler = Arc::clone(scheduler);
        let engine = Arc::clone(engine);
        let cancel = cancel.clone();
        let (pending, parked) = mpsc::channel();
        let task = thread::spawn(move || {
            scheduler.run(id, Origin::Watch, &cancel, |_| {
                Box::pin(async {
                    let config = WorkerConfig { space_poll_interval_ms: Some(1000), space_status_report_interval_ms: Some(1000) };
                    let mut worker = Box::pin(engine.worker(&config, &cancel));
                    let mut pending = Some(pending);
                    poll_fn(|cx| {
                        let result = worker.as_mut().poll(cx);
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
    let timeout = Duration::from_secs(10);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let scheduler = pool.install(Scheduler::new);
    let worker_path = std::env::temp_dir().join(format!(
        "sunpack_missing_startup_worker_{}_{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    let engine = Arc::new(Engine::new(worker_path));
    let (entered, spawning) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let initial = Process::with_test_start(move || {
        entered.send(()).unwrap();
        released.recv().unwrap();
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "abandoned spawn failure"))
    });
    spawning.recv_timeout(timeout).unwrap();
    engine.worker.lock().unwrap().process = Some(Arc::clone(&initial));
    let cancel = Cancellation::new();
    let (first, pending) = borrow(&scheduler, &engine, &cancel, 1);
    pending.recv_timeout(timeout).unwrap();
    cancel.cancel();
    initial.test_wait_startup_abandoned();
    assert!(!first.is_finished(), "last borrower returned before cleanup");
    assert!(initial.startup_abandoned());
    assert!(initial.alive());
    let (next, pending) = borrow(&scheduler, &engine, &Cancellation::new(), 2);
    pending.recv_timeout(timeout).unwrap();
    assert!(Arc::ptr_eq(engine.worker.lock().unwrap().process.as_ref().unwrap(), &initial));
    let (done, finished) = mpsc::channel();
    let independent_scheduler = Arc::clone(&scheduler);
    let independent = thread::spawn(move || {
        independent_scheduler.run(3, Origin::Foreground, &Cancellation::new(), |_| {
            Box::pin(async move { done.send(()).unwrap(); })
        });
    });
    let responsive = finished.recv_timeout(timeout);
    release.send(()).unwrap();
    assert!(is_cancellation(&first.join().unwrap().err().unwrap()));
    let error = next.join().unwrap().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "borrower inherited an abandoned generation");
    let replacement = Arc::clone(engine.worker.lock().unwrap().process.as_ref().unwrap());
    assert!(!Arc::ptr_eq(&initial, &replacement));
    assert!(!initial.alive());
    independent.join().unwrap();
    responsive.expect("abandoned startup cleanup retained the only host slot");

    // Genuine startup errors return to the current request, but do not
    // prevent a later request from starting a fresh generation.
    assert!(!engine.set_process_mode(ProcessMode::High).unwrap());
    let (later, _) = borrow(&scheduler, &engine, &Cancellation::new(), 4);
    assert_eq!(later.join().unwrap().err().unwrap().kind(), io::ErrorKind::NotFound);
    let owner = engine.worker.lock().unwrap();
    assert!(!Arc::ptr_eq(owner.process.as_ref().unwrap(), &replacement));
    assert_eq!(owner.desired_mode, ProcessMode::High);
    drop(owner);
    let ready = Process::with_test_input(Vec::new());
    engine.worker.lock().unwrap().process = Some(Arc::clone(&ready));
    let (later, _) = borrow(&scheduler, &engine, &Cancellation::new(), 5);
    assert!(Arc::ptr_eq(&later.join().unwrap().unwrap(), &ready));
}

#[test]
fn process_mode_waits_do_not_block_worker_borrows_and_survive_replacement() {
    use crate::scan::worker_wire::encode_worker_frame;
    use std::thread;
    use std::time::Duration;

    // Direct Process tests miss the ownership mutex above the transport.
    // Hold both the pipe write and the ACK while a real scheduled poll
    // borrows the worker, then cover serialized changes across replacement.
    struct ModeInput {
        writes: mpsc::Sender<Vec<u8>>,
        release: mpsc::Receiver<()>,
        shutdown: Vec<u8>,
    }
    impl io::Write for ModeInput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes != self.shutdown.as_slice() {
                self.writes.send(bytes.to_vec()).unwrap();
                self.release.recv().unwrap();
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn process() -> (Arc<Process>, mpsc::Receiver<Vec<u8>>, mpsc::Sender<()>) {
        let (writes, written) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let input = ModeInput {
            writes,
            release: released,
            shutdown: encode_worker_frame(&json!({"worker_command": "shutdown"})).unwrap(),
        };
        (Process::with_test_input(input), written, release)
    }
    fn borrow_on_scheduler(
        scheduler: &Arc<Scheduler>,
        engine: &Arc<Engine>,
        expected: &Arc<Process>,
        id: u64,
    ) -> (thread::JoinHandle<()>, mpsc::Receiver<bool>) {
        let scheduler = Arc::clone(scheduler);
        let engine = Arc::clone(engine);
        let expected = Arc::clone(expected);
        let (borrowed, received) = mpsc::channel();
        let task = thread::spawn(move || {
            scheduler.run(id, Origin::Foreground, &Cancellation::new(), |_| {
                Box::pin(async move {
                    let process = engine
                        .worker(&WorkerConfig {
                            space_poll_interval_ms: Some(1000),
                            space_status_report_interval_ms: Some(1000),
                        }, &Cancellation::new())
                        .await
                        .unwrap();
                    borrowed.send(Arc::ptr_eq(&process, &expected)).unwrap();
                })
            });
        });
        (task, received)
    }
    fn change(engine: &Arc<Engine>, mode: ProcessMode) -> thread::JoinHandle<io::Result<bool>> {
        let engine = Arc::clone(engine);
        thread::spawn(move || engine.set_process_mode(mode))
    }
    fn ack(process: &Process, mode: &str) {
        process.test_event(json!({"type": "process_mode_ack", "mode": mode, "applied": true}));
    }
    fn command(mode: &str) -> Vec<u8> {
        encode_worker_frame(&json!({"worker_command": "set_process_mode", "mode": mode})).unwrap()
    }

    let timeout = Duration::from_secs(10);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let scheduler = pool.install(Scheduler::new);
    let engine = Arc::new(Engine::new(PathBuf::from("unused-worker")));
    let (initial, writing, release) = process();
    engine.worker.lock().unwrap().process = Some(Arc::clone(&initial));
    let background = change(&engine, ProcessMode::Background);
    assert_eq!(writing.recv_timeout(timeout).unwrap(), command("background"));
    let (first, first_done) = borrow_on_scheduler(&scheduler, &engine, &initial, 1);
    let during_write = first_done.recv_timeout(timeout);
    release.send(()).unwrap();
    let (second, second_done) = borrow_on_scheduler(&scheduler, &engine, &initial, 2);
    let during_ack = second_done.recv_timeout(timeout);
    let high = change(&engine, ProcessMode::High);
    ack(&initial, "background");
    assert!(background.join().unwrap().unwrap());
    assert_eq!(writing.recv_timeout(timeout).unwrap(), command("high"));
    release.send(()).unwrap();
    ack(&initial, "high");
    assert!(high.join().unwrap().unwrap());
    first.join().unwrap();
    second.join().unwrap();
    assert!(during_write.expect("mode write held the worker ownership mutex"));
    assert!(during_ack.expect("mode ACK held the worker ownership mutex"));

    let normal = change(&engine, ProcessMode::Normal);
    assert_eq!(writing.recv_timeout(timeout).unwrap(), command("normal"));
    release.send(()).unwrap();
    let (replacement, replacement_writing, replacement_release) = process();
    {
        // Model worker() publishing its replacement under this same owner
        // lock, using the desired mode already published by the transition.
        let mut owner = engine.worker.lock().unwrap();
        assert!(matches!(owner.desired_mode, ProcessMode::Normal));
        replacement.test_event(json!({
            "type": "worker_ready", "process_mode": "normal", "process_mode_applied": true,
        }));
        owner.process = Some(Arc::clone(&replacement));
        initial.test_exit();
    }
    assert!(normal.join().unwrap().is_err());
    let final_change = change(&engine, ProcessMode::Background);
    assert_eq!(
        replacement_writing.recv_timeout(timeout).unwrap(),
        command("background"),
    );
    replacement_release.send(()).unwrap();
    ack(&initial, "normal"); // An obsolete ACK cannot rewrite the new owner's state.
    ack(&replacement, "background");
    assert!(final_change.join().unwrap().unwrap());
    let (borrowed, received) = borrow_on_scheduler(&scheduler, &engine, &replacement, 3);
    assert!(received.recv_timeout(timeout).unwrap());
    borrowed.join().unwrap();
    let cached_engine = Arc::clone(&engine);
    let (cached_done, cached_result) = mpsc::channel();
    let cached = thread::spawn(move || {
        cached_done.send(cached_engine.set_process_mode(ProcessMode::Background)).unwrap();
    });
    let cached_result = cached_result.recv_timeout(timeout);
    if cached_result.is_err() {
        // A cache regression must fail rather than leave this test's
        // writer/control thread blocked on an unexpected extra command.
        if replacement_writing.recv_timeout(timeout).is_ok() {
            replacement_release.send(()).unwrap();
            ack(&replacement, "background");
        } else {
            replacement.test_exit();
        }
    }
    cached.join().unwrap();
    assert!(cached_result.expect("applied mode cache was lost").unwrap());
    assert!(replacement_writing.try_recv().is_err());
    assert!(matches!(
        engine.worker.lock().unwrap().desired_mode,
        ProcessMode::Background,
    ));
}

#[test]
fn preflight_damage_keeps_a_proven_password_in_scan_and_extract() {
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};
    struct NoWake;
    impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
    for mode in [Mode::Scan, Mode::Extract] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(vec![], mode);
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let mut input = ArchiveInput::file("damaged.rar".into(), "rar".into(), "damaged".into());
        input.analysis.password_required = true;
        let logical = LogicalInput { input, password: Some(Arc::from("confirmed")),
            failure: Some(Failure::new(FailureKind::Damaged, "missing ENDARC")) };
        let mut shell = engine.shell.branch();
        let mut outcome = Outcome::default();
        let mut future = Box::pin(run.execute_input(logical, 1, DiscoverySource::Embedded,
            1, None, None, &run.candidates, &mut shell, &mut outcome));
        let waker = Waker::from(Arc::new(NoWake));
        let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
            panic!("preflight failure started worker execution");
        };
        let result = result.unwrap().result;
        assert_eq!(result.password.as_deref(), Some("confirmed"));
        assert_eq!(result.failure.unwrap().kind, FailureKind::Damaged);
        assert!(result.output.is_none());
    }
}

#[test]
fn verified_scan_finishes_without_starting_worker() {
    use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    let source = crate::test_support::temp_file("verified_scan", &encrypted_rar_fixture());
    let engine = Engine::new(source.with_extension("missing-worker.exe"));
    let request = Request::new(vec![source.clone()], Mode::Scan);
    let observer = |_: Event| {};
    let mut run = test_run(&engine, &request, &observer);
    Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
        Arc::from([Arc::from("secret")]), None, &engine.recent_passwords, None,
    );
    for projected in [false, true] {
        let path = source.to_string_lossy().into_owned();
        let mut input = ArchiveInput::file(path.clone(), "rar".into(), "encrypted".into());
        input.analysis.password_required = true;
        if projected {
            let extent = InputExtent { path, start: 0, end: Some(fs::metadata(&source).unwrap().len()) };
            let mut part = InputPart::range(extent.clone());
            part.volume_number = Some(1);
            part.canonical_name = "archive.part1.rar".into();
            input.mode = OpenMode::NativeVolumes;
            input.parts = Box::new([part]);
            input.volume_attempts = Some(Arc::new(VolumeAttemptPlan {
                sources: Box::new([extent]),
                layouts: Box::new([VolumeLayout {
                    slots: Box::new([VolumeSlot { number: 1, canonical_name: "archive.part1.rar".into(), domain: 0 }]),
                    minimum_slots: 0,
                }]),
                domains: Box::new([VolumeDomain { choices: Arc::new(vec![0]) }]),
                head_size_from_total: None,
                minimum_size: None,
                tail_totals: Box::default(),
            }));
        }
        let logical = LogicalInput { input, password: None, failure: None };
        let mut shell = engine.shell.branch();
        let mut outcome = Outcome::default();
        let executed = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.execute_input(logical, 1, DiscoverySource::Detection,
                1, None, None, &run.candidates, &mut shell, &mut outcome))
        }).unwrap();
        assert!(executed.result.failure.is_none(), "{:?}", executed.result.failure);
        assert_eq!(executed.result.encrypted, Some(true));
        assert_eq!(executed.result.password.as_deref(), Some("secret"));
        assert!(executed.input.volume_attempts.is_none());
        assert!(engine.worker.lock().unwrap().process.is_none());
    }
    release_reader_resources_under_roots(vec![source.to_string_lossy().into_owned()]).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn worker_failure_preserves_only_noncontradicted_strong_password() {
    use crate::scan::worker_wire::NativeWorkerFrameDecoder;
    struct Input(mpsc::Sender<Vec<u8>>);
    impl io::Write for Input {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.0.send(bytes.to_vec());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let source = crate::test_support::temp_file("verified_failure", &encrypted_rar_fixture());
    for (failure, kind, expected) in [
        ("unsupported_method", FailureKind::Unsupported, Some("secret")),
        ("encrypted_or_wrong_password", FailureKind::WrongPassword, None),
    ] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(Vec::new(), Mode::Extract);
        let output = source.with_extension("output");
        request.output_root = Some(output.clone());
        let observer = |_: Event| {};
        let mut run = test_run(&engine, &request, &observer);
        Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
            Arc::from([Arc::from("secret")]), None, &engine.recent_passwords, None,
        );
        let (sent, received) = mpsc::channel();
        let process = Process::with_test_input(Input(sent));
        engine.worker.lock().unwrap().process = Some(Arc::clone(&process));
        let responder = std::thread::spawn(move || {
            let bytes = received.recv().unwrap();
            let mut decoder = NativeWorkerFrameDecoder::default();
            let frames = decoder.feed(&bytes).unwrap();
            decoder.finish().unwrap();
            let request = &frames[0].summary;
            let id = &request["job_id"];
            process.test_event(json!({"type":"result", "job_id":id,
                "status":"error", "failure_kind":failure,
                "unsupported_method":failure == "unsupported_method",
                "failure_stage":"item_extract", "encrypted":true}));
            process.test_event(json!({"type":"native_event", "event":"job_finished", "job_id":id}));
            request.clone()
        });
        let mut input = ArchiveInput::file(source.to_string_lossy().into_owned(), "rar".into(), "encrypted".into());
        input.analysis.password_required = true;
        // No discovery-supplied password: only the real probe's strong
        // plan can populate the failed result, not an existing receipt.
        let logical = LogicalInput { input, password: None, failure: None };
        let mut shell = engine.shell.branch();
        let mut outcome = Outcome::default();
        let result = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.execute_input(logical, 1, DiscoverySource::Embedded,
                1, None, None, &run.candidates, &mut shell, &mut outcome))
        }).unwrap().result;
        let submitted = responder.join().unwrap();
        assert_eq!(submitted["password_verified"], true);
        assert_eq!(submitted["password"], "secret");
        assert_eq!(result.failure.unwrap().kind, kind);
        assert_eq!(result.password.as_deref(), expected);
        fs::remove_dir(output).unwrap();
    }
    release_reader_resources_under_roots(vec![source.to_string_lossy().into_owned()]).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn recovery_selection_uses_unique_physical_anchors_without_io() {
    let source = crate::test_support::temp_file("recovery_anchor", b"existing second volume");
    let mut old = ArchiveInput::file(source.to_string_lossy().into_owned(), "7z".into(), "old".into());
    let generations = HashMap::from([(path_key(&old.entry_path), capture_file_generation(&source).unwrap())]);
    let result = receipt(&old, DiscoverySource::Relations, 1);
    let mut checkpoint = InputCheckpoint::create(&source, Arc::new(old.clone()), &result, &generations, None).unwrap();
    checkpoint.install_report(InputCheckpoint::report_state(&old, &result, None, None, 4, 7));
    let mut arrived = old.clone();
    // Relations can choose an arriving first volume as the new entry while
    // retaining the previous second volume as a physical source anchor.
    arrived.entry_path = source.with_extension("first").to_string_lossy().into_owned();
    arrived.parts = Box::new([crate::io::archive_state::InputPart::range(
        crate::io::archive_state::InputExtent { path: old.entry_path.clone(), start: 0, end: None })]);
    let logical = |input| LogicalInput { input, password: None, failure: None };
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let observer = |_: Event| {};
    let mut request = Request::new(Vec::new(), Mode::Extract);
    request.checkpoints.push(checkpoint);
    let mut run = test_run(&engine, &request, &observer);
    Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&source.to_string_lossy()))).or_default().insert(request.checkpoints[0].key(), 0);
    let exact = run.select_checkpoints(&source, &[logical(old.clone())]);
    assert_eq!(exact[0].unwrap().report_position(), Some(4));
    assert!(run.checkpoint_anchors.get().is_none(), "exact identity must not build an anchor index");
    let matched = run.select_checkpoints(&source, &[logical(arrived.clone())]);
    assert_eq!(matched[0].unwrap().report_position(), Some(4));
    assert!(!matched[0].unwrap().valid_for(&arrived, &generations), "identity must not bypass layout validation");
    let consumed = run.select_checkpoints(&source, &[logical(old.clone()), logical(arrived.clone())]);
    assert!(consumed[0].is_some() && consumed[1].is_none());
    let mut different_format = arrived.clone(); different_format.format_hint = "zip".into();
    assert!(run.select_checkpoints(&source, &[logical(different_format)])[0].is_none());
    let mut different_offset = arrived.clone(); different_offset.parts[0].extent.start = 1;
    assert!(run.select_checkpoints(&source, &[logical(different_offset)])[0].is_none());
    old.mode = crate::io::archive_state::OpenMode::FileRange;
    assert!(run.select_checkpoints(&source, &[logical(old.clone())])[0].is_some(), "mode is not logical identity");
    // Remapping the descriptor does not replace its stable logical ID.
    let mut remapped_result = receipt(&arrived, DiscoverySource::Relations, 1);
    remapped_result.source_paths = vec![source.clone()];
    let mut remapped = InputCheckpoint::create(&source, Arc::new(arrived.clone()), &remapped_result, &generations, None).unwrap();
    remapped.install_report(InputCheckpoint::report_state(&arrived, &remapped_result, None,
        Some(&request.checkpoints[0]), 1, 1));
    let mut remapped_request = Request::new(Vec::new(), Mode::Extract);
    remapped_request.checkpoints.push(remapped);
    let mut remapped_run = test_run(&engine, &remapped_request, &observer);
    Arc::get_mut(&mut remapped_run).unwrap().checkpoints.entry(Arc::from(path_key(&source.to_string_lossy()))).or_default().insert(remapped_request.checkpoints[0].key(), 0);
    assert_eq!(remapped_run.select_checkpoints(&source, &[logical(old.clone())])[0].unwrap().report_position(), Some(4));
    assert!(remapped_run.checkpoint_anchors.get().is_none());
    let changed_carrier = source.with_extension("arrived-carrier");
    assert_eq!(run.select_checkpoints(&changed_carrier, &[logical(arrived.clone())])[0].unwrap().report_position(), Some(4));
    // Watch batches carry several owners' receipts. Shared bytes never
    // authorize taking another physical task's identity or output slot.
    let other_carrier = source.with_extension("other-carrier");
    let other_result = receipt(&old, DiscoverySource::Relations, 1);
    let mut other_group = InputCheckpoint::create(&other_carrier, Arc::new(old.clone()), &other_result, &generations, None).unwrap();
    other_group.install_report(InputCheckpoint::report_state(&old, &other_result, None, None, 9, 9));
    let mut grouped_request = request.clone();
    grouped_request.checkpoints.push(other_group);
    let mut grouped = test_run(&engine, &grouped_request, &observer);
    for (index, checkpoint) in grouped_request.checkpoints.iter().enumerate() {
        Arc::get_mut(&mut grouped).unwrap().checkpoints
            .entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy())))
            .or_default().insert(checkpoint.key(), index);
    }
    assert_eq!(grouped.select_checkpoints(&source, &[logical(arrived.clone())])[0].unwrap().report_position(), Some(4));
    assert_eq!(grouped.select_checkpoints(&other_carrier, &[logical(arrived.clone())])[0].unwrap().report_position(), Some(9));
    assert!(grouped.select_checkpoints(&changed_carrier, &[logical(arrived.clone())])[0].is_none(),
        "ambiguous prior carrier must not be guessed");
    // Two distinct old logical identities sharing this anchor are ambiguous.
    let mut other = arrived.clone(); other.entry_path.push_str("-other");
    let mut other_result = receipt(&other, DiscoverySource::Relations, 1);
    other_result.source_paths = vec![source.clone()];
    let other = InputCheckpoint::create(&source, Arc::new(other.clone()), &other_result, &generations, None).unwrap();
    request.checkpoints.push(other);
    let mut ambiguous = test_run(&engine, &request, &observer);
    for (index, checkpoint) in request.checkpoints.iter().enumerate() {
        Arc::get_mut(&mut ambiguous).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
    }
    assert!(ambiguous.select_checkpoints(&source, &[logical(arrived)])[0].is_none());
    fs::remove_file(source).unwrap();
}

#[test]
fn password_failure_keeps_real_planned_output_after_cleanup() {
    let source = crate::test_support::temp_file("password_output_order", &encrypted_rar_fixture());
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let request = Request::new(Vec::new(), Mode::Extract);
    let observer = |_: Event| {};
    let run = test_run(&engine, &request, &observer);
    let mut input = ArchiveInput::file(source.to_string_lossy().into_owned(), "rar".into(), "encrypted".into());
    input.analysis.password_required = true;
    let logical = LogicalInput { input, password: None, failure: None };
    let mut shell = engine.shell.branch();
    let mut outcome = Outcome::default();
    let executed = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
        Box::pin(run.execute_input(logical, 1, DiscoverySource::Embedded,
            1, None, None, &run.candidates, &mut shell, &mut outcome))
    }).unwrap();
    assert!(matches!(executed.result.failure.as_ref().unwrap().context.as_deref(),
        Some(super::super::FailureContext::PasswordResolution)));
    let output = executed.planned_output.as_ref().expect("output reserved before password resolution");
    assert!(!output.exists(), "failed password output was not cleaned");
    assert!(executed.result.output.is_none());
    assert!(InputCheckpoint::report_state(&executed.input, &executed.result,
        Some(output), None, 1, 1).is_some());
    release_reader_resources_under_roots(vec![source.to_string_lossy().into_owned()]).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn completed_cleanup_retires_jobs_and_keeps_only_failures() {
    let tasks = Arc::new(Mutex::new(CleanupTasks::default()));
    Scheduler::new().run(1, Origin::Foreground, &Cancellation::new(), |spawner| {
        let tasks = Arc::clone(&tasks);
        Box::pin(async move {
            for id in 0..32 {
                let completed = Arc::clone(&tasks);
                let mut pending = tasks.lock().unwrap();
                let task = spawner.spawn(Box::pin(async move {
                    let failures = if id == 0 {
                        cleanup_failure(Path::new("source.zip"), "delete", Err(io::ErrorKind::PermissionDenied.into()))
                            .into_iter().collect()
                    } else {
                        Vec::new()
                    };
                    completed.lock().unwrap().retire(id, failures)
                }));
                pending.register(id, vec![Arc::from("source.zip")], task);
            }
        })
    });
    let mut tasks = tasks.lock().unwrap();
    assert!(tasks.active.is_empty() && tasks.by_path.is_empty());
    assert!(tasks.take_failures(Some("other")).is_empty());
    let failures = tasks.take_failures(None);
    let [failure] = failures.as_slice() else { panic!("expected one failed cleanup") };
    assert_eq!(failure.path, Path::new("source.zip"));
    assert_eq!(failure.status, CleanupStatus::Failed);

    for (id, paths) in [
        (32, &["out\\first.zip", "out\\second.zip", "external.zip"][..]),
        (33, &["out (2)\\sibling.zip"][..]),
    ] {
        tasks.register(id, paths.iter().copied().map(Arc::from).collect(), super::super::scheduling::Join::ready(Vec::new()));
    }
    assert_eq!(tasks.take_pending(Some("out")).len(), 1);
    assert!(tasks.take_pending(Some("external.zip")).is_empty());
    assert_eq!(tasks.take_pending(Some("out (2)")).len(), 1);
    assert!(tasks.active.is_empty() && tasks.by_path.is_empty());
}

fn test_run<'a, O: Observer>(
    engine: &'a Engine,
    request: &'a Request,
    observer: &'a O,
) -> Arc<Run<'a, O>> {
    Arc::new(Run {
        engine: engine.clone(),
        request: Arc::new(request.clone()),
        resolve_aliases: false,
        candidates: CandidateSet::new(Arc::from([]), None, &engine.recent_passwords, None),
        options: OnceLock::new(),
        deep_options: None,
        observer: ObserverRef::Borrowed(observer),
        recursion: RecursivePrompts::default(),
        output_names: OutputReservationGuard { registry: Arc::clone(&engine.output_names), owner: 1 },
        created_outputs: Mutex::default(),
        output_base: None,
        checkpoints: HashMap::new(),
        checkpoint_anchors: OnceLock::new(),
        generated_sources: HashMap::new(),
        cleanup_boundaries: cleanup_boundaries(request),
        scan_errors: Mutex::new(DirectoryReadErrors::report()),
        cleanup_tasks: Mutex::default(),
        cleanup_refs: Arc::default(),
    })
}

#[test]
fn replacement_worker_spawn_failure_preserves_start_classification() {
    let source = crate::test_support::temp_file("replacement_worker", b"archive");
    let engine = Engine::new(source.with_extension("missing-worker.exe"));
    let initial = Process::with_test_input(Vec::new());
    engine.worker.lock().unwrap().process = Some(Arc::clone(&initial));
    let request = Request::new(vec![source.clone()], Mode::Scan);
    let observer = |event: Event| {
        if matches!(event, Event::Waiting { .. }) { initial.test_exit(); }
    };
    let run = test_run(&engine, &request, &observer);
    let logical = LogicalInput {
        input: ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into()),
        password: None, failure: None,
    };
    let mut shell = engine.shell.branch();
    let mut outcome = Outcome::default();
    let result = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
        Box::pin(async {
            // The first borrow and handshake succeed inside this request.
            let started = engine.worker(&request.config.performance.worker, &request.cancel).await.unwrap();
            assert!(Arc::ptr_eq(&started, &initial));
            run.execute_input(logical, 1, DiscoverySource::Embedded, 1, None, None,
                &run.candidates, &mut shell, &mut outcome).await
        })
    }).unwrap().result;
    let failure = result.failure.unwrap();
    assert_eq!(failure.kind, FailureKind::ProcessError);
    let evidence = failure.evidence.unwrap();
    assert_eq!(evidence.native_kind.as_deref(), Some("process_start"));
    assert_eq!(evidence.stage.as_deref(), Some("worker_start"));
    assert!(!failure.message.is_empty());
    assert!(!Arc::ptr_eq(engine.worker.lock().unwrap().process.as_ref().unwrap(), &initial));
    fs::remove_file(source).unwrap();
}

#[test]
fn watch_family_join_preserves_owner_and_propagates_infrastructure_error() {
    use std::future::Future;
    use std::task::Context;

    let first = crate::test_support::temp_file("join_watch_first_head", b"first");
    let second = crate::test_support::temp_file("join_watch_second_head", b"second");
    let tail1 = crate::test_support::temp_file("join_watch_tail1", b"common tail 1");
    let tail2 = crate::test_support::temp_file("join_watch_tail2", b"common tail 2");
    let task = |path: &Path| Task {
        primary: None,
        owned_paths: [path, &tail1, &tail2].into_iter()
            .map(|member| member.to_string_lossy().into_owned()).collect(),
        inputs: vec![LogicalInput { password: None,
            input: ArchiveInput::file(path.to_string_lossy().into_owned(), "7z".into(), "split".into()),
            failure: None }],
        source: DiscoverySource::Relations, context: None,
    };
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let leases = &engine.leases;
    let mut request = Request::new(vec![tail1.clone()], Mode::Extract);
    request.origin = Origin::Watch;
    let leader = Arc::new(request.clone());
    let follower = Arc::new(Request {
        inputs: vec![tail2.clone()], cancel: Cancellation::new(), ..request.clone()
    });
    let notify = |_: Event| {};
    let members = test_run(&engine, &leader, &notify).watch_generations(&Discovered {
        tasks: vec![task(&first), task(&second)], ..Discovered::default()
    }).expect("two logical roots can share one physical generation union");
    let follower_members = test_run(&engine, &follower, &notify).watch_generations(&Discovered {
        tasks: vec![task(&second), task(&first)], ..Discovered::default()
    }).unwrap();
    assert_eq!(members.len(), 4);
    let mut cx = Context::from_waker(Waker::noop());

    let WatchFamily::Owner(owner) = leases.claim_watch(1, &members, &leader) else {
        panic!("first request owns extraction");
    };
    let different_policy = Arc::new(Request { deep: true, ..request });
    let WatchFamily::Owner(other) = leases.claim_watch(2, &members, &different_policy) else {
        panic!("different policy must execute independently");
    };
    let WatchFamily::Follower(key, id, settlement) = leases.claim_watch(3, &follower_members, &follower) else {
        panic!("equivalent request must join the active owner");
    };
    assert_eq!(id, 1);
    let mut wait = Box::pin(leases.join_watch(&key, id, &settlement, &follower.cancel));
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    follower.cancel.cancel();
    assert!(matches!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    drop(wait);
    assert!(!leader.cancel.cancelled());

    let uncancelled = Cancellation::new();
    let mut wait = Box::pin(leases.join_watch(&key, id, &settlement, &uncancelled));
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    owner.finish(&Err(io::Error::other("write failed")), &leader.cancel);
    // A replacement owner can register before existing followers wake.
    let WatchFamily::Owner(owner) = leases.claim_watch(4, &members, &leader) else {
        panic!("failed owner must retire");
    };
    let Poll::Ready(Err(error)) = wait.as_mut().poll(&mut cx) else {
        panic!("infrastructure error must propagate to the waiting follower");
    };
    assert_eq!(error.to_string(), "write failed");
    drop(wait);
    drop(owner);
    drop(other);
    let state = leases.state.lock().unwrap();
    assert!(state.watch.is_empty() && state.waiters.is_empty() && state.blocked_by.is_empty());
    drop(state);
    for source in [first, second, tail1, tail2] { fs::remove_file(source).unwrap(); }
}

#[test]
fn completed_watch_family_returns_existing_success_without_extracting_or_reowning_output() {
    struct Reuse {
        output: PathBuf,
        events: Mutex<Vec<Event>>,
        queries: std::sync::atomic::AtomicUsize,
    }
    impl Observer for Reuse {
        fn notify(&self, event: Event) { self.events.lock().unwrap().push(event); }
        fn completed_sources(&self, generations: &HashMap<String, PhysicalFileGeneration>) -> io::Result<Option<PathBuf>> {
            if !self.output.is_dir() { return Ok(None); }
            assert_eq!(generations.len(), 2);
            self.queries.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.output.clone()))
        }
        fn register_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
            panic!("completed output must not be created again")
        }
        fn reuse_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
            panic!("completed output must not acquire a second durable owner")
        }
        fn after_output(&self, _: &ArchiveResult) -> io::Result<()> {
            panic!("completed output must not be republished")
        }
    }
    let head = crate::test_support::temp_file("completed_family_head", b"head");
    let tail = crate::test_support::temp_file("completed_family_tail", b"tail");
    let launcher = crate::test_support::temp_file("completed_family_launcher", b"standalone executable");
    let output = head.with_extension("existing-output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("damaged-inner.zip"), b"retained terminal inner failure").unwrap();
    let engine = Engine::new(PathBuf::from("must-not-start-worker.exe"));
    let mut request = Request::new(vec![tail.clone()], Mode::Extract);
    request.origin = Origin::Watch;
    let observer = Reuse { output: output.clone(), events: Mutex::default(), queries: 0.into() };
    let run = test_run(&engine, &request, &observer);
    let mut input = ArchiveInput::file(head.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    input.mode = OpenMode::NativeVolumes;
    input.parts = [&head, &tail].map(|path| crate::io::archive_state::InputPart::range(
        crate::io::archive_state::InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: None },
    )).into();
    let task = Task {
        primary: None, owned_paths: [&head, &tail, &launcher].map(|path| path.to_string_lossy().into_owned()).into(),
        inputs: vec![LogicalInput {
            input,
            password: None, failure: None }],
        source: DiscoverySource::Relations, context: None,
    };
    let (generations, missing) = run.capture_generations(&task);
    assert_eq!(generations.len(), 3, "launcher remains owned for cleanup");
    assert_eq!(run.requested_generation(&task, true).unwrap().len(), 2);
    // Foreground/nested tasks and incomplete observations do not consume
    // the Watch-only completed family fact.
    assert!(matches!(run.task_admission(&task, &generations, &[], false, |_| None).unwrap(), TaskAdmission::Execute(None)));
    let mut partial = generations.clone();
    partial.remove(&path_key(&tail.to_string_lossy()));
    assert!(matches!(run.task_admission(&task, &partial, &[tail.clone()], true, |_| None).unwrap(), TaskAdmission::Execute(None)));
    assert!(matches!(run.task_admission(&task, &HashMap::new(), &[head.clone(), tail.clone()], true, |_| None).unwrap(), TaskAdmission::Departed));
    let single = Task { primary: None, owned_paths: vec![head.to_string_lossy().into_owned()],
        inputs: vec![LogicalInput {
            input: ArchiveInput::file(head.to_string_lossy().into_owned(), "zip".into(), "archive".into()),
            password: None, failure: None }],
        source: DiscoverySource::Relations, context: None };
    assert!(matches!(run.task_admission(&single, &partial, &[], true, |_| None).unwrap(), TaskAdmission::Execute(None)));
    assert_eq!(observer.queries.load(Ordering::SeqCst), 0);
    assert!(matches!(run.task_admission(&task, &partial, &[tail.clone()], true, |path| generations.get(path)).unwrap(),
        TaskAdmission::Completed(ref path) if path == &output));
    assert!(matches!(run.task_admission(&task, &HashMap::new(), &[head.clone(), tail.clone()], true,
        |path| generations.get(path)).unwrap(), TaskAdmission::Departed));
    let changed = HashMap::from([(path_key(&head.to_string_lossy()), generations[&path_key(&tail.to_string_lossy())].clone())]);
    assert!(matches!(run.task_admission(&task, &changed, &[tail.clone()], true, |path| generations.get(path)).unwrap(), TaskAdmission::Execute(None)));
    assert_eq!(observer.queries.swap(0, Ordering::SeqCst), 1);
    assert!(missing.is_empty());
    // A successful worker can select only two of three candidate sources.
    // The cache must store the complete admitted set and omit the unrelated
    // executable. Do not derive its key from the successful worker output.
    let alternative = crate::test_support::temp_file("completed_family_alternative", b"candidate");
    let mut alternative_input = task.entry().clone();
    alternative_input.volume_attempts = Some(Arc::new(crate::io::archive_state::VolumeAttemptPlan {
        sources: [&head, &tail, &alternative].map(|path| crate::io::archive_state::InputExtent {
            path: path.to_string_lossy().into_owned(), start: 0, end: None,
        }).into(),
        layouts: Box::new([]), domains: Box::new([]), head_size_from_total: None,
        minimum_size: None, tail_totals: Box::new([]),
    }));
    let alternative_task = Task {
        primary: None,
        owned_paths: [&head, &tail, &alternative, &launcher].map(|path| path.to_string_lossy().into_owned()).into(),
        inputs: vec![LogicalInput { input: alternative_input, password: None, failure: None }],
        source: DiscoverySource::Relations, context: None,
    };
    let uncached = Reuse { output: output.join("absent"), events: Mutex::default(), queries: 0.into() };
    let uncached = test_run(&engine, &request, &uncached);
    let (physical, missing) = uncached.capture_generations(&alternative_task);
    let TaskAdmission::Execute(Some(cache_key)) = uncached.task_admission(
        &alternative_task, &physical, &missing, true, |_| None,
    ).unwrap() else { panic!("uncached speculative family should execute"); };
    let candidate_paths = [&head, &tail, &alternative].map(|path| path_key(&path.to_string_lossy()));
    assert_eq!(cache_key.len(), candidate_paths.len());
    assert!(candidate_paths.iter().all(|path| cache_key.contains_key(path)));
    fs::remove_file(alternative).unwrap();
    let outcome = Scheduler::new().run(1, Origin::Watch, &request.cancel, |spawner| {
        run.execute_task(run.register_task(task), 1, 1, None, spawner)
    }).unwrap();
    assert_eq!(observer.queries.load(Ordering::SeqCst), 1);
    assert_eq!(outcome.archives.len(), 1);
    let reused = &outcome.archives[0];
    assert_eq!(reused.path, head);
    assert_eq!(reused.output.as_ref(), Some(&output));
    assert_eq!(reused.source_paths, [head.clone(), tail.clone(), launcher.clone()]);
    assert!(reused.failure.is_none() && !reused.partial);
    assert_eq!(reused.files, 0); // No invented member inventory/count.
    assert!(outcome.cleanup_results.is_empty());
    assert!(outcome.checkpoints.is_empty());
    assert!(run.created_outputs.lock().unwrap().0.is_empty());
    assert!(run.cleanup_refs.lock().unwrap().paths.is_empty());
    assert!(matches!(observer.events.lock().unwrap().as_slice(),
        [Event::Finished { id: 1, result, .. }] if result.output.as_ref() == Some(&output)));
    assert_eq!(fs::read(output.join("damaged-inner.zip")).unwrap(), b"retained terminal inner failure");
    assert!(launcher.is_file());
    fs::remove_dir_all(output).unwrap();
    fs::remove_file(head).unwrap();
    fs::remove_file(tail).unwrap();
    fs::remove_file(launcher).unwrap();
}

#[test]
fn partial_departure_fails_admission_and_keeps_generations_for_extraction() {
    let path = crate::test_support::temp_file("partial_departure", b"archive");
    let missing = path.with_extension("missing");
    for (mode, count) in [Mode::Scan, Mode::Extract].into_iter()
        .flat_map(|mode| [1, 2].map(|count| (mode, count))) {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        assert_eq!(engine.next_id(), 1); // Reserve the parent observer ID.
        let request = Request::new(vec![path.clone()], mode);
        let events = Mutex::new(Vec::new());
        let observer = |event: Event| { events.lock().unwrap().push(event); };
        let run = test_run(&engine, &request, &observer);
        let mut input = ArchiveInput::file(path.to_string_lossy().into_owned(), "rar".into(), "archive".into());
        input.mode = OpenMode::NativeVolumes;
        input.parts = [&path, &missing].map(|path| crate::io::archive_state::InputPart::range(
            crate::io::archive_state::InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: None },
        )).into();
        let companion = missing.with_extension("exe");
        let mut task = Task {
            primary: None,
            owned_paths: [&path, &missing, &companion].map(|path| path.to_string_lossy().into_owned()).into(),
            inputs: vec![LogicalInput {
                input,
                password: None, failure: None,
            }],
            source: DiscoverySource::Relations,
            context: Some(discovery::TaskContext::Report(Arc::new(crate::scan::scope::NativeDiscoveryScope::new(
                path.parent().unwrap().to_string_lossy().into_owned(), Some(0), Vec::new())))),
        };
        let (generations, absent) = run.capture_generations(&task);
        assert_eq!(absent, vec![missing.clone()]);
        match mode {
            Mode::Scan => assert!(generations.is_empty()),
            Mode::Extract => {
                assert_eq!(generations.len(), 1);
                assert_eq!(generations[&path_key(&path.to_string_lossy())], capture_file_generation(&path).unwrap());
            }
        }
        assert!(matches!(run.task_admission(&task, &generations, &absent, false, |_| None).unwrap(), TaskAdmission::Execute(None)));
        task.inputs[0].failure = Some(Failure::new(FailureKind::Unsupported, "discovery")
            .with_context(super::super::FailureContext::Discovery {
                discovery: DiscoverySource::Embedded, reason: "unsupported".into(),
                path: path.clone(), error: String::new(),
            }));
        run.admit_missing_inputs(&mut task, &absent);
        assert_eq!(task.inputs[0].failure.as_ref().unwrap().kind, FailureKind::Unsupported);
        let input = task.inputs[0].input.clone();
        task.inputs.push(LogicalInput { input, password: None, failure: None });
        run.admit_missing_inputs(&mut task, &absent);
        assert!(task.inputs.iter().all(|logical| matches!(logical.failure.as_ref().unwrap().context.as_deref(),
            Some(super::super::FailureContext::InputAdmission { .. }))));
        task.inputs.pop();
        task.inputs[0].failure = None;
        if count == 2 {
            let input = task.inputs[0].input.clone();
            task.inputs.push(LogicalInput { input, password: Some(Arc::from("known")), failure: None });
            task.inputs[0].failure = Some(Failure::new(FailureKind::Unsupported, "discovery")
                .with_context(super::super::FailureContext::Discovery {
                    discovery: DiscoverySource::Embedded, reason: "unsupported".into(),
                    path: path.clone(), error: String::new(),
                }));
        }
        let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
            run.execute_task(run.register_task(task), 1, 1, None, spawner)
        }).unwrap();
        assert_eq!(outcome.archives.len(), if mode == Mode::Scan { count } else { 1 });
        let events = events.lock().unwrap();
        assert_eq!(events.iter().filter(|event| matches!(event, Event::Started { .. })).count(), 1);
        assert_eq!(events.iter().filter(|event| matches!(event, Event::Finished { .. })).count(), if count > 1 { count + 1 } else { 1 });
        assert_eq!(events.iter().filter(|event| matches!(event, Event::Queued { .. })).count(), if count > 1 { count } else { 0 });
        assert!(events.iter().any(|event| matches!(event, Event::Finished { result, .. }
            if result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::MissingVolume))));
        if count == 2 {
            // main keeps a discovery-blocked segment visible and marks
            // the otherwise unexecuted sibling skipped after admission.
            assert!(events.iter().any(|event| matches!(event, Event::Finished { id, result, .. }
                if *id != 1 && result.status == super::super::TaskStatus::Skipped)));
            assert!(events.iter().any(|event| matches!(event, Event::Finished { id, result, .. }
                if *id != 1 && result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::Unsupported))));
        }
        if mode == Mode::Scan && count == 2 {
            assert_eq!(outcome.archives[0].failure.as_ref().unwrap().kind, FailureKind::Unsupported);
            assert_eq!(outcome.archives[1].password.as_deref(), Some("known"));
        }
        let failure = outcome.archives.last().unwrap().failure.as_ref().unwrap();
        assert_eq!(failure.kind, FailureKind::MissingVolume);
        assert!(matches!(failure.context.as_deref(), Some(super::super::FailureContext::InputAdmission { missing_paths }) if missing_paths == &[missing.clone()]));
        assert_eq!(failure.discovery_scope.is_some(), mode == Mode::Extract);
        assert!(path.exists());
    }
    fs::remove_file(path).unwrap();
}

#[test]
fn carrier_completion_keeps_split_warning_but_suppresses_segment_aggregate_detail() {
    let input = ArchiveInput::file("carrier.bin".into(), "zip".into(), "archive".into());
    let mut results = vec![receipt(&input, DiscoverySource::Embedded, 1), receipt(&input, DiscoverySource::Embedded, 1)];
    results[0].failure = Some(Failure::new(FailureKind::Damaged, "segment damaged"));
    results[1].failure = Some(Failure::new(FailureKind::Unsupported, "segment unsupported"));
    let completion = super::super::TaskCompletion::from_group(&results);
    assert_eq!(completion.status, super::super::TaskStatus::Failed);
    assert!(completion.failure.is_none());
    results[1].failure.as_mut().unwrap().evidence = Some(Box::new(super::super::FailureEvidence {
        possible_missing_volume: true, ..Default::default()
    }));
    let completion = super::super::TaskCompletion::from_group(&results);
    assert!(completion.failure.as_ref().unwrap().evidence.as_ref().unwrap().possible_missing_volume);

}

#[test]
fn discovery_blocked_tasks_register_display_segments_without_executing_them() {
    let path = crate::test_support::temp_file("discovery_preflight", b"carrier");
    for (mode, count) in [Mode::Scan, Mode::Extract].into_iter()
        .flat_map(|mode| [1, 2].map(|count| (mode, count))) {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        assert_eq!(engine.next_id(), 1); // Reserve the parent observer ID.
        let request = Request::new(vec![path.clone()], mode);
        let events = Mutex::new(Vec::new());
        let observer = |event: Event| { events.lock().unwrap().push(event); };
        let run = test_run(&engine, &request, &observer);
        let inputs = (0..count).map(|index| LogicalInput {
            input: ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), "carrier".into()),
            password: Some(Arc::from("known")),
            failure: Some(Failure::new(if index == 0 { FailureKind::Unsupported } else { FailureKind::Damaged },
                "discovery detail").with_context(super::super::FailureContext::Discovery {
                    discovery: DiscoverySource::Embedded, reason: "unsupported".into(),
                    path: path.clone(), error: "discovery detail".into(),
                })),
        }).collect();
        let task = Task {
            primary: None, inputs, owned_paths: vec![path.to_string_lossy().into_owned()],
            source: DiscoverySource::Embedded,
            context: Some(discovery::TaskContext::Report(Arc::new(crate::scan::scope::NativeDiscoveryScope::new(
                path.parent().unwrap().to_string_lossy().into_owned(), Some(0), Vec::new())))),
        };
        let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner|
            run.execute_task(run.register_task(task), 1, 1, None, spawner)).unwrap();
        assert_eq!(outcome.archives.len(), count);
        for (index, result) in outcome.archives.iter().enumerate() {
            assert_eq!(result.failure.as_ref().unwrap().kind,
                if index == 0 { FailureKind::Unsupported } else { FailureKind::Damaged });
            assert_eq!(result.failure.as_ref().unwrap().discovery_scope.is_some(), mode == Mode::Extract);
            assert_eq!(result.password.as_deref(), Some("known"));
            assert!(result.output.is_none());
        }
        let events = events.lock().unwrap();
        assert_eq!(events.iter().filter(|event| matches!(event, Event::Started { .. })).count(), 1);
        assert_eq!(events.iter().filter(|event| matches!(event, Event::Finished { .. })).count(), if count > 1 { count + 1 } else { 1 });
        assert_eq!(events.iter().filter(|event| matches!(event, Event::Queued { .. })).count(), if count > 1 { count } else { 0 });
        assert!(events.iter().any(|event| matches!(event, Event::Finished { result, .. }
            if result.status == super::super::TaskStatus::Failed)));
    }
    fs::remove_file(path).unwrap();
}

#[test]
fn replacement_display_reuses_parent_or_registers_retained_failure_without_execution() {
    let source = crate::test_support::temp_file("replacement_display", &[0; 16]);
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "carrier".into());
    let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
    let mut result = receipt(&input, DiscoverySource::Detection, 1);
    result.failure = Some(Failure::new(FailureKind::MissingVolume, "first attempt"));
    let mut checkpoint = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap();
    checkpoint.install_report(InputCheckpoint::report_state(&input, &result, None, None, 1, 1));
    let engine = Engine::new(PathBuf::from("unused-worker"));
    assert_eq!(engine.next_id(), 1);
    let request = Request::new(vec![source.clone()], Mode::Extract);
    let events = Mutex::new(Vec::new());
    let observer = |event: Event| { events.lock().unwrap().push(event); };
    let run = test_run(&engine, &request, &observer);
    assert_eq!(run.replan_input(1, &input, Some(&checkpoint)), (1, None));
    assert!(matches!(events.lock().unwrap().as_slice(), [Event::Replanned { id: 1, .. }]));
    events.lock().unwrap().clear();
    let mut replacement = input.clone();
    replacement.entry_path = source.with_extension("first").to_string_lossy().into_owned();
    let (active, retained) = run.replan_input(1, &replacement, Some(&checkpoint));
    let retained = retained.unwrap();
    assert_ne!(active, 1);
    assert_ne!(active, retained);
    let events = events.lock().unwrap();
    assert!(matches!(&events[0], Event::Replanned { id: 1, .. }));
    assert!(matches!(&events[1], Event::Queued { id, parent: Some(1), .. } if *id == active));
    assert!(matches!(&events[2], Event::Queued { id, parent: Some(1), .. } if *id == retained));
    assert!(matches!(&events[3], Event::Finished { id, result, .. } if *id == retained
        && result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::MissingVolume)));
    assert!(matches!(&events[4], Event::Started { id, .. } if *id == active));
    assert_eq!(events.len(), 5);
    fs::remove_file(source).unwrap();
}

#[test]
fn retry_panel_uses_checkpoint_positions_without_creating_execution_work() {
    let source = crate::test_support::temp_file("panel_retry_positions", &[0; 16]);
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "carrier".into());
    let inputs: Vec<_> = archive_input_slices(&input, &[
        ("zip", 0, Some(8)), ("zip", 8, Some(16)),
    ]).unwrap().0.into_iter().map(Option::unwrap).collect();
    let generations = HashMap::from([
        (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
    ]);
    let mut result = receipt(&inputs[0], DiscoverySource::Embedded, 1);
    let output = source.with_extension("out");
    result.output = Some(output.clone());
    let mut checkpoint = InputCheckpoint::create(&source, Arc::new(inputs[0].clone()), &result, &generations, None).unwrap();
    checkpoint.install_report(InputCheckpoint::report_state(&inputs[0], &result,
        Some(&output), None, 4, 7));
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let request = Request::new(vec![source.clone()], Mode::Extract);
    let events = Mutex::new(Vec::new());
    let observer = |event: Event| { events.lock().unwrap().push(event); };
    let run = test_run(&engine, &request, &observer);
    let task = Task {
        primary: None, owned_paths: vec![input.entry_path.clone()],
        inputs: inputs.into_iter().map(|input| LogicalInput { input, password: None, failure: None }).collect(),
        source: DiscoverySource::Embedded, context: None,
    };
    let ids = run.queue_inputs(&task, 1000, &[Some(&checkpoint), None], true);
    assert_eq!(ids.len(), 2);
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2);
    for (event, position) in events.iter().zip([2, 4]) {
        assert!(matches!(event, Event::Queued { parent: Some(1000), segment: Some(segment), .. }
            if segment.index == position));
    }
    assert!(matches!(&events[0], Event::Queued { id, .. } if *id == ids[1]));
    assert!(matches!(&events[1], Event::Queued { id, .. } if *id == ids[0]));
    // Both retained and retry candidates have display rows; queue_inputs
    // emits no Started/Finished and never creates worker/scheduler tasks.
    fs::remove_file(source).unwrap();
}

#[test]
fn departed_discovered_tasks_skip_before_started_across_modes_and_depths() {
    // Exercise the real task boundary, not just its predicate: no worker,
    // Started event, or failed receipt may be produced for a stale proposal.
    let path = crate::test_support::temp_file("departed_proposal", b"archive");
    let input = ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    fs::remove_file(&path).unwrap();
    for mode in [Mode::Scan, Mode::Extract] {
        for origin in [Origin::Foreground, Origin::Watch] {
            for depth in [1, 2] {
                let engine = Engine::new(PathBuf::from("unused-worker"));
                let mut request = Request::new(vec![path.clone()], mode);
                request.origin = origin;
                let events = Mutex::new(Vec::new());
                let observer = |event: Event| { events.lock().unwrap().push(event); };
                let run = test_run(&engine, &request, &observer);
                let task = Task {
                    primary: None,
                    owned_paths: vec![input.entry_path.clone()],
                    inputs: vec![LogicalInput { input: input.clone(), password: None, failure: None }],
                    source: DiscoverySource::Detection,
                    context: None,
                };
                let outcome = Scheduler::new().run(1, origin, &request.cancel, |spawner| {
                    run.execute_task(run.register_task(task), 1, depth, None, spawner)
                }).unwrap();
                assert!(outcome.archives.is_empty());
                assert!(outcome.errors.is_empty());
                assert!(matches!(events.lock().unwrap().as_slice(), [Event::Skipped { id: 1 }]));

            }
        }
    }
}

fn output_manifest(files: &[(&str, &[u8])]) -> crate::scan::directory::NativeWorkerManifest {
    use crate::scan::directory::{NativeWorkerManifest, OutputFileRecord};

    let records = files.iter().map(|(path, data)| OutputFileRecord {
        path: (*path).to_owned(),
        size: data.len() as u64,
        status: 1,
        mtime_ns: Some(1),
        magic: Box::from(&data[..data.len().min(512)]),
    }).collect();
    NativeWorkerManifest::from_parts(records, true,
        files.iter().map(|(_, data)| data.len() as u64).sum())
}

#[test]
#[cfg(windows)]
fn retained_carrier_outputs_do_not_reenter_recursive_discovery() {
    struct RetainedObserver {
        started: Mutex<Vec<TaskId>>,
        finished: Mutex<Vec<TaskId>>,
    }
    impl Observer for RetainedObserver {
        fn notify(&self, event: Event) {
            match event {
                Event::Started { id, .. } => self.started.lock().unwrap().push(id),
                Event::Finished { id, .. } => self.finished.lock().unwrap().push(id),
                _ => {}
            }
        }
        fn allow_recursive(&self, _: usize, _: usize) -> bool {
            panic!("retained outputs must not request another recursive scan");
        }
    }
    for (count, split_sources) in [(1, false), (2, false), (2, true)] {
        let source = crate::test_support::temp_file("carrier_parent_barrier", &[0; 16]);
        let container = source.with_extension("output");
        fs::create_dir(&container).unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), container.file_name().unwrap().to_string_lossy().into_owned());
        let (segments, _) = archive_input_slices(&input, &[
            ("zip", 0, Some(8)), ("zip", 8, Some(16)),
        ]).unwrap();
        let mut inputs: Vec<_> = segments.into_iter().take(count).map(Option::unwrap).collect();
        let continuation = source.with_extension("part2");
        if split_sources {
            fs::write(&continuation, [0; 16]).unwrap();
            let part = ArchiveInput::file(continuation.to_string_lossy().into_owned(), "zip".into(), "second".into());
            inputs[1] = archive_input_slices(&part, &[("zip", 8, Some(16))]).unwrap().0.remove(0).unwrap();
        }
        let mut generations = HashMap::from([
            (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
        ]);
        if split_sources {
            generations.insert(path_key(&continuation.to_string_lossy()), capture_file_generation(&continuation).unwrap());
        }
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(vec![source.clone()], Mode::Extract);
        request.max_depth = 1;
        Arc::make_mut(&mut request.config).recursive_extract = Recursion::Prompt;
        Arc::make_mut(&mut request.config).post_extract.archive_cleanup_mode = CleanupMode::Keep;
        for (index, input) in inputs.iter().enumerate() {
            let output = container.join(format!("segment-{index}"));
            fs::create_dir(&output).unwrap();
            fs::write(output.join("payload"), b"keep").unwrap();
            let mut result = receipt(input, DiscoverySource::Embedded, 1);
            result.output = Some(output);
            result.files = 1;
            result.bytes = 4;
            request.checkpoints.push(InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap());
        }
        let observer = RetainedObserver {
            started: Mutex::new(Vec::new()),
            finished: Mutex::new(Vec::new()),
        };
        let mut run = test_run(&engine, &request, &observer);
        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
            Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
        }
        let task = Task {
            primary: None,
            owned_paths: inputs.iter().map(|input| input.entry_path.clone()).collect(),
            inputs: inputs.into_iter().map(|input| LogicalInput { input, password: None, failure: None }).collect(),
            source: DiscoverySource::Embedded,
            context: None,
        };
        let scheduler = Scheduler::new();
        let outcome = run.recursion.serve(&request.cancel,
            |depth, pending| observer.allow_recursive(depth, pending),
            || scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| {
                run.execute_task(run.register_task(task), 1000, 1, None, spawner)
            }),
        ).unwrap();
        assert_eq!(observer.started.lock().unwrap().len(), if count == 1 { 1 } else { count + 1 });
        assert_eq!(observer.finished.lock().unwrap().last(), Some(&1000));
        assert_eq!(outcome.archives.len(), count);
        assert_eq!(outcome.archives.iter().map(|result| result.offset).collect::<Vec<_>>(),
            (0..count).map(|index| (index * 8) as u64).collect::<Vec<_>>());
        assert!(outcome.archives.iter().all(|result| result.retained));
        assert!(source.is_file());
        for index in 0..count {
            assert_eq!(fs::read(container.join(format!("segment-{index}/payload"))).unwrap(), b"keep");
        }
        release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
        fs::remove_dir_all(container).unwrap();
        fs::remove_file(source).unwrap();
        if split_sources { fs::remove_file(continuation).unwrap(); }
    }
}

#[test]
#[cfg(windows)]
fn changed_carrier_inputs_keep_their_slots_not_their_old_results() {
    use std::os::windows::fs::OpenOptionsExt;
    // Exercise selection, ownership and both physical cleanup outcomes.
    // The worker-level changed-volume case is covered by the Watch blackbox.
    for previously_failed in [false, true] {
        for cleanup_locked in [false, true] {
            let source = crate::test_support::temp_file("changed_carrier_slot", &[0; 16]);
            let container = source.with_extension("output");
            let sibling = container.join("sibling");
            let slot = container.join("segment(2)");
            fs::create_dir_all(&sibling).unwrap();
            fs::create_dir(&slot).unwrap();
            fs::write(sibling.join("keep"), b"unchanged").unwrap();
            fs::write(slot.join("old"), b"previous attempt").unwrap();
            let sibling_before = capture_file_generation(&sibling.join("keep")).unwrap();
            let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(),
                container.file_name().unwrap().to_string_lossy().into_owned());
            let inputs: Vec<_> = archive_input_slices(&input, &[
                ("zip", 0, Some(4)), ("zip", 4, Some(8)),
            ]).unwrap().0.into_iter().map(Option::unwrap).collect();
            let changed = archive_input_slices(&input, &[("zip", 4, Some(12))])
                .unwrap().0.remove(0).unwrap();
            let generations = HashMap::from([
                (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
            ]);
            let mut request = Request::new(vec![source.clone()], Mode::Extract);
            for (index, logical) in inputs.iter().enumerate() {
                let mut result = receipt(logical, DiscoverySource::Embedded, 1);
                result.output = Some(if index == 0 { sibling.clone() } else { slot.clone() });
                result.files = 1;
                if index == 1 && previously_failed {
                    result.failure = Some(Failure::new(FailureKind::MissingVolume, "old failure"));
                    result.recovered_complete_files = 1;
                    result.partial = true;
                }
                request.checkpoints.push(InputCheckpoint::create(&source, Arc::new((logical).clone()), &result, &generations, Some(&container)).unwrap());
            }
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let observer = |_: Event| {};
            let mut run = test_run(&engine, &request, &observer);
            for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
            }
            let kept = run.checkpoint_for(&inputs[0], Some(&run.request.checkpoints[0]), &generations, &container, 1, &run.candidates).unwrap();
            assert_eq!(kept.retained_container(), Some(container.as_path()));
            assert!(run.checkpoint_for(&changed, Some(&run.request.checkpoints[1]), &generations, &container, 1, &run.candidates).is_none());
            let previous = run.retry_slot_for(&changed, Some(&run.request.checkpoints[1]), &container).unwrap();
            assert_eq!(previous.output(), slot);
            assert!(run.retry_slot_for(&changed, Some(&run.request.checkpoints[1]), &source.with_extension("unrelated")).is_none());
            assert!(!previous.output_slot_for(&changed, &slot), "carrier root is never a child retry slot");
            let held = cleanup_locked.then(|| fs::OpenOptions::new().read(true).share_mode(3)
                .open(slot.join("old")).unwrap());
            let mut outcome = Outcome::default();
            let cleared = run.discard_failed_output(&previous.result(1), &slot, &mut outcome).unwrap();
            assert_eq!(cleared, !cleanup_locked);
            // Current extraction uses current facts, not the old partial
            // marker or old success, even when best-effort cleanup failed.
            let current = receipt(&changed, DiscoverySource::Embedded, 1);
            if cleared {
                assert_eq!(run.recreate_reserved_output(&slot, &current).unwrap().unwrap(), slot);
            } else {
                observer.reuse_output(&current, &slot).unwrap();
            }
            fs::write(slot.join("new"), b"current attempt").unwrap();
            assert_eq!(slot.join("old").exists(), cleanup_locked);
            assert_eq!(fs::read_dir(&container).unwrap().count(), 2);
            assert_eq!(capture_file_generation(&sibling.join("keep")).unwrap(), sibling_before);
            assert_eq!(fs::read(sibling.join("keep")).unwrap(), b"unchanged");
            drop(held);
            drop(run);
            release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
            fs::remove_dir_all(container).unwrap();
            fs::remove_file(source).unwrap();
        }
    }
}

#[test]
#[cfg(windows)]
fn source_cleanup_runs_after_consumer_finish_and_is_joined_by_request() {
    use std::os::windows::fs::OpenOptionsExt;
    for locked in [false, true] {
    let source = crate::test_support::temp_file("background_source_cleanup", b"archive");
    let held = locked.then(|| fs::OpenOptions::new().read(true).share_mode(1).open(&source).unwrap());
    let output = source.with_extension("output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("payload"), b"keep").unwrap();
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), output.file_name().unwrap().to_string_lossy().into_owned());
    let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
    let mut request = Request::new(vec![source.clone()], Mode::Extract);
    request.max_depth = 0;
    let config = Arc::make_mut(&mut request.config);
    config.post_extract.archive_cleanup_mode = CleanupMode::Delete;
    config.post_extract.flatten_single_directory = false;
    let mut result = receipt(&input, DiscoverySource::Embedded, 1);
    result.output = Some(output.clone());
    result.files = 1;
    request.checkpoints.push(InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap());
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let finished = std::sync::atomic::AtomicBool::new(false);
    let observer = |event| {
        if matches!(event, Event::Finished { .. }) {
            assert!(source.exists(), "consumer waited for source cleanup before reporting completion");
            finished.store(true, Ordering::Release);
        }
    };
    let mut run = test_run(&engine, &request, &observer);
    for (index, checkpoint) in request.checkpoints.iter().enumerate() {
        Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
    }
    let task = Task {
        primary: None, inputs: vec![LogicalInput { input, password: None, failure: None }],
        owned_paths: vec![source.to_string_lossy().into_owned()], source: DiscoverySource::Embedded, context: None,
    };
    let scheduler = Scheduler::new();
    scheduler.configure_capacity(1);
    let source_key = Arc::from(resolved_key(&source));
    let leases = Arc::clone(&engine.leases);
    let outcome = scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| Box::pin(async move {
        let outcome = run.execute_task(run.register_task(task), 1, 1, None, spawner.clone()).await;
        let (checked, check) = mpsc::channel();
        spawner.spawn(Box::pin(async move {
            let cancel = Cancellation::new();
            let mut next = Box::pin(leases.acquire_shared(HashSet::from([source_key]), 2, &cancel));
            let blocked = poll_fn(|cx| {
                use std::future::Future;
                Poll::Ready(next.as_mut().poll(cx).is_pending())
            }).await;
            checked.send(blocked).unwrap();
        }));
        // The cleanup child started before this probe, but this poll owns
        // the only blocking stage until the probe observes the lease.
        assert!(check.recv().unwrap(), "another request acquired the source before cleanup");
        run.finish(outcome).await
    })).unwrap();
    assert!(finished.load(Ordering::Acquire));
    assert_eq!(source.exists(), locked, "request returned before background cleanup settled");
    assert_eq!(outcome.cleanup_results.len(), usize::from(locked));
    assert!(outcome.errors.is_empty());
    assert_eq!(fs::read(output.join("payload")).unwrap(), b"keep");
    drop(held);
    if locked { fs::remove_file(source).unwrap(); }
    fs::remove_dir_all(output).unwrap();
    }
}

#[test]
fn control_driver_start_failure_drops_future_and_allows_retry() {
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let scheduler = engine.scheduler.get_or_init(Scheduler::new);
    scheduler.fail_driver.store(true, Ordering::Relaxed);
    let held = Arc::new(());
    let pending = Arc::clone(&held);
    let failed = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move {
        drop(pending);
    });
    assert!(failed.is_err());
    assert_eq!(Arc::strong_count(&held), 1);
    let next = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async { 42 }).unwrap();
    assert_eq!(next.join().unwrap(), 42);
}

#[test]
fn owned_request_reports_executor_startup_failure_once_and_retries() {
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let scheduler = engine.scheduler.get_or_init(Scheduler::new);
    scheduler.fail_pool.store(2, Ordering::Relaxed);
    let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&called);
    let request = Request::new(Vec::new(), Mode::Extract);
    let completion = engine.submit(request, Arc::new(|_: Event| {}), move |result| {
        observed.fetch_add(1, Ordering::Relaxed);
        result
    });
    assert!(completion.join().unwrap().is_err());
    assert_eq!(called.load(Ordering::Relaxed), 1);
    assert_eq!(scheduler.fail_pool.load(Ordering::Relaxed), 0);
    // A service call after the fault must use the newly available executor.
    scheduler.fail_pool.store(0, Ordering::Relaxed);
    assert_eq!(engine.run_stage("report", Origin::Foreground, || 42).unwrap(), 42);
}

#[test]
fn synchronous_service_work_reuses_shared_stage_and_nested_admission() {
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let scheduler = engine.scheduler.get_or_init(Scheduler::new);
    scheduler.configure_capacity(1);
    let value = engine.run_stage("watch_admission", Origin::Watch, || {
        assert!(crate::pipeline::scheduling::in_stage());
        engine.run_stage("watch_usn_checkpoint", Origin::Watch, || {
            assert!(crate::pipeline::scheduling::in_stage());
            42
        })
    });
    assert_eq!(value.unwrap().unwrap(), 42);
    assert!(!crate::pipeline::scheduling::in_stage());
}

fn encrypted_rar_fixture() -> Vec<u8> {
    let hex = "526172211a07010074de7b1c21040000010f7b64253244702e2a32eb93579555a37d38b616cb97898c463d3682920551724ed0c1c974029cc2b8ef8491fc816311daa1b0410f6115608170466e4948a8c6d4f17e28b08c727b4acfc116d3d075ce011963dc0c72e50a803d9036619810e92352e809830c9463ab4a0abdaab61e008218673e9c51409f76b2064bf7982e56d8173f1e387329bd5aca3bac49063545fcbfc19547d2be214b4fe1dae172b250e168f2a258548930b1763fb500c7869d70f2539d86fd19214dcc3bca1363154b0a0f2b0bba7dcc224ec1893cbc31cfa95158ccf5e96d74921de6f268ea4429e2ddf63d49220005742fef059f868372345f071322a7e690d56d5ac17b563fa9e923076fa2c58aa8e88e9843df17b7e79a30ca936d8215c92f6832f86887c3c3160ecfddfcdf7712382f84f39eb8";
    (0..hex.len()).step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap()).collect()
}

#[test]
fn recursive_many_outputs_preserve_parent_index_and_prompt_boundary() {
    let source = crate::test_support::temp_file("recursive_many", b"source");
    let root = source.with_extension("outputs");
    fs::create_dir(&root).unwrap();
    let rar = encrypted_rar_fixture();
    for answer in [false, true] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(Vec::new(), Mode::Extract);
        request.max_depth = usize::MAX;
        let config = Arc::make_mut(&mut request.config);
        config.recursive_extract = Recursion::Prompt;
        config.recursive_authorization.enabled = false;
        config.filesystem.scan_filters_enabled = false;
        let observer = |_: Event| {};
        let mut run = test_run(&engine, &request, &observer);
        Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
            Arc::from([Arc::from("secret")]), None, &engine.recent_passwords, None);
        let mut inventories = Vec::new();
        let mut manifests = Vec::new();
        for index in [3, 7, 15] {
            let output = root.join(index.to_string()); fs::create_dir_all(&output).unwrap();
            fs::write(output.join("encrypted.bin"), &rar).unwrap();
            let manifest = output_manifest(&[("encrypted.bin", &rar)]);
            manifests.push(Arc::downgrade(manifest.records().unwrap()));
            inventories.push((index, manifest.into_output_stats(&output.to_string_lossy(), true).unwrap().inventory.unwrap()));
        }
        let scheduler = Scheduler::new();
        let results = run.recursion.serve(&request.cancel, |depth, _| {
            assert_eq!(depth, 2);
            assert!(manifests.iter().all(|manifest| manifest.upgrade().is_none()));
            assert!(engine.recent_passwords().is_empty());
            answer
        }, || scheduler.run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.discover_children_many(inventories.into_iter(), 1, &run.candidates))
        })).unwrap();
        assert_eq!(results.len(), 3);
        for (expected, (index, nested, scanned)) in [3, 7, 15].into_iter().zip(results) {
            assert_eq!(index, expected);
            assert_eq!(scanned, answer);
            if answer { assert!(!nested.tasks.is_empty()); }
            else { assert!(nested.tasks.is_empty()); }
            for task in &nested.tasks {
                assert!(Path::new(&task.entry().entry_path).starts_with(root.join(index.to_string())));
            }
        }
    }
    release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
    fs::remove_dir_all(root).unwrap(); fs::remove_file(source).unwrap();
}

#[test]
fn recursive_discovery_waits_for_consent_and_releases_the_manifest() {
    // Real RAR5 -hp fixture (password "secret"). A real successful probe
    // changes this request's password cache, so this catches discovery moved
    // above the prompt without a mock or process-global test counters.
    let rar = encrypted_rar_fixture();
    let source = crate::test_support::temp_file("recursive_consent", b"source");
    let root = source.with_extension("output");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("encrypted.bin"), &rar).unwrap();
    // A carrier can disappear after its worker manifest was produced.
    // A missing input is a retired proposal, even after consent.
    let carrier = [0; 1024];
    for answer in [false, true] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(Vec::new(), Mode::Extract);
        request.max_depth = usize::MAX;
        let config = Arc::make_mut(&mut request.config);
        config.recursive_extract = Recursion::Prompt;
        config.recursive_authorization.enabled = false;
        config.filesystem.scan_filters_enabled = false;
        config.embedded_scan.enabled = true;
        config.embedded_scan.recursive_candidate_ratio = 0.0;
        let observer = |_: Event| {};
        let mut run = test_run(&engine, &request, &observer);
        Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
            Arc::from([Arc::from("secret")]), None, &engine.recent_passwords, None,
        );
        let manifest = output_manifest(&[("encrypted.bin", &rar), ("carrier.bin", &carrier)]);
        let retained = Arc::downgrade(manifest.records().unwrap());
        let inventory = manifest.into_output_stats(&root.to_string_lossy(), true).unwrap().inventory.unwrap();
        let prompted = Mutex::new(Vec::new());
        let scheduler = Scheduler::new();
        let (nested, scanned) = run.recursion.serve(&request.cancel, |depth, pending| {
            assert!(retained.upgrade().is_none(), "prompt retained the worker manifest");
            assert!(engine.recent_passwords().is_empty(), "password probe ran before consent");
            prompted.lock().unwrap().push((depth, pending));
            answer
        }, || scheduler.run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.discover_children(inventory, 1, &run.candidates))
        })).unwrap();
        assert_eq!(*prompted.lock().unwrap(), [(2, 1)]);
        assert_eq!(scanned, answer);
        if answer {
            assert_eq!(engine.recent_passwords().as_slice(), [Arc::<str>::from("secret")]);
            assert!(!nested.tasks.is_empty(), "approved archive was not discovered");
            assert!(nested.scan_errors.is_empty(), "departed carrier reported as unreadable");
            engine.clear_idle_caches();
            assert!(engine.recent_passwords().is_empty());
            assert_eq!(run.candidates.for_embedded(&source.to_string_lossy()), [Arc::<str>::from("secret")]);
        } else {
            assert!(engine.recent_passwords().is_empty());
            assert!(nested.tasks.is_empty());
            assert!(nested.scan_errors.is_empty(), "decline still scanned the carrier");
        }
    }
    release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn recursive_prompt_uses_filtered_outputs_before_candidate_authorization() {
    use crate::core::config::{ScanFilter, ScanFilterKind};
    use std::io::Write;

    // Main's boundary is a filtered file, not an archive candidate. Cover
    // the complementary no-prompt cases and post-prompt policy rejection
    // together so moving either policy to the wrong side is observable.
    let source = crate::test_support::temp_file("recursive_boundaries", b"source");
    let root = source.with_extension("output");
    fs::create_dir_all(root.join("sub")).unwrap();
    let plain = [b'x'; 1024];
    fs::write(root.join("sub/plain.bin"), plain).unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(b"nested payload").unwrap();
    let gzip = gzip.finish().unwrap();
    fs::write(root.join("nested.bin"), &gzip).unwrap();
    for (case, expected_prompt, expected_scan, expected_tasks) in [
        ("empty", false, false, 0),
        ("unreadable", false, false, 0),
        ("filtered", false, false, 0),
        ("depth", false, false, 0),
        ("cancelled", false, false, 0),
        ("plain", true, true, 0),
        ("archive", true, true, 1),
        ("policy_rejected", true, true, 0),
        ("fixed", false, true, 1),
    ] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(Vec::new(), Mode::Extract);
        request.max_depth = if case == "depth" { 0 } else { usize::MAX };
        let config = Arc::make_mut(&mut request.config);
        config.recursive_extract = if case == "fixed" { Recursion::Fixed(2) } else { Recursion::Prompt };
        config.recursive_authorization.enabled = case == "policy_rejected";
        config.recursive_authorization.minimum_authorization_score = 1.0;
        config.embedded_scan.enabled = false;
        config.filesystem.scan_filters_enabled = false;
        if case == "filtered" {
            config.filesystem.scan_filters_enabled = true;
            config.filesystem.scan_filters = Arc::from([ScanFilter {
                enabled: true,
                kind: ScanFilterKind::MtimeRange([Some(1), None, None, None, None]),
            }]);
        }
        let files: Vec<(&str, &[u8])> = match case {
            "empty" | "unreadable" => Vec::new(),
            "archive" | "policy_rejected" | "fixed" => vec![
                ("sub/plain.bin", &plain), ("nested.bin", &gzip),
            ],
            _ => vec![("sub/plain.bin", &plain)],
        };
        let inventory = if case == "unreadable" {
            scan_output_stats(&root.join("absent").to_string_lossy(), true).inventory.unwrap()
        } else {
            output_manifest(&files).into_output_stats(&root.to_string_lossy(), true).unwrap().inventory.unwrap()
        };
        if case == "cancelled" {
            request.cancel.cancel();
        }
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let prompted = Mutex::new(Vec::new());
        let scheduler = Scheduler::new();
        let (nested, scanned) = run.recursion.serve(&request.cancel, |depth, pending| {
            prompted.lock().unwrap().push((depth, pending));
            true
        }, || scheduler.run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.discover_children(inventory, 1, &run.candidates))
        })).unwrap();
        assert_eq!(!prompted.lock().unwrap().is_empty(), expected_prompt, "{case}");
        assert_eq!(scanned, expected_scan, "{case}");
        assert_eq!(nested.tasks.len(), expected_tasks, "{case}");
        assert_eq!(!nested.scan_errors.is_empty(), case == "unreadable", "{case}");
    }
    release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn recursive_prompt_parks_siblings_and_shares_each_depth_decision() {
    use std::time::Duration;

    struct Prompt {
        entered: mpsc::Sender<usize>,
        answer: Mutex<mpsc::Receiver<bool>>,
    }
    impl Observer for Prompt {
        fn notify(&self, _: Event) {}
        fn allow_recursive(&self, depth: usize, _: usize) -> bool {
            self.entered.send(depth).unwrap();
            self.answer.lock().unwrap().recv().unwrap()
        }
    }
    // The generic parked-task test does not exercise the blocking Observer
    // callback or same-depth prompt sharing. Withhold input until unrelated
    // work actually runs on the only host slot, for both yes and no answers.
    for answer in [true, false] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(Vec::new(), Mode::Extract);
        Arc::make_mut(&mut request.config).recursive_extract = Recursion::Prompt;
        let (entered, prompts) = mpsc::channel();
        let (respond, responses) = mpsc::channel();
        let observer = Prompt { entered, answer: Mutex::new(responses) };
        let run = test_run(&engine, &request, &observer);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let scheduler = pool.install(Scheduler::new);
        std::thread::scope(|scope| {
            let prompted = scope.spawn(|| {
                run.recursion.serve(
                    &request.cancel,
                    |depth, pending| observer.allow_recursive(depth, pending),
                    || scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| {
                        let run = &run;
                        Box::pin(async move {
                            let results = spawner.bounded_map([(); 8].into_iter(), move |_| {
                                Box::pin(run.allow_recursive(2, 1))
                            }).await;
                            assert_eq!(run.allow_recursive(2, 1).await, answer);
                            let next_depth = run.allow_recursive(3, 1).await;
                            (results, next_depth)
                        })
                    }),
                )
            });
            assert_eq!(prompts.recv_timeout(Duration::from_secs(10)).unwrap(), 2);
            let (finished, completed) = mpsc::channel();
            let independent = scope.spawn(|| {
                scheduler.run(2, Origin::Watch, &Cancellation::new(), |_| {
                    Box::pin(async move { finished.send(()).unwrap() })
                });
            });
            let admitted = completed.recv_timeout(Duration::from_secs(10));
            // Release the prompt even on a scheduling regression so both
            // requests can join before the assertion reports the failure.
            respond.send(answer).unwrap();
            assert_eq!(prompts.recv_timeout(Duration::from_secs(10)).unwrap(), 3);
            respond.send(!answer).unwrap();
            let (results, next_depth) = prompted.join().unwrap();
            independent.join().unwrap();
            admitted.expect("recursive prompt held the shared host slot");
            assert_eq!(results, vec![answer; 8]);
            assert_eq!(next_depth, !answer);
            assert!(prompts.try_recv().is_err(), "same depth asked more than once");
        });
    }
}

#[test]
fn cancelled_or_panicking_prompt_wakes_siblings_and_joins_its_callback() {
    use std::time::Duration;

    // Verify cancellation wakes every archive independently of a still
    // returning input callback, and a callback panic cannot strand gates.
    for panic in [false, true] {
        let cancel = Cancellation::new();
        let prompts = RecursivePrompts::default();
        let scheduler = Scheduler::new();
        let (entered, entering) = mpsc::channel();
        let (respond, response) = mpsc::channel();
        let response = Mutex::new(response);
        let (finished, completed) = mpsc::channel();
        std::thread::scope(|scope| {
            let request = scope.spawn(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    prompts.serve(&cancel, |_, _| {
                        entered.send(()).unwrap();
                        assert!(!panic, "observer prompt panic");
                        response.lock().unwrap().recv().unwrap()
                    }, || scheduler.run(1, Origin::Foreground, &cancel, |spawner| {
                        let prompts = &prompts;
                        let cancel = &cancel;
                        let finished = &finished;
                        Box::pin(async move {
                            let results = spawner.bounded_map([(); 8].into_iter(), move |_| {
                                Box::pin(prompts.allow(2, 1, cancel, None::<fn(usize, usize) -> std::future::Ready<bool>>))
                            }).await;
                            finished.send(()).unwrap();
                            results
                        })
                    }))
                }))
            });
            entering.recv_timeout(Duration::from_secs(10)).unwrap();
            if !panic {
                cancel.cancel();
            }
            let woke = completed.recv_timeout(Duration::from_secs(10));
            if !panic {
                // A late yes must not replace the cancellation decision.
                respond.send(true).unwrap();
            }
            let result = request.join().unwrap();
            woke.expect("cancellation left recursive siblings parked");
            assert!(cancel.cancelled());
            if panic {
                assert!(result.is_err());
            } else {
                let results = result.unwrap();
                assert!(!results.is_empty() && results.len() <= 8);
                assert!(results.iter().all(|allowed| !allowed));
            }
            for decision in prompts.decisions.lock().unwrap().values() {
                assert!(decision.0.lock().unwrap().waiters.is_empty());
            }
        });
    }
}

#[test]
fn cancelled_batch_does_not_swallow_unrelated_journal_io_errors() {
    struct JournalFailure(Cancellation, io::ErrorKind);
    impl Observer for JournalFailure {
        fn notify(&self, _: Event) {}
        fn claim_sources(&self, _: &Path, _: &[String], _: usize) -> io::Result<()> {
            self.0.cancel();
            Err(io::Error::new(self.1, "journal failure"))
        }
    }
    // The cancelled-child outcome regression alone would still pass if all
    // IO errors were swallowed whenever the request token was cancelled.
    for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(Vec::new(), Mode::Extract);
        let observer = JournalFailure(request.cancel.clone(), kind);
        let run = test_run(&engine, &request, &observer);
        let batch = Discovered {
            tasks: vec![Task {
                primary: None,
                inputs: vec![LogicalInput {
                    input: ArchiveInput::file("child.zip".into(), "zip".into(), "child".into()),
                    password: None,
                    failure: Some(Failure::new(FailureKind::Damaged, "preflight failure")),
                }],
                owned_paths: Vec::new(),
                source: DiscoverySource::Embedded,
                context: None,
            }],
            errors: Vec::new(),
            scan_errors: DirectoryReadErrors::report(),
            blocked_paths: HashSet::new(),
        };
        let error = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
            Box::pin(run.execute_batch(batch, 2, None, None, spawner, None))
        }).unwrap_err();
        assert!(request.cancel.cancelled());
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), "journal failure");
        assert_eq!(run.process_or_file_failure(io::Error::new(kind, "filesystem failure"), false).kind,
            FailureKind::FilesystemError);
        assert_eq!(run.process_or_file_failure(io::Error::new(kind, "worker failure"), true).kind,
            FailureKind::ProcessError);
        assert_eq!(run.process_or_file_failure(request.cancel.check_io().unwrap_err(), false).kind,
            FailureKind::Cancelled);
    }
}

#[test]
#[cfg(windows)]
fn watch_volume_retry_waits_for_a_late_writer_to_close() {
    use std::io::Write;
    let next_header = [1, 0, 0];
    let mut start_header = [0_u8; 20];
    start_header[..8].copy_from_slice(&45_u64.to_le_bytes());
    start_header[8..16].copy_from_slice(&(next_header.len() as u64).to_le_bytes());
    start_header[16..].copy_from_slice(&crc32fast::hash(&next_header).to_le_bytes());
    let mut head = b"\x37\x7A\xBC\xAF\x27\x1C\x00\x04".to_vec();
    head.extend(crc32fast::hash(&start_header).to_le_bytes());
    head.extend(start_header);
    head.resize(64, 0);
    let marker = crate::test_support::temp_file("late_volume", b"");
    let root = marker.with_extension("volumes");
    fs::create_dir(&root).unwrap();
    let first = root.join("split.7z.001");
    fs::write(&first, head).unwrap();

    let mut request = Request::new(vec![first.clone()], Mode::Extract);
    request.origin = Origin::Watch;
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let candidates = CandidateSet::new(Arc::from([]), None, &engine.recent_passwords, None);
    let options = discovery::scan_options(&request.config).unwrap();
    let discovered = discovery::discover(&request, &options, &candidates, true).unwrap();
    let [task] = discovered.tasks.as_slice() else {
        panic!("expected an incomplete volume group");
    };
    let Some(discovery::TaskContext::Retry(context)) = &task.context else {
        panic!("expected retained volume resolution context");
    };
    let mut original = receipt(task.entry(), task.source, 1);
    let output = root.join("damaged-output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("damaged.bin"), b"recoverable bytes").unwrap();
    original.output = Some(output.clone());
    original.failure = Some(Failure::new(FailureKind::MissingVolume, "missing"));
    let observer = |_: Event| {};
    let run = test_run(&engine, &request, &observer);
    CreatedOutputs::register(&run.created_outputs, &output, &original);

    let last = root.join("split.7z.002");
    let mut writer = fs::File::create(&last).unwrap();
    writer.write_all(&[0; 13]).unwrap();
    writer.write_all(&next_header).unwrap();
    assert!(discovery::retry_volume(&original, &[], context, &options, &candidates, &request)
        .unwrap().is_none());
    assert!(output.join("damaged.bin").is_file());
    drop(writer);
    assert!(discovery::retry_volume(&original, &[], context, &options, &candidates, &request)
        .unwrap().is_some());
    // A live retry cannot replace a member that was still present at
    // admission. Only names admitted as departed may be left behind.
    let departed = root.join("split.7z.002.downloading");
    original.source_paths.push(departed.clone());
    assert!(discovery::retry_volume(&original, &[], context, &options, &candidates, &request)
        .unwrap().is_none());
    assert!(discovery::retry_volume(&original, &[departed], context, &options, &candidates, &request)
        .unwrap().is_some());
    run.discard_failed_output(&original, &output, &mut Outcome::default()).unwrap();
    assert!(!output.exists());
    assert!(run.created_outputs.lock().unwrap().0.is_empty());

    drop(discovered);
    release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
#[cfg(windows)]
fn mirrored_output_names_keep_the_drive_or_share() {
    assert_eq!(
        mirrored_parent_component(Path::new(r"D:\Data\file set")),
        "D_Data_file_set"
    );
    assert_eq!(
        mirrored_parent_component(Path::new(r"\\server\share\folder")),
        "__server_share_folder"
    );
}

#[test]
fn alias_dedup_covers_candidate_and_preflight_failure_plans() {
    use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan};
    let path = crate::test_support::temp_file("dedup_unresolved", b"physical archive");
    let alias = path.parent().unwrap().join(".").join(path.file_name().unwrap());
    let make = |path: &Path, candidate: bool, blocked: bool| {
        let mut input = ArchiveInput::file(path.to_string_lossy().into_owned(),
            "7z".into(), "archive".into());
        if candidate {
            input.volume_attempts = Some(Arc::new(VolumeAttemptPlan {
                sources: Box::new([InputExtent {
                    path: input.entry_path.clone(), start: 0, end: None,
                }]),
                layouts: Box::new([]), domains: Box::new([]),
                head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
            }));
        }
        Task {
            primary: None,
            owned_paths: vec![input.entry_path.clone()],
            inputs: vec![LogicalInput { input, password: None,
                failure: blocked.then(|| Failure::new(FailureKind::MissingVolume, "missing")) }],
            source: DiscoverySource::Embedded, context: None,
        }
    };
    for (candidate, blocked) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut tasks = vec![make(&path, candidate, blocked), make(&alias, candidate, blocked)];
        dedup_resolved_plans(&mut tasks);
        assert_eq!(tasks.len(), 1, "candidate={candidate}, blocked={blocked}");
    }
    let mut first = make(&path, false, true);
    first.inputs[0].input.mode = OpenMode::FileRange;
    first.inputs[0].input.parts = Box::new([InputPart::range(InputExtent {
        path: path.to_string_lossy().into_owned(), start: 0, end: Some(4),
    })]);
    let mut different = make(&alias, false, true);
    different.inputs[0].input = first.inputs[0].input.clone();
    different.inputs[0].input.parts[0].extent.start = 4;
    different.inputs[0].input.parts[0].extent.end = Some(8);
    let mut tasks = vec![first, different];
    dedup_resolved_plans(&mut tasks);
    assert_eq!(tasks.len(), 2, "distinct physical ranges must remain separate");
    fs::remove_file(path).unwrap();
}

// Covers history reuse on ancestor rebases and released descendant slots;
// the leaf-only allocator tests cannot exercise this ownership path.
#[test]
fn ancestor_rebases_share_number_history_and_reuse_released_slots() {
    let source = crate::test_support::temp_file("ancestor_history", b"input");
    let base = source.with_extension("output");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    let names = Mutex::new(OutputNames::default());
    assert_eq!(OutputNames::plan(&names, base.clone(), &result.path, 1, None).unwrap().unwrap(), base);
    for index in 1..=32 {
        let wanted = base.join(format!("child-{index}"));
        assert_eq!(OutputNames::plan(&names, wanted, &result.path, index as u64 + 1, None).unwrap().unwrap(),
            numbered(&base, index).join(format!("child-{index}")));
    }
    let family = output_key(&base);
    let guard = names.lock().unwrap();
    let history = guard.indices.peek(family.as_str()).unwrap();
    assert_eq!(history.next, 33);
    assert_eq!(history.observed.len(), 32);
    drop(guard);
    names.lock().unwrap().release(2);
    assert_eq!(OutputNames::plan(&names, base.join("replacement"), &result.path, 99, None).unwrap().unwrap(),
        numbered(&base, 1).join("replacement"));
    assert_eq!(names.lock().unwrap().indices.peek(family.as_str()).unwrap().next, 33);
    fs::remove_file(source).unwrap();
}

#[test]
fn conflicting_output_ancestor_preserves_alias_spelling() {
    for spelling in ["physical", "junction-alias"] {
        let path = PathBuf::from(spelling).join("branch").join("archive");
        let (base, tail) = conflicting_output_base(
            &path, "physical\\branch\\archive", "physical",
        ).unwrap();
        assert_eq!(base, Path::new(spelling));
        assert_eq!(numbered(base, 1).join(tail),
            PathBuf::from(format!("{spelling}(1)")).join("branch").join("archive"));
    }
}

// Registration-only tests miss filesystem probes under the naming lock.
// Inject peers at that exact boundary, including an alias of the same tree;
// no sleeps or timing assumptions are needed to expose lost reservations.
#[test]
fn output_path_queries_release_the_gate_and_keep_alias_ancestor_slots() {
    let source = crate::test_support::temp_file("output_query_gate", b"input");
    let root = source.with_extension("output").join("physical").join("deep");
    let alias = source.with_extension("aliases").join("shortcut");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir(alias.parent().unwrap()).unwrap();
    let junction = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"]).arg(&alias).arg(&root).output().unwrap();
    assert!(junction.status.success(), "{}{}", String::from_utf8_lossy(&junction.stdout), String::from_utf8_lossy(&junction.stderr));
    let names = Mutex::new(OutputNames::default());
    let base = root.join("archive");
    let aliased = alias.join("archive");
    assert_eq!(OutputNames::plan(&names, base.clone(), &source, 1, None).unwrap().unwrap(), base);
    fs::create_dir(numbered(&base, 1)).unwrap();
    let mut probes = 0;
    let (output, key) = OutputNames::plan_checked(
        &names, aliased.join("child"), &source, 2, None, |path| {
            drop(names.try_lock().expect("path query held the global naming gate"));
            probes += 1;
            assert_eq!(path, numbered(&aliased, [1, 2, 4][probes - 1]));
            if probes == 1 {
                let inside = numbered(&base, 1).join("inside");
                assert_eq!(OutputNames::plan(&names, inside.clone(), &source, 10, None)?.unwrap(), inside,
                    "an unverified candidate must not displace children of an existing directory");
            }
            if probes == 2 {
                let peer = OutputNames::plan(&names, base.join("peer"), &source, 3, None)?.unwrap();
                assert_eq!(peer, numbered(&base, 3).join("peer"));
                let independent = root.join("independent");
                assert_eq!(OutputNames::plan(&names, independent.clone(), &source, 4, None)?.unwrap(), independent);
                let child = OutputNames::plan(&names, path.join("nested"), &source, 2, Some(path))?.unwrap();
                assert_eq!(child, path.join("nested"));
            }
            path.try_exists()
        },
    ).unwrap().unwrap();
    assert_eq!(probes, 3);
    assert_eq!(output, numbered(&aliased, 4).join("child"));
    assert_eq!(key, output_key(&numbered(&base, 4).join("child")));
    names.lock().unwrap().release(2);
    // A failed query must return its numbered ancestor slot, even though
    // the previous probe transferred that slot to a descendant claim.
    let failure = OutputNames::plan_checked(&names, base.join("failed"), &source, 5, None, |path| {
        assert_eq!(path, numbered(&base, 2));
        Err(io::ErrorKind::PermissionDenied.into())
    }).unwrap().unwrap_err();
    assert_eq!(failure.kind, FailureKind::FilesystemError);
    assert!(!names.lock().unwrap().owners.contains_key(&5));
    assert_eq!(OutputNames::plan(&names, base.join("retry"), &source, 5, None).unwrap().unwrap(),
        numbered(&base, 2).join("retry"));
    let mut names = names.lock().unwrap();
    for owner in [1, 3, 4, 5, 10] { names.release(owner); }
    assert!(names.claimed.is_empty() && names.owners.is_empty() && names.slots.is_empty());
    drop(names);
    // When the claimed ancestor is the junction itself, numbering must
    // stay beside the alias, not beside its deeper physical destination.
    let names = Mutex::new(OutputNames::default());
    assert!(OutputNames::retain(&names, &root, 6, &source, None));
    let (moved, key) = OutputNames::plan_checked(&names, alias.join("branch/leaf"),
        &source, 7, None, Path::try_exists).unwrap().unwrap();
    assert_eq!(moved, numbered(&alias, 1).join("branch/leaf"));
    assert_eq!(key, output_key(&moved));
    names.lock().unwrap().release(7);
    assert!(OutputNames::retain(&names, alias.parent().unwrap(), 8, &source, None));
    let (moved, key) = OutputNames::plan_checked(&names, alias.join("branch/leaf"),
        &source, 9, None, Path::try_exists).unwrap().unwrap();
    assert_eq!(moved, numbered(alias.parent().unwrap(), 1).join("shortcut/branch/leaf"));
    assert_eq!(key, output_key(&moved));
    fs::remove_dir(&alias).unwrap();
    fs::remove_dir(alias.parent().unwrap()).unwrap();
    fs::remove_dir_all(source.with_extension("output")).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn output_registration_does_not_hold_naming_gate_and_failure_releases_only_its_claim() {
    struct Register<'a>(&'a Mutex<OutputNames>);
    impl Observer for Register<'_> {
        fn notify(&self, _: Event) {}
        fn register_output(&self, result: &ArchiveResult, path: &Path) -> io::Result<()> {
            drop(self.0.try_lock().expect("registration held the global naming gate"));
            // Simulate a peer selecting the same tree during publication.
            let peer = OutputNames::plan(self.0, path.to_owned(), &result.path, 2, None)?.unwrap();
            assert_ne!(peer, path);
            Err(super::super::OutputCreateError::wrap(io::ErrorKind::PermissionDenied.into()))
        }
    }
    let source = crate::test_support::temp_file("unlocked_output_registration", b"input");
    let preferred = source.with_extension("output");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    let names = Mutex::new(OutputNames::default());
    let failure = OutputNames::reserve(&names, preferred.clone(), &result, &Register(&names), 1, None)
        .unwrap().unwrap_err();
    assert!(matches!(failure.context.as_deref(),
        Some(super::super::FailureContext::OutputCreate { path: Some(path), .. }) if path == &preferred));
    assert!(!names.lock().unwrap().owners.contains_key(&1));
    assert_eq!(names.lock().unwrap().claimed.len(), 1);
    assert_eq!(OutputNames::plan(&names, preferred.clone(), &result.path, 3, None).unwrap().unwrap(), preferred);
    names.lock().unwrap().release(2);
    names.lock().unwrap().release(3);
    assert!(names.lock().unwrap().claimed.is_empty());
    fs::remove_file(source).unwrap();
}

#[test]
fn output_creation_collision_retries_without_reusing_external_directory() {
    struct Collision(PathBuf);
    impl Observer for Collision {
        fn notify(&self, _: Event) {}
        fn register_output(&self, _: &ArchiveResult, path: &Path) -> io::Result<()> {
            if path == self.0 {
                fs::create_dir(path)?;
                fs::write(path.join("user-file"), b"keep")?;
            }
            crate::scan::scope::create_output_root_exclusive(path)
                .map_err(super::super::OutputCreateError::wrap)
        }
    }
    let source = crate::test_support::temp_file("output_create_collision", b"input");
    let preferred = source.with_extension("output");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    let names = Mutex::new(OutputNames::default());
    let output = OutputNames::reserve(&names, preferred.clone(), &result,
        &Collision(preferred.clone()), 1, None).unwrap().unwrap();
    assert_eq!(output, numbered(&preferred, 1));
    assert_eq!(fs::read(preferred.join("user-file")).unwrap(), b"keep");
    assert_eq!(names.lock().unwrap().claimed.len(), 1);
    fs::remove_dir(output).unwrap();
    fs::remove_dir_all(&preferred).unwrap();
    // A dangling directory entry is not a competing created directory.
    // main's mkdir fails once; retrying it must not select the same name.
    let target = source.with_extension("target");
    fs::create_dir(&target).unwrap();
    let junction = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"]).arg(&preferred).arg(&target).output().unwrap();
    assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stdout));
    fs::remove_dir(&target).unwrap();
    let failure = OutputNames::reserve(&names, preferred.clone(), &result,
        &|_: Event| {}, 2, None).unwrap().unwrap_err();
    assert_eq!(failure.kind, FailureKind::FilesystemError);
    assert!(!names.lock().unwrap().owners.contains_key(&2));
    fs::remove_dir(&preferred).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn independent_output_trees_survive_peer_cleanup_and_creation_failure() {
    struct ObserverWithFailure;
    impl Observer for ObserverWithFailure {
        fn notify(&self, _: Event) {}
        fn register_output(&self, _: &ArchiveResult, path: &Path) -> io::Result<()> {
            if path.file_name().is_some_and(|name| name == "denied") {
                return Err(super::super::OutputCreateError::wrap(
                    io::ErrorKind::PermissionDenied.into(),
                ));
            }
            if path.file_name().is_some_and(|name| name == "journal") {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "journal unavailable"));
            }
            crate::scan::scope::create_output_root_exclusive(path)
                .map_err(super::super::OutputCreateError::wrap)
        }
    }
    let source = crate::test_support::temp_file("output_isolation", b"input");
    let root = source.with_extension("output");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    // Match main's coarse lifecycle: both orders, same/different request
    // owners, owned recursion, foreign input and continued output refusal.
    for descendant_first in [false, true] {
      for shared_request in [false, true] {
        let registry = Arc::new(Mutex::new(OutputNames::default()));
        let owner = if shared_request { 1 } else { 2 };
        let first = OutputReservationGuard { registry: Arc::clone(&registry), owner: 1 };
        let second = OutputReservationGuard { registry: Arc::clone(&registry), owner };
        let preferred = root.join("a");
        let descendant = preferred.join("sub").join("b");
        let (failed, successful) = if descendant_first {
            let successful = OutputNames::reserve(&registry, descendant.clone(), &result, &ObserverWithFailure, owner, None).unwrap().unwrap();
            (OutputNames::reserve(&registry, preferred.clone(), &result, &ObserverWithFailure, 1, None).unwrap().unwrap(), successful)
        } else {
            let failed = OutputNames::reserve(&registry, preferred.clone(), &result, &ObserverWithFailure, 1, None).unwrap().unwrap();
            (failed, OutputNames::reserve(&registry, descendant.clone(), &result, &ObserverWithFailure, owner, None).unwrap().unwrap())
        };
        assert!(!successful.starts_with(&failed) && !failed.starts_with(&successful));
        fs::write(successful.join("payload"), b"keep").unwrap();
        let generated = successful.join("nested.zip");
        let nested = successful.join("nested");
        assert_eq!(OutputNames::reserve(&registry, nested.clone(), &result, &ObserverWithFailure, owner, Some(&generated))
            .unwrap().unwrap(), nested);
        let foreign = OutputNames::reserve(&registry, successful.join("foreign"), &result, &ObserverWithFailure, 3, Some(&generated))
            .unwrap().unwrap();
        assert!(!foreign.starts_with(&successful));
        assert!(!OutputNames::retain(&registry, &successful.join("continued"), 3, &result.path, None));
        cleanup_owned_output(&failed).unwrap();
        assert_eq!(fs::read(successful.join("payload")).unwrap(), b"keep");
        assert_eq!(OutputNames::reserve(&registry, root.join("denied"), &result, &ObserverWithFailure, owner, None)
            .unwrap().unwrap_err().kind, FailureKind::FilesystemError);
        assert!(OutputNames::reserve(&registry, root.join("journal"), &result, &ObserverWithFailure, owner, None).is_err());
        // Released owners leave bounded family history, not ownership.
        // More families evict history without affecting live claims.
        for short_owner in 10..42 {
            let family = root.join(format!("family-{short_owner}"));
            fs::create_dir(&family).unwrap();
            OutputNames::reserve(&registry, family.clone(), &result, &ObserverWithFailure, short_owner, None)
                .unwrap().unwrap();
            assert!(registry.lock().unwrap().indices.peek(output_key(&family).as_str()).is_some());
            registry.lock().unwrap().release(short_owner);
            assert!(registry.lock().unwrap().indices.len() <= OUTPUT_HISTORY_LIMIT);
            assert!(!registry.lock().unwrap().owners.contains_key(&short_owner));
        }
        registry.lock().unwrap().release(3);
        drop(second);
        drop(first);
        assert!(registry.lock().unwrap().claimed.is_empty());
        registry.lock().unwrap().clear_history();
        assert_eq!(registry.lock().unwrap().indices.len(), 0);
        fs::remove_dir_all(&root).unwrap();
      }
    }
    fs::remove_file(source).unwrap();
}

#[test]
fn failed_segment_plans_name_without_creating_recoverable_output() {
    let source = crate::test_support::temp_file("planned_segment", b"carrier");
    let root = source.with_extension("output");
    fs::create_dir(&root).unwrap();
    let preferred = root.join("segment");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "segment".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    let names = Mutex::new(OutputNames::default());
    let failed = OutputNames::plan(&names, preferred.clone(), &result.path, 1, None).unwrap().unwrap();
    let sibling = OutputNames::plan(&names, preferred.clone(), &result.path, 1, None).unwrap().unwrap();
    assert_eq!(failed, preferred);
    assert_eq!(sibling, numbered(&preferred, 1));
    assert!(!failed.exists() && !sibling.exists());
    names.lock().unwrap().release(1);
    assert!(OutputNames::retain(&names, &failed, 2, &source, Some(&root)));
    assert!(OutputNames::retain(&names, &sibling, 2, &source, Some(&root)));
    assert_eq!(OutputNames::plan(&names, preferred.clone(), &result.path, 2, None).unwrap().unwrap(), numbered(&preferred, 2));
    fs::remove_dir(root).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn output_history_survives_requests_rechecks_released_slots_and_stays_bounded() {
    struct Create;
    impl Observer for Create {
        fn notify(&self, _: Event) {}
        fn register_output(&self, _: &ArchiveResult, path: &Path) -> io::Result<()> {
            crate::scan::scope::create_output_root_exclusive(path)
                .map_err(super::super::OutputCreateError::wrap)
        }
    }
    let source = crate::test_support::temp_file("output_history", b"input");
    let root = source.with_extension("output");
    fs::create_dir(&root).unwrap();
    let preferred = root.join("archive");
    fs::create_dir(&preferred).unwrap();
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    let names = Mutex::new(OutputNames::default());
    let family = output_key(&preferred);
    for owner in 1..=32 {
        let output = OutputNames::reserve(&names, preferred.clone(), &result, &Create, owner, None).unwrap().unwrap();
        assert_eq!(output, numbered(&preferred, owner as usize));
        names.lock().unwrap().release(owner);
        let guard = names.lock().unwrap();
        let history = guard.indices.peek(family.as_str()).unwrap();
        assert_eq!(history.next, owner as usize + 1);
        assert_eq!(history.available.first(), Some(&(owner as usize)));
    }
    // Released reservations remain reusable if their actual output is
    // removed, rather than blindly allocating ever increasing numbers.
    fs::remove_dir(numbered(&preferred, 32)).unwrap();
    assert_eq!(OutputNames::reserve(&names, preferred.clone(), &result, &Create, 33, None).unwrap().unwrap(), numbered(&preferred, 32));
    names.lock().unwrap().release(33);
    fs::remove_dir(&preferred).unwrap();
    assert_eq!(OutputNames::reserve(&names, preferred.clone(), &result, &Create, 34, None).unwrap().unwrap(), preferred);
    names.lock().unwrap().release(34);
    struct Fail;
    impl Observer for Fail {
        fn notify(&self, _: Event) {}
        fn register_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
            Err(super::super::OutputCreateError::wrap(io::ErrorKind::PermissionDenied.into()))
        }
    }
    assert!(OutputNames::reserve(&names, preferred.clone(), &result, &Fail, 35, None).unwrap().is_err());
    assert_eq!(OutputNames::reserve(&names, preferred.clone(), &result, &Create, 36, None).unwrap().unwrap(), numbered(&preferred, 33));
    names.lock().unwrap().release(36);
    for index in 0..(OUTPUT_HISTORY_LIMIT + 1) { names.lock().unwrap().next_index(&Arc::from(format!("family-{index}"))); }
    assert_eq!(names.lock().unwrap().indices.len(), OUTPUT_HISTORY_LIMIT);
    assert!(names.lock().unwrap().indices.peek(family.as_str()).is_none());
    assert!(names.lock().unwrap().slots.values().all(|slots| !slots.contains_key(family.as_str())));
    names.lock().unwrap().clear_history();
    let names = names.lock().unwrap();
    assert_eq!(names.indices.len(), 0);
    assert!(names.slots.is_empty());
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn completed_failures_are_carried_until_their_dependencies_change() {
    let source = crate::test_support::temp_file("failure_receipts", b"archive");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    let mut generations = HashMap::from([(
        path_key(&input.entry_path), capture_file_generation(&source).unwrap(),
    )]);
    let mut keys = Vec::new();
    for kind in [None, Some(FailureKind::Damaged), Some(FailureKind::WrongPassword)] {
        let mut result = receipt(&input, DiscoverySource::Embedded, 1);
        result.failure = kind.map(|kind| Failure::new(kind, "failed"));
        // Successful receipts do not require opening any output directory.
        if kind.is_none() { result.output = Some(source.with_extension("not-created")); }
        let mut checkpoint = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap();
        checkpoint.set_password_signature(|| "before".into());
        let checkpoint: InputCheckpoint = serde_json::from_slice(
            &serde_json::to_vec(&checkpoint).unwrap(),
        ).unwrap();
        assert!(checkpoint.valid_for(&input, &generations));
        assert!(checkpoint.password_unchanged(|| "before".into()));
        assert_eq!(checkpoint.password_unchanged(|| "after".into()), kind != Some(FailureKind::WrongPassword));
        let restored = checkpoint.result(1);
        assert_eq!(restored.failure.as_ref().map(|failure| failure.kind), kind);
        assert_eq!(restored.output, result.output);
        assert!(!restored.partial);
        keys.push(checkpoint);
    }
    fs::write(&source, b"changed generation").unwrap();
    generations.insert(path_key(&input.entry_path), capture_file_generation(&source).unwrap());
    assert!(keys.iter().all(|checkpoint| !checkpoint.valid_for(&input, &generations)));
    fs::remove_file(source).unwrap();
}

#[test]
#[cfg(windows)]
fn complete_carrier_keeps_salvage_only_with_a_complete_sibling() {
    for (complete_sibling, damaged) in [(false, true), (true, true), (true, false)] {
        let source = crate::test_support::temp_file("carrier_salvage", &[0; 16]);
        let container = source.with_extension("output");
        fs::create_dir(&container).unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(),
            container.file_name().unwrap().to_string_lossy().into_owned());
        let inputs: Vec<_> = archive_input_slices(&input, &[
            ("zip", 0, Some(8)), ("zip", 8, Some(16)),
        ]).unwrap().0.into_iter().map(Option::unwrap).collect();
        let generations = HashMap::from([
            (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
        ]);
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(vec![source.clone()], Mode::Extract);
        request.max_depth = 0;
        Arc::make_mut(&mut request.config).extraction.content_requirement = ContentRequirement::Complete;
        Arc::make_mut(&mut request.config).post_extract.archive_cleanup_mode = CleanupMode::Keep;
        for (index, input) in inputs.iter().enumerate() {
            let output = container.join(format!("segment-{index}"));
            fs::create_dir(&output).unwrap();
            fs::write(output.join("payload"), b"keep").unwrap();
            let mut result = receipt(input, DiscoverySource::Embedded, 1);
            result.output = Some(output);
            result.files = 1;
            result.bytes = 4;
            if (index != 0 && damaged) || !complete_sibling {
                result.partial = true;
                result.recovered_complete_files = 1;
                result.failure = Some(Failure::new(FailureKind::Damaged, "CRC error"));
            }
            request.checkpoints.push(InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap());
        }
        let observer = |_: Event| {};
        let mut run = test_run(&engine, &request, &observer);
        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
            Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
        }
        let task = Task {
            primary: None,
            inputs: inputs.into_iter().map(|input| LogicalInput { input, password: None, failure: None }).collect(),
            owned_paths: vec![source.to_string_lossy().into_owned()],
            source: DiscoverySource::Embedded,
            context: None,
        };
        let outcome = Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
            run.execute_task(run.register_task(task), 1, 1, None, spawner)
        }).unwrap();
        assert_eq!(outcome.archives.len(), 2);
        assert_eq!(outcome.failed(), if !damaged { 0 } else if complete_sibling { 1 } else { 2 });
        assert_eq!(outcome.checkpoints.len(), if damaged { 2 } else { 0 },
            "successful carrier plans must not survive in ancestor recovery");
        assert!(outcome.archives.iter().all(|result| !result.partial));
        assert!(source.is_file());
        for index in 0..2 {
            assert_eq!(container.join(format!("segment-{index}/payload")).is_file(), complete_sibling);
        }
        release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
        if container.exists() { fs::remove_dir_all(container).unwrap(); }
        fs::remove_file(source).unwrap();
    }
}

#[test]
fn retained_carrier_recomputes_content_policy_without_reexecuting_inputs() {
    // Exercise the real receipt/aggregate path in both policy directions.
    // Missing-volume reload must not freeze the previous acceptance flag;
    // password and unsupported failures never become accepted partials.
    for kind in [FailureKind::Damaged, FailureKind::MissingVolume,
                 FailureKind::WrongPassword, FailureKind::Unsupported] {
        for (complete_files, has_output) in [(1, true), (0, true), (1, false)] {
            let source = crate::test_support::temp_file("retained_policy_reload", &[0; 16]);
            let container = source.with_extension("output");
            fs::create_dir(&container).unwrap();
            let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(),
                container.file_name().unwrap().to_string_lossy().into_owned());
            let inputs: Vec<_> = archive_input_slices(&input, &[
                ("zip", 0, Some(8)), ("zip", 8, Some(16)),
            ]).unwrap().0.into_iter().map(Option::unwrap).collect();
            let generations = HashMap::from([
                (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
            ]);
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(vec![source.clone()], Mode::Extract);
            request.max_depth = 8;
            Arc::make_mut(&mut request.config).recursive_extract = Recursion::Prompt;
            Arc::make_mut(&mut request.config).filesystem.scan_filters_enabled = false;
            Arc::make_mut(&mut request.config).post_extract.archive_cleanup_mode = CleanupMode::Keep;
            for (index, input) in inputs.iter().enumerate() {
                let output = container.join(format!("segment-{index}"));
                fs::create_dir(&output).unwrap();
                fs::write(output.join("payload"), b"keep").unwrap();
                let mut result = receipt(input, DiscoverySource::Embedded, 1);
                result.output = Some(output);
                result.files = 1;
                result.bytes = 4;
                if index == 1 {
                    result.failure = Some(Failure::new(kind, "retained failure"));
                    result.recovered_complete_files = complete_files;
                    if !has_output { result.output = None; }
                }
                let mut checkpoint = InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap();
                checkpoint.set_password_signature(|| CandidateSet::new(
                    Arc::from([]), None, &RecentPasswords::default(), None,
                ).signature(&input.entry_path));
                request.checkpoints.push(checkpoint);
            }
            for requirement in [ContentRequirement::Complete,
                                ContentRequirement::AllowPartial, ContentRequirement::Complete] {
                Arc::make_mut(&mut request.config).extraction.content_requirement = requirement;
                let outcome = {
                    struct RetainedOnly(Mutex<Option<PathBuf>>);
                    impl Observer for RetainedOnly {
                        fn notify(&self, event: Event) {
                            if let Event::Finished { id: 1, result, .. } = event {
                                *self.0.lock().unwrap() = result.output;
                            }
                        }
                        fn allow_recursive(&self, _: usize, _: usize) -> bool {
                            panic!("retained output must not be scanned or prompt again");
                        }
                    }
                    let observer = RetainedOnly(Mutex::new(None));
                    let mut run = test_run(&engine, &request, &observer);
                    for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                        Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
                    }
                    let task = Task {
                        primary: None,
                        inputs: inputs.iter().cloned().map(|input| LogicalInput {
                            input, password: None, failure: None,
                        }).collect(),
                        owned_paths: vec![source.to_string_lossy().into_owned()],
                        source: DiscoverySource::Embedded, context: None,
                    };
                    let outcome = run.recursion.serve(&request.cancel,
                        |depth, pending| observer.allow_recursive(depth, pending),
                        || Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                            run.execute_task(run.register_task(task), 1, 1, None, spawner)
                        }),
                    ).unwrap();
                    assert_eq!(observer.0.lock().unwrap().as_deref(), Some(container.as_path()),
                        "one surviving segment must still report its physical carrier root");
                    outcome
                };
                let accepted = requirement == ContentRequirement::AllowPartial
                    && matches!(kind, FailureKind::Damaged | FailureKind::MissingVolume)
                    && complete_files > 0 && has_output;
                assert_eq!(outcome.archives.len(), 2);
                assert_eq!(outcome.archives[1].partial, accepted);
                assert_eq!(outcome.failed(), usize::from(!accepted));
                assert!(outcome.archives.iter().all(|result| result.retained));
                assert!(outcome.errors.is_empty());
                for index in 0..2 {
                    assert_eq!(fs::read(container.join(format!("segment-{index}/payload"))).unwrap(), b"keep");
                }
                request.checkpoints = outcome.checkpoints.into_vec();
            }
            release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
            fs::remove_dir_all(container).unwrap();
            fs::remove_file(source).unwrap();
        }
    }
}

#[test]
fn split_recovery_warning_preserves_original_failure_and_confirmation() {
    let input = ArchiveInput::file("split.zip.001".into(), "zip".into(), "split".into());
    for (split, partial, kind, suspected, expected) in [
        (true, true, FailureKind::Damaged, false, true),
        (true, false, FailureKind::Damaged, true, true),
        (true, false, FailureKind::Damaged, false, false),
        (false, true, FailureKind::Damaged, true, false),
        (true, true, FailureKind::MissingVolume, true, false),
        (true, false, FailureKind::WrongPassword, false, false),
    ] {
        let mut result = receipt(&input, DiscoverySource::Embedded, 1);
        result.partial = partial;
        let mut failure = Failure::new(kind, "native cause");
        failure.evidence = worker_evidence(&json!({"missing_volume_suspected": suspected}), None);
        result.failure = Some(failure);
        project_possible_missing_volume(std::slice::from_mut(&mut result), split);
        let failure = result.failure.unwrap();
        assert_eq!(failure.kind, kind);
        assert_eq!(failure.evidence.as_ref().is_some_and(|e| e.possible_missing_volume), expected);
        let restored: Failure = serde_json::from_value(serde_json::to_value(failure).unwrap()).unwrap();
        assert_eq!(restored.evidence.as_ref().is_some_and(|e| e.possible_missing_volume), expected);
    }
    // One confirmed missing-volume cause suppresses a speculative carrier
    // warning, even when another independently recovered segment is damaged.
    let mut first = receipt(&input, DiscoverySource::Embedded, 1);
    first.partial = true;
    first.failure = Some(Failure::new(FailureKind::Damaged, "CRC"));
    let mut second = receipt(&input, DiscoverySource::Embedded, 1);
    second.partial = true;
    second.failure = Some(Failure::new(FailureKind::MissingVolume, "part2"));
    let mut results = [first, second];
    project_possible_missing_volume(&mut results, true);
    assert!(results.iter().all(|r| !r.failure.as_ref().unwrap().evidence.as_ref()
        .is_some_and(|e| e.possible_missing_volume)));
}

#[test]
fn changed_id_replacement_without_output_clears_rejected_recovery() {
    let source = crate::test_support::temp_file("replacement_rejected_recovery", b"archive");
    let output = source.with_extension("recovery-output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("complete.txt"), b"complete").unwrap();
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let request = Request::new(vec![source.clone()], Mode::Extract);
    let observer = |_: Event| {};
    let run = test_run(&engine, &request, &observer);
    let first = ArchiveInput::file(source.to_string_lossy().into_owned(), "".into(), "original".into());
    let generation = crate::io::reader::capture_file_generation(&source).unwrap();
    let generations = HashMap::from([(path_key(&first.entry_path), generation)]);
    let mut failed = receipt(&first, DiscoverySource::Detection, 1);
    failed.failure = Some(Failure::new(FailureKind::MissingVolume, "missing")
        .with_context(super::super::FailureContext::Extraction));
    failed.output = Some(output.clone());
    failed.files = 1;
    failed.bytes = 8;
    failed.recovered_complete_files = 1;
    let mut checkpoint = InputCheckpoint::create(&source, Arc::new(first.clone()), &failed, &generations, None).unwrap();
    checkpoint.install_report(InputCheckpoint::report_state(&first, &failed,
        Some(&output), None, 1, 1));
    CreatedOutputs::register(&run.created_outputs, &output, &failed);
    let mut outcome = Outcome::default();
    // Exercise real retry cleanup. The second input then fails before
    // writing output, while the original checkpoint still has partial facts.
    assert!(run.discard_failed_output(&failed, &output, &mut outcome).unwrap());
    assert!(!output.exists());
    let mut replacement = first;
    replacement.format_hint = "7z".into();
    assert!(!checkpoint.same_report_input(&replacement));
    let mut second = receipt(&replacement, DiscoverySource::Relations, 1);
    second.failure = Some(Failure::new(FailureKind::WrongPassword, "password")
        .with_context(super::super::FailureContext::PasswordResolution));
    let mut states = vec![InputCheckpoint::report_state(&replacement, &second,
        Some(&output), None, 1, 1)];
    let mut parent_outputs = vec![(second, None, Arc::new(replacement), 1)];
    run.apply_complete_content_policy(&mut parent_outputs, &mut states, Some(&mut checkpoint), &mut outcome).unwrap();
    assert!(!checkpoint.has_recovered_members());
    assert!(!checkpoint.has_output());
    outcome.checkpoints.push(checkpoint);
    let (second, _, input, ..) = &parent_outputs[0];
    let mut checkpoint = InputCheckpoint::create(&source, Arc::clone(input), second, &generations, None).unwrap();
    checkpoint.install_report(states[0].take());
    outcome.checkpoints.push(checkpoint);
    let recovery = InputRecovery::capture(&outcome.checkpoints, &source, None,
        None, 1, true, true).unwrap();
    let report = recovery.report(|failure| json!({"kind": format!("{:?}", failure.kind)}));
    assert_eq!(report["output_dir"], "");
    assert!(recovery.retry_output().is_none());
    for checkpoint in report["inputs"].as_array().unwrap() {
        assert_eq!(checkpoint["output_dir"], "");
        assert_eq!(checkpoint["recovered_complete_files"], 0);
        assert_eq!(checkpoint["complete"], false);
    }
    fs::remove_file(source).unwrap();
}

#[test]
fn replacement_recreates_the_original_numbered_reservation() {
    let source = crate::test_support::temp_file("replacement_output", b"source");
    let preferred = source.with_extension("output");
    fs::create_dir(&preferred).unwrap();
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    let result = receipt(&input, DiscoverySource::Embedded, 1);
    let request = Request::new(vec![source.clone()], Mode::Extract);
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let observer = |_: Event| {};
    let run = test_run(&engine, &request, &observer);
    let output = run.reserve_output(preferred.clone(), &result, None).unwrap().unwrap();
    assert_ne!(output, preferred);
    fs::write(output.join("old"), b"payload").unwrap();
    assert!(run.discard_failed_output(&result, &output, &mut Outcome::default()).unwrap());
    let recreated = run.recreate_reserved_output(&output, &result).unwrap().unwrap();
    assert_eq!(recreated, output);
    assert!(output.is_dir());
    assert!(!output.join("old").exists());
    assert!(run.output_names.registry.lock().unwrap().claimed.contains_key(&output_key(&output)));
    fs::remove_dir(output).unwrap();
    fs::remove_dir(preferred).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn failed_carrier_recovery_counts_choose_only_eligible_output_roots() {
    for kind in [FailureKind::Unsupported, FailureKind::Damaged, FailureKind::MissingVolume] {
        let source = crate::test_support::temp_file("recovery_count_carrier", &[0; 16]);
        let container = source.with_extension("outputs");
        fs::create_dir(&container).unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "carrier".into());
        let inputs: Vec<_> = archive_input_slices(&input, &[("zip", 0, Some(8)), ("zip", 8, Some(16))])
            .unwrap().0.into_iter().map(Option::unwrap).collect();
        let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
        let mut checkpoints = Vec::new();
        for (index, input) in inputs.iter().enumerate() {
            let mut result = receipt(input, DiscoverySource::Embedded, 1);
            let failure = Failure::new(if index == 0 { kind } else { FailureKind::WrongPassword }, "failed segment");
            result.recovered_complete_files = recovery_complete_files(&failure, u64::from(index == 0));
            result.failure = Some(failure);
            if index == 0 {
                let output = container.join("salvaged"); fs::create_dir(&output).unwrap();
                fs::write(output.join("complete.txt"), b"manual recovery").unwrap();
                result.output = Some(output); result.files = 1;
            }
            let mut checkpoint = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, Some(&container)).unwrap();
            checkpoint.install_report(InputCheckpoint::report_state(input, &result, None, None, index + 1, 2));
            checkpoint.set_password_signature(|| "old".into());
            checkpoints.push(checkpoint);
        }
        // Only B's password change invalidates its receipt. A's physical
        // salvage stays on disk, but Unsupported must not retain its root.
        assert!(checkpoints[0].password_unchanged(|| "new".into()));
        assert!(!checkpoints[1].password_unchanged(|| "new".into()));
        let retained = checkpoints[0].retained_container();
        let eligible = kind != FailureKind::Unsupported;
        assert_eq!(retained, eligible.then_some(container.as_path()));
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let mut request = Request::new(vec![source.clone()], Mode::Extract);
        Arc::make_mut(&mut request.config).extraction.content_requirement = ContentRequirement::AllowPartial;
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let selected = match retained {
            Some(root) => root.to_path_buf(),
            None => run.reserve_output(container.clone(), &receipt(&inputs[1], DiscoverySource::Embedded, 1), None).unwrap().unwrap(),
        };
        assert_eq!(selected == container, eligible);
        let recovery = InputRecovery::capture(&checkpoints, &source, Some(&container), None, 2, true, eligible).unwrap();
        let report = recovery.report(|failure| json!({"kind": format!("{:?}", failure.kind)}));
        assert_eq!(report["inputs"][0]["recovered_complete_files"], u64::from(eligible));
        assert_eq!(fs::read(container.join("salvaged/complete.txt")).unwrap(), b"manual recovery");
        if selected != container { fs::remove_dir(selected).unwrap(); }
        fs::remove_dir_all(container).unwrap(); fs::remove_file(source).unwrap();
    }
}

#[test]
fn retained_payload_does_not_authorize_partial_success() {
    for (kind, stage, expected) in [
        ("unsupported_method", "item_extract", true),
        ("data_error", "", true),
        ("unsupported_method", "archive_open", false),
        ("output_filesystem", "item_extract", false),
        ("process_exit", "archive_extract", false),
    ] {
        let frame: WorkerFrame = serde_json::from_str(&serde_json::json!({
            "failure_kind":kind, "failure_stage":stage, "recovered_complete_files":2,
        }).to_string()).unwrap();
        assert_eq!(recoverable_file_count(&frame), expected.then_some(2));
    }
    for kind in [FailureKind::Damaged, FailureKind::MissingVolume,
        FailureKind::WrongPassword, FailureKind::Unsupported, FailureKind::PasswordInconclusive] {
        let failure = Failure::new(kind, "worker failure");
        assert_eq!(recovery_complete_files(&failure, 2),
            if matches!(kind, FailureKind::Damaged | FailureKind::MissingVolume) { 2 } else { 0 });
        assert_eq!(accepts_partial_content(ContentRequirement::AllowPartial, kind, 2),
            matches!(kind, FailureKind::Damaged | FailureKind::MissingVolume));
        assert!(!accepts_partial_content(ContentRequirement::Complete, kind, 2));
        assert!(!accepts_partial_content(ContentRequirement::AllowPartial, kind, 0));
    }
}

#[test]
fn failed_output_cleanup_is_local_but_journal_failure_propagates() {
    struct Journal { fail: bool }
    impl Observer for Journal {
        fn notify(&self, _: Event) {}
        fn discard_output(&self, _: &Path, _: &[PathBuf], _: &Path) -> io::Result<()> {
            if self.fail { Err(io::Error::other("journal unavailable")) } else { Ok(()) }
        }
    }
    let source = crate::test_support::temp_file("discard_failure", b"archive");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    let mut failed = receipt(&input, DiscoverySource::Embedded, 1);
    failed.failure = Some(Failure::new(FailureKind::Damaged, "failed"));
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let request = Request::new(vec![source.clone()], Mode::Extract);
    let observer = Journal { fail: false };
    let run = test_run(&engine, &request, &observer);
    let mut outcome = Outcome::default();
    outcome.archives.push(receipt(&input, DiscoverySource::Embedded, 1));
    // Replaced non-directory output fails independently of ACL privileges.
    CreatedOutputs::register(&run.created_outputs, &source, &failed);
    assert!(!run.discard_failed_output(&failed, &source, &mut outcome).unwrap());
    assert_eq!(outcome.archives.len(), 1);
    assert_eq!(outcome.cleanup_results.len(), 1);
    assert!(run.created_outputs.lock().unwrap().0.contains_key(&output_key(&source)));
    let output = source.with_extension("output");
    fs::create_dir(&output).unwrap();
    let observer = Journal { fail: true };
    let run = test_run(&engine, &request, &observer);
    assert_eq!(run.discard_failed_output(&failed, &output, &mut outcome)
        .unwrap_err().to_string(), "journal unavailable");
    fs::remove_file(source).unwrap();
}

#[test]
fn rollback_isolates_cleanup_failures_and_preserves_journal_errors() {
    struct Discards {
        fail: bool,
        paths: Mutex<Vec<PathBuf>>,
    }
    impl Observer for Discards {
        fn notify(&self, _: Event) {}
        fn discard_output(&self, _: &Path, _: &[PathBuf], output: &Path) -> io::Result<()> {
            self.paths.lock().unwrap().push(output.to_owned());
            if self.fail { Err(io::Error::other("journal unavailable")) } else { Ok(()) }
        }
    }
    let source = crate::test_support::temp_file("rollback_failure", b"source");
    let root = source.with_extension("output");
    let bad = root.join("a-failed");
    let good = root.join("z-cleaned");
    let nested = good.join("child");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    let generations = HashMap::from([
        (path_key(&source.to_string_lossy()), capture_file_generation(&source).unwrap()),
    ]);
    for journal_fails in [false, true] {
        fs::create_dir_all(&bad).unwrap();
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("payload"), b"partial data").unwrap();
        let created = Mutex::default();
        let mut outcome = Outcome::default();
        for output in [&bad, &good, &nested] {
            let mut archive = receipt(&input, DiscoverySource::Embedded, 1);
            archive.output = Some(output.clone());
            archive.files = 1;
            archive.bytes = 12;
            outcome.checkpoints.push(InputCheckpoint::create(&source, Arc::new(input.clone()), &archive, &generations, None).unwrap());
            CreatedOutputs::register(&created, output, &archive);
            outcome.archives.push(archive);
        }
        // Deterministic unsafe-root failure, independent of ACLs/admin rights.
        fs::remove_dir(&bad).unwrap();
        fs::write(&bad, b"replacement must survive").unwrap();
        let observer = Discards { fail: journal_fails, paths: Mutex::default() };
        let mut created = created.into_inner().unwrap();
        let result = created.rollback(&observer, &mut outcome);
        if journal_fails {
            assert_eq!(result.unwrap_err().to_string(), "journal unavailable");
            assert_eq!(created.0.len(), 3);
        } else {
            result.unwrap();
            assert_eq!(created.0.len(), 1);
        }
        assert!(created.0.contains_key(&output_key(&bad)));
        assert_eq!(fs::read(&bad).unwrap(), b"replacement must survive");
        assert!(!good.exists());
        assert_eq!(outcome.cleanup_results.len(), 1);
        assert_eq!(outcome.cleanup_results[0].path, bad);
        assert_eq!(outcome.checkpoints.len(), 1);
        assert_eq!(outcome.checkpoints[0].output(), bad);
        assert_eq!(outcome.archives[0].output.as_ref(), Some(&bad));
        assert!(outcome.archives.iter().skip(1).all(|archive| {
            archive.output.is_none() && archive.files == 0 && archive.bytes == 0
                && archive.failure.as_ref().unwrap().kind == FailureKind::Cancelled
        }));
        let paths = observer.paths.lock().unwrap();
        assert_eq!(paths.len(), 2);
        assert!(!paths.contains(&bad));
        fs::remove_file(&bad).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn cancellation_joins_nested_writer_then_rolls_back_only_uncommitted_trees() {
    struct Discards(Mutex<Vec<PathBuf>>);
    impl Observer for Discards {
        fn notify(&self, _: Event) {}
        fn discard_output(&self, _: &Path, _: &[PathBuf], output: &Path) -> io::Result<()> {
            self.0.lock().unwrap().push(output.to_owned());
            Ok(())
        }
    }
    let source = crate::test_support::temp_file("cancel_output_trees", b"source");
    let root = source.with_extension("output");
    let parent = root.join("parent");
    let nested = parent.join("child");
    let sibling = root.join("completed");
    let retained = root.join("continued");
    let retry_child = retained.join("new-segment");
    let retained_finished = retained.join("finished-carrier");
    let retained_segment = retained_finished.join("segment");
    let retained_source = retained.join("finished-carrier.zip");
    for path in [&nested, &sibling, &retry_child, &retained_segment] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(parent.join("ordinary.txt"), b"parent data").unwrap();
    fs::write(nested.join("partial.txt"), b"in flight").unwrap();
    fs::write(sibling.join("kept.txt"), b"committed").unwrap();
    fs::write(retained.join("old.txt"), b"continued data").unwrap();
    fs::write(retained_source.clone(), b"nested source").unwrap();
    fs::write(retained_segment.join("payload.txt"), b"completed nested data").unwrap();
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "parent".into());
    // A punctuation sibling sorts between the exact key and descendants.
    // Relocation must scan the separator-prefixed range independently.
    let moving = Mutex::default();
    let old = root.join("a");
    let punctuation = root.join("a (2)");
    let new = root.join("relocated");
    let ownership = receipt(&input, DiscoverySource::Embedded, 1);
    for path in [&old, &old.join("child"), &punctuation] {
        CreatedOutputs::register(&moving, path, &ownership);
    }
    let mut moving = moving.into_inner().unwrap();
    moving.relocate_flatten(&old, &old, &new);
    assert!(moving.0.contains_key(&output_key(&new.join("child"))));
    assert!(!moving.0.contains_key(&output_key(&old.join("child"))));
    assert!(moving.0.contains_key(&output_key(&punctuation)));
    let mut outcome = Outcome::default();
    let created = Mutex::default();
    for path in [&parent, &nested, &sibling, &retry_child, &retained_finished, &retained_segment] {
        let mut archive = receipt(&input, DiscoverySource::Embedded, 1);
        archive.output = Some(path.clone());
        CreatedOutputs::register(&created, path, &archive);
        outcome.archives.push(archive);
    }
    CreatedOutputs::commit_if_unowned(&created, &sibling);
    // A freshly created parent still owns its completed nested output.
    CreatedOutputs::commit_if_unowned(&created, &nested);
    assert!(created.lock().unwrap().0.contains_key(&output_key(&nested)));
    // A retained parent does not own rollback: commit the completed child
    // before deleting its archive source. A later sibling cancellation
    // must not delete the only remaining copy of that child's content.
    CreatedOutputs::commit_if_unowned(&created, &retained_finished);
    fs::remove_file(&retained_source).unwrap();
    let cancel = Cancellation::new();
    let gate = Arc::new(Mutex::new((false, None::<Waker>)));
    let (started, entered) = std::sync::mpsc::channel();
    let signal = Arc::clone(&gate);
    let stop = cancel.clone();
    let parent_check = parent.clone();
    let nested_check = nested.clone();
    let stopper = std::thread::spawn(move || {
        entered.recv().unwrap();
        stop.cancel();
        let exists_while_writing = parent_check.join("ordinary.txt").is_file()
            && nested_check.join("partial.txt").is_file();
        let mut signal = signal.lock().unwrap();
        signal.0 = true;
        if let Some(waker) = signal.1.take() {
            waker.wake();
        }
        assert!(exists_while_writing, "rollback ran before the nested writer stopped");
    });
    let nested_writer = nested.clone();
    Scheduler::new().run(1, Origin::Foreground, &cancel, |spawner| {
        Box::pin(async move {
            spawner.spawn(Box::pin(async move {
                let mut started = Some(started);
                poll_fn(move |cx| {
                    let mut gate = gate.lock().unwrap();
                    if gate.0 {
                        Poll::Ready(())
                    } else {
                        gate.1 = Some(cx.waker().clone());
                        if let Some(started) = started.take() {
                            started.send(()).unwrap();
                        }
                        Poll::Pending
                    }
                }).await;
                fs::write(nested_writer.join("writer-finished.txt"), b"joined").unwrap();
            })).wait().await;
        })
    });
    stopper.join().unwrap();
    assert!(nested.join("writer-finished.txt").is_file());
    let observer = Discards(Mutex::default());
    created.into_inner().unwrap().rollback(&observer, &mut outcome).unwrap();
    assert!(!parent.exists());
    assert!(!retry_child.exists());
    assert_eq!(fs::read(sibling.join("kept.txt")).unwrap(), b"committed");
    assert_eq!(fs::read(retained.join("old.txt")).unwrap(), b"continued data");
    assert_eq!(fs::read(retained_segment.join("payload.txt")).unwrap(), b"completed nested data");
    assert!(!retained_source.exists());
    assert!(source.is_file());
    assert_eq!(outcome.archives.iter().filter(|archive| archive.output.is_some()).count(), 3);
    assert!(!observer.0.lock().unwrap().contains(&sibling));
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
#[cfg(windows)]
fn request_cancellation_rolls_back_partial_but_not_complete_or_continued_outputs() {
    // Actual worker receipts, task commit, observer boundary and request
    // rollback. Cancel after the task finishes but before the request does;
    // this is the ownership window exposed by a later sibling cancellation.
    let Ok(worker) = crate::test_support::built_worker() else { return; };
    fn zip(damaged: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut directory = Vec::new();
        for (index, name) in [b"good.txt", b"late.txt"].into_iter().enumerate() {
            let data = b"verified complete member";
            let crc = crc32fast::hash(data) ^ u32::from(damaged && index == 1);
            let offset = bytes.len() as u32;
            bytes.extend(0x04034b50u32.to_le_bytes());
            for value in [20u16, 0, 0, 0, 0] { bytes.extend(value.to_le_bytes()); }
            for value in [crc, data.len() as u32, data.len() as u32] { bytes.extend(value.to_le_bytes()); }
            bytes.extend((name.len() as u16).to_le_bytes()); bytes.extend(0u16.to_le_bytes());
            bytes.extend(name); bytes.extend(data);
            directory.extend(0x02014b50u32.to_le_bytes());
            for value in [20u16, 20, 0, 0, 0, 0] { directory.extend(value.to_le_bytes()); }
            for value in [crc, data.len() as u32, data.len() as u32] { directory.extend(value.to_le_bytes()); }
            for value in [name.len() as u16, 0, 0, 0, 0] { directory.extend(value.to_le_bytes()); }
            directory.extend(0u32.to_le_bytes()); directory.extend(offset.to_le_bytes()); directory.extend(name);
        }
        let offset = bytes.len() as u32;
        let size = directory.len() as u32;
        bytes.extend(directory); bytes.extend(0x06054b50u32.to_le_bytes());
        for value in [0u16, 0, 2, 2] { bytes.extend(value.to_le_bytes()); }
        bytes.extend(size.to_le_bytes()); bytes.extend(offset.to_le_bytes()); bytes.extend(0u16.to_le_bytes());
        bytes
    }
    // Root ID must not collide with the engine-assigned carrier segment
    // IDs: input_finished precedes the physical task commit boundary.
    struct CancelAfterTask { cancel: Cancellation, enabled: bool }
    impl Observer for CancelAfterTask {
        fn notify(&self, event: Event) {
            if self.enabled && matches!(event, Event::Finished { id: 1000, .. }) {
                self.cancel.cancel();
            }
        }
    }
    for multi in [false, true] {
        for damaged in [false, true] {
            for cancel_after in [false, true] {
                let first = zip(damaged);
                let mut bytes = first.clone();
                if multi { bytes.extend(zip(false)); }
                let source = crate::test_support::temp_file("partial_request_cancel", &bytes);
                let output = source.with_extension("output");
                fs::create_dir(&output).unwrap();
                let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
                let inputs = if multi {
                    archive_input_slices(&input, &[("zip", 0, Some(first.len() as u64)),
                        ("zip", first.len() as u64, Some(bytes.len() as u64))])
                        .unwrap().0.into_iter().map(Option::unwrap).collect::<Vec<_>>()
                } else { vec![input] };
                let engine = Engine::new(worker.clone());
                let mut request = Request::new(vec![source.clone()], Mode::Extract);
                request.output_root = Some(output.clone());
                request.max_depth = 0;
                let config = Arc::make_mut(&mut request.config);
                config.extraction.content_requirement = ContentRequirement::AllowPartial;
                config.post_extract.archive_cleanup_mode = CleanupMode::Keep;
                config.post_extract.flatten_single_directory = false;
                let observer = CancelAfterTask { cancel: request.cancel.clone(), enabled: cancel_after };
                let run = test_run(&engine, &request, &observer);
                let task = Task { primary: None, inputs: inputs.iter().cloned().map(|input|
                    LogicalInput { input, password: None, failure: None }).collect(),
                    owned_paths: vec![source.to_string_lossy().into_owned()],
                    source: DiscoverySource::Embedded, context: None };
                let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
                    let run = Arc::clone(&run);
                    Box::pin(async move {
                    let result = run.execute_task(run.register_task(task), 1000, 1, None, spawner).await;
                    let before = result.as_ref().unwrap();
                    assert_eq!(before.archives.len(), if multi { 2 } else { 1 });
                    assert_eq!(before.archives[0].partial, damaged, "multi={multi} cancel={cancel_after} failure={:?}", before.archives[0].failure);
                    assert!(before.archives[0].output.as_ref().unwrap().join("good.txt").is_file());
                    run.finish(result).await
                })}).unwrap();
                assert!(source.is_file());
                for archive in &outcome.archives {
                    assert_eq!(archive.output.is_some(), !cancel_after || !damaged,
                        "multi={multi} damaged={damaged} cancel={cancel_after} failure={:?}", archive.failure);
                }
                if damaged && !cancel_after {
                    // An existing continuation is not newly owned by the
                    // cancelled request and must never be rolled back.
                    let mut continued = request.clone();
                    continued.cancel = Cancellation::new();
                    continued.checkpoints = outcome.checkpoints.into_vec();
                    let observer = CancelAfterTask { cancel: continued.cancel.clone(), enabled: true };
                    let mut run = test_run(&engine, &continued, &observer);
                    for (index, checkpoint) in continued.checkpoints.iter().enumerate() {
                        Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy())))
                            .or_default().insert(checkpoint.key(), index);
                    }
                    let task = Task { primary: None, inputs: inputs.into_iter().map(|input|
                        LogicalInput { input, password: None, failure: None }).collect(),
                        owned_paths: vec![source.to_string_lossy().into_owned()],
                        source: DiscoverySource::Embedded, context: None };
                    let retained = Scheduler::new().run(2, Origin::Foreground, &continued.cancel, |spawner| {
                    let run = Arc::clone(&run);
                    Box::pin(async move {
                        let result = run.execute_task(run.register_task(task), 1000, 1, None, spawner).await;
                        run.finish(result).await
                    })}).unwrap();
                    assert!(retained.archives.iter().all(|archive| archive.retained
                        && archive.output.as_ref().unwrap().join("good.txt").is_file()));
                }
                drop(run);
                drop(engine);
                release_reader_resources_under_roots(vec![output.to_string_lossy().into_owned(), source.to_string_lossy().into_owned()]).unwrap();
                fs::remove_dir_all(output).unwrap();
                fs::remove_file(source).unwrap();
            }
        }
    }
}

#[test]
fn retained_parent_does_not_publish_new_child_before_its_commit_boundary() {
    struct Roots(std::sync::atomic::AtomicUsize);
    impl Observer for Roots {
        const PUBLISHES_ROOTS: bool = true;

        fn notify(&self, _: Event) {}
        async fn root_finished(&self, _: TaskId, _: &Path, _: PublicOutcome, _: u64) -> io::Result<PublicOutcome> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(PublicOutcome::default())
        }
    }
    // Exercise the production root handoff and filesystem rollback at the
    // post-worker/pre-commit boundary. Retained parents are not rollback
    // owners, so a new child must independently prove durable completion.
    for partial in [false, true] {
        let source = crate::test_support::temp_file("retained_root_cancel", b"archive");
        let parent = source.with_extension("retained");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(parent.join("old.txt"), b"old retained data").unwrap();
        fs::write(child.join("new.txt"), b"new extraction").unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "parent".into());
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(Vec::new(), Mode::Extract);
        let observer = Roots(std::sync::atomic::AtomicUsize::new(0));
        let run = test_run(&engine, &request, &observer);
        let mut outer = receipt(&input, DiscoverySource::Embedded, 1);
        outer.retained = true;
        outer.output = Some(parent.clone());
        let mut nested = receipt(&input, DiscoverySource::Embedded, 2);
        nested.output = Some(child.clone());
        nested.partial = partial;
        if partial { nested.failure = Some(Failure::new(FailureKind::Damaged, "accepted files")); }
        CreatedOutputs::register(&run.created_outputs, &child, &nested);
        let mut outcome = Outcome::default();
        outcome.archives = vec![outer, nested].into();
        outcome.uncommitted = true; // cancellation preceded the child's durable commit
        request.cancel.cancel();
        let mut outcome = Scheduler::new().run(1, Origin::Foreground, &Cancellation::new(), |_| {
            Box::pin(run.finish_root(1, &source, Ok(outcome)))
        }).unwrap();
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        run.created_outputs.lock().unwrap().rollback(&observer, &mut outcome).unwrap();
        assert!(parent.join("old.txt").is_file());
        assert!(!child.exists());
        assert_eq!(outcome.archives[1].failure.as_ref().unwrap().kind, FailureKind::Cancelled);
        assert!(!outcome.settled());
        fs::remove_dir_all(parent).unwrap();
        fs::remove_file(source).unwrap();
    }
}

#[test]
fn cancelled_recursive_batch_returns_incomplete_outcome_not_parent_unwind() {
    struct CancelOnQueue(Cancellation);
    impl Observer for CancelOnQueue {
        fn notify(&self, event: Event) {
            if matches!(event, Event::Queued { .. }) {
                self.0.cancel();
            }
        }
    }
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let request = Request::new(Vec::new(), Mode::Extract);
    let observer = CancelOnQueue(request.cancel.clone());
    let run = test_run(&engine, &request, &observer);
    let input = ArchiveInput::file("parent/child.zip".into(), "zip".into(), "child".into());
    let batch = Discovered {
        tasks: vec![Task {
            primary: None,
            inputs: vec![LogicalInput { input, password: None, failure: None }],
            owned_paths: Vec::new(),
            source: DiscoverySource::Embedded,
            context: None,
        }],
        errors: Vec::new(),
        scan_errors: DirectoryReadErrors::report(),
        blocked_paths: HashSet::new(),
    };
    let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
        Box::pin(run.execute_batch(batch, 2, None, Some(1), spawner, None))
    }).expect("cancellation must not bypass the parent's output commit");
    assert_eq!(outcome.archives.len(), 1);
    assert_eq!(outcome.archives[0].failure.as_ref().unwrap().kind, FailureKind::Cancelled);
    assert!(!outcome.subtree_complete());
    assert!(!is_cancellation(&io::Error::other("journal failure")));
    // A fully undispatched recursive batch still carries incompleteness;
    // an empty result cannot authorize a parent/carrier commit.
    let input = ArchiveInput::file("parent/unstarted.zip".into(), "zip".into(), "unstarted".into());
    let batch = Discovered {
        tasks: vec![Task {
            primary: None,
            inputs: vec![LogicalInput { input, password: None, failure: None }],
            owned_paths: Vec::new(), source: DiscoverySource::Embedded, context: None,
        }],
        errors: Vec::new(), scan_errors: DirectoryReadErrors::report(), blocked_paths: HashSet::new(),
    };
    let outcome = Scheduler::new().run(2, Origin::Foreground, &request.cancel, |spawner| {
        Box::pin(run.execute_batch(batch, 2, None, Some(1), spawner, None))
    }).unwrap();
    assert!(outcome.archives.is_empty());
    assert!(outcome.uncommitted);
    assert!(!outcome.subtree_complete());
}

#[test]
fn numbered_outputs_share_unicode_decimal_syntax_with_recursion() {
    for name in ["archive(１)", "archive(١)", "archive(𝟙)"] {
        let path = Path::new(name);
        assert_eq!(numbered(path, 1), PathBuf::from("archive(2)"));
        assert!(output_candidate(path, Path::new("archive(2)")));
    }
    for name in ["archive(²)", "archive(+1)", "archive(1_0)"] {
        assert_eq!(numbered(Path::new(name), 1), PathBuf::from(format!("{name}(1)")));
    }
}

#[test]
fn flatten_work_avoids_unmaterialized_output_claim_and_releases_its_slot() {
    struct Work(Mutex<Option<PathBuf>>);
    impl Observer for Work {
        fn notify(&self, _: Event) {}
        fn before_flatten(&self, _: &Path, work: &Path, _: &Path, _: &Path) -> io::Result<()> {
            *self.0.lock().unwrap() = Some(work.to_owned());
            Ok(())
        }
    }
    let source = crate::test_support::temp_file("flatten_reserved", b"archive");
    let output = source.with_extension("output");
    fs::create_dir_all(output.join("wrapper")).unwrap();
    fs::write(output.join("wrapper/payload.txt"), b"payload").unwrap();
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "sample".into());
    let mut archive = receipt(&input, DiscoverySource::Embedded, 1);
    archive.output = Some(output.clone());
    let mut work = output.as_os_str().to_os_string();
    work.push(".__sunpack_flatten_work__");
    let preferred = PathBuf::from(work);
    let names = OutputReservationGuard { registry: Arc::default(), owner: 1 };
    let reserved = OutputNames::plan(&names.registry, preferred.clone(), &archive.path, 2, None).unwrap().unwrap();
    assert_eq!(reserved, preferred);
    assert!(!reserved.exists()); // Peer has claimed but not created its output.
    let observer = Work(Mutex::default());
    let mut outcome = Outcome::default();
    flatten_result(&observer, 1, &mut archive, &mut outcome, None, &names, crate::core::config::FlattenDirectoryName::Outer).unwrap();
    let staging = observer.0.lock().unwrap().clone().unwrap();
    assert_ne!(staging, reserved);
    assert!(outcome.cleanup_results.is_empty());
    assert_eq!(fs::read(output.join("payload.txt")).unwrap(), b"payload");
    let registry = names.registry.lock().unwrap();
    assert!(registry.claimed.contains_key(&output_key(&reserved)));
    assert!(!registry.claimed.contains_key(&output_key(&staging)));
    drop(registry);
    fs::remove_dir_all(output).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn flatten_inner_reserves_unique_name_and_rebases_rollback_receipts() {
    struct Discards(Mutex<Vec<PathBuf>>);
    impl Observer for Discards {
        fn notify(&self, _: Event) {}
        fn discard_output(&self, _: &Path, _: &[PathBuf], output: &Path) -> io::Result<()> {
            self.0.lock().unwrap().push(output.to_owned());
            Ok(())
        }
    }
    let source = crate::test_support::temp_file("flatten_cancel_receipts", b"input");
    let output = source.with_extension("output");
    let occupied = source.with_extension("inner");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("unrelated"), b"peer").unwrap();
    let leaf = output.join("wrapper").join(occupied.file_name().unwrap());
    let child = leaf.join("child");
    fs::create_dir_all(&child).unwrap();
    fs::write(leaf.join("ordinary.txt"), b"keep").unwrap();
    fs::write(child.join("payload.txt"), b"child").unwrap();
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "parent".into());
    let mut archive = receipt(&input, DiscoverySource::Embedded, 1);
    archive.output = Some(output.clone());
    let mut nested = receipt(&input, DiscoverySource::Embedded, 2);
    nested.output = Some(child.clone());
    let created = Mutex::new(CreatedOutputs::default());
    CreatedOutputs::register(&created, &output, &archive);
    let mut leaf_archive = receipt(&input, DiscoverySource::Embedded, 2);
    leaf_archive.path = output.join("inner.zip");
    CreatedOutputs::register(&created, &leaf, &leaf_archive);
    CreatedOutputs::register(&created, &child, &nested);
    let mut children = Outcome::default();
    children.archives.push(nested);
    let observer = Discards(Mutex::default());
    let names = OutputReservationGuard { registry: Arc::default(), owner: 1 };
    flatten_result(&observer, 1, &mut archive, &mut children, Some(&created), &names, crate::core::config::FlattenDirectoryName::Inner).unwrap();
    let destination = numbered(&occupied, 1);
    assert_eq!(archive.output.as_ref(), Some(&destination));
    assert!(names.registry.lock().unwrap().claimed.contains_key(&output_key(&destination)));
    assert_eq!(created.lock().unwrap().0.get(&output_key(&destination)).unwrap().archive, source);
    let published_child = destination.join("child");
    assert_eq!(children.archives[0].output.as_ref(), Some(&published_child));
    assert!(published_child.join("payload.txt").is_file());
    created.lock().unwrap().rollback(&observer, &mut children).unwrap();
    let discarded = observer.0.lock().unwrap();
    assert!(discarded.contains(&published_child));
    assert!(!discarded.contains(&child));
    assert!(!output.exists());
    assert!(!destination.exists());
    assert_eq!(fs::read(occupied.join("unrelated")).unwrap(), b"peer");
    fs::remove_dir_all(occupied).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
#[cfg(windows)]
fn flatten_failure_keeps_extraction_successful_and_reports_output() {
    use std::os::windows::fs::OpenOptionsExt;
    let source = crate::test_support::temp_file("flatten_warning", b"input");
    let output = source.with_extension("output");
    let wrapper = output.join("wrapper");
    fs::create_dir_all(&wrapper).unwrap();
    fs::write(wrapper.join("payload.txt"), b"payload").unwrap();
    let input = ArchiveInput::file(
        source.to_string_lossy().into_owned(),
        "zip".into(),
        "sample".into(),
    );
    let mut archive = receipt(&input, DiscoverySource::Embedded, 1);
    archive.output = Some(output.clone());
    let mut outcome = Outcome::default();

    // FILE_LIST_DIRECTORY participates in delete sharing; an attributes-only
    // handle does not block rename on Windows. Hold the real root rename
    // failure, distinct from ordinary source-cleanup warnings.
    let held = fs::OpenOptions::new().access_mode(0x1).share_mode(3)
        .custom_flags(0x0200_0000).open(&output).unwrap();
    let result = flatten_result(&|_: Event| {}, 1, &mut archive, &mut outcome, None, &OutputReservationGuard { registry: Arc::default(), owner: 1 }, crate::core::config::FlattenDirectoryName::Outer);
    let payload = fs::read(wrapper.join("payload.txt"));
    drop(held);
    fs::remove_dir_all(&output).unwrap();
    fs::remove_file(&source).unwrap();

    result.unwrap();
    outcome.archives.push(archive);
    assert_eq!(outcome.succeeded(), 1);
    assert_eq!(outcome.failed(), 0);
    assert!(!outcome.subtree_complete(), "ancestors must not flatten an unsettled child");
    let mut source_warning = Outcome::default();
    record_cleanup(&mut source_warning, &source, "delete", Err(io::ErrorKind::PermissionDenied.into()));
    assert!(source_warning.subtree_complete(), "source cleanup alone does not block ancestors");
    assert_eq!(outcome.archives[0].output.as_ref(), Some(&output));
    assert_eq!(payload.unwrap(), b"payload");
    assert!(
        outcome.cleanup_results.len() == 1 && matches!(outcome.cleanup_results.iter().next(), Some(CleanupResult { path, mode: "flatten", status: CleanupStatus::Failed, .. }) if path == &output)
    );
}

#[test]
fn completed_extract_compacts_segments_but_keeps_nested_summary_and_retry_receipts() {
    struct DetailedPublication(std::sync::atomic::AtomicBool);
    impl Observer for DetailedPublication {
        const PUBLISHES_ROOTS: bool = true;

        fn notify(&self, _: Event) {}
        async fn root_finished(&self, _: TaskId, _: &Path, outcome: PublicOutcome, _: u64) -> io::Result<PublicOutcome> {
            assert_eq!(outcome.archives.len(), 3);
            assert_eq!(outcome.checkpoints.len(), 3);
            assert!(outcome.archives.iter().all(|entry| !entry.source_paths.is_empty() && entry.password.is_some()));
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(outcome)
        }
    }
    let source = crate::test_support::temp_file("completed_extract_summary", b"source");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
    let generations = HashMap::from([
        (path_key(&source.to_string_lossy()), capture_file_generation(&source).unwrap()),
    ]);
    let output = source.with_extension("output");
    // None: successful physical carrier. Failure/partial: receipts must
    // remain available for CLI retry and durable observer publication.
    for (mode, failure_kind, partial, uncommitted) in [
        (Mode::Extract, None, false, false),
        (Mode::Extract, Some(FailureKind::WrongPassword), false, false),
        (Mode::Extract, Some(FailureKind::Damaged), true, false),
        (Mode::Extract, None, false, true),
        (Mode::Scan, None, false, false),
    ] {
        let mut outcome = Outcome::default();
        for index in 0..3 {
            let mut archive = receipt(&input, DiscoverySource::Embedded, if index == 2 { 2 } else { 1 });
            if index == 2 { archive.path = output.join("nested.zip"); }
            archive.offset = index * 100;
            archive.output = Some(output.join(format!("segment{index}")));
            archive.files = 1;
            archive.bytes = 10;
            archive.password = Some("successful-password".into());
            if index == 1 {
                archive.partial = partial;
                archive.failure = failure_kind.map(|kind| {
                    let mut failure = Failure::new(kind, "worker diagnostic");
                    failure.evidence = worker_evidence(&json!({"failure_stage": "item_extract"}), None);
                    failure
                });
            }
            outcome.checkpoints.push(InputCheckpoint::create(&source, Arc::new(input.clone()), &archive, &generations, None).unwrap());
            outcome.archives.push(archive);
        }
        outcome.uncommitted = uncommitted;
        let before = serde_json::to_value(outcome.checkpoints.iter().collect::<Vec<_>>()).unwrap();
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(Vec::new(), mode);
        let observer = DetailedPublication(std::sync::atomic::AtomicBool::new(false));
        let run = test_run(&engine, &request, &observer);
        let outcome = Scheduler::new().run(1, request.origin, &request.cancel, |_| {
            Box::pin(run.finish_root(1, &source, Ok(outcome)))
        }).unwrap();
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::SeqCst), !uncommitted);
        if uncommitted || mode == Mode::Scan {
            assert_eq!(outcome.archives.len(), 3);
            assert!(outcome.archives.iter().all(|entry| entry.password.is_some()));
            assert_eq!(serde_json::to_value(outcome.checkpoints.iter().collect::<Vec<_>>()).unwrap(), before);
        } else if failure_kind.is_some() {
            assert_eq!(outcome.archives.len(), 3);
            assert_eq!(serde_json::to_value(outcome.checkpoints.iter().collect::<Vec<_>>()).unwrap(), before);
            let failure = outcome.archives[1].failure.as_ref().unwrap();
            assert_eq!(Some(failure.kind), failure_kind);
            assert_eq!(failure.message, "worker diagnostic");
            assert_eq!(failure.evidence.as_ref().unwrap().stage.as_deref(), Some("item_extract"));
            assert_eq!(outcome.archives[1].partial, partial);
            assert!(outcome.archives.iter().all(|entry| entry.source_paths.is_empty() && entry.password.is_none()));
        } else {
            assert!(outcome.checkpoints.is_empty());
            assert_eq!(outcome.checkpoints.capacity(), 0);
            assert_eq!(outcome.archives.len(), 2);
            assert_eq!(outcome.archives[0].output.as_ref(), Some(&output));
            assert_eq!((outcome.archives[0].files, outcome.archives[0].bytes), (2, 20));
            assert_eq!(outcome.archives[1].depth, 2);
            assert_eq!(outcome.archives[1].path, output.join("nested.zip"));
            assert_eq!(outcome.succeeded(), 2);
            assert_eq!(outcome.failed(), 0);
            assert!(outcome.archives.iter().all(|entry| entry.source_paths.is_empty() && entry.password.is_none()));
        }
    }
    fs::remove_file(source).unwrap();
}

#[test]
fn declined_watch_input_retires_without_worker_success_or_cleanup() {
    struct Decline(Mutex<Vec<Event>>);
    impl Observer for Decline {
        fn input_admission_enabled(&self) -> bool { true }
        fn notify(&self, event: Event) { self.0.lock().unwrap().push(event); }
        fn admit_inputs(&self, owner: &Path, inputs: &[&ArchiveInput], members: &[String], depth: usize) -> io::Result<bool> {
            assert!(super::super::scheduling::in_stage());
            assert_eq!(depth, 1);
            assert_eq!(inputs.len(), 1);
            assert_eq!(owner, Path::new(&inputs[0].entry_path));
            assert_eq!(members, &[inputs[0].entry_path.clone()]);
            Ok(false)
        }
        fn register_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
            panic!("declined input cannot reserve output")
        }
    }
    let source = crate::test_support::temp_file("declined_watch_input", b"unchanged source");
    let engine = Engine::new(PathBuf::from("must-not-start-worker.exe"));
    let mut request = Request::new(vec![source.clone()], Mode::Extract);
    request.origin = Origin::Watch;
    let observer = Decline(Mutex::default());
    let run = test_run(&engine, &request, &observer);
    let task = Task {
        primary: None, owned_paths: vec![source.to_string_lossy().into_owned()],
        inputs: vec![LogicalInput {
            input: ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into()),
            password: None, failure: None,
        }], source: DiscoverySource::Detection, context: None,
    };
    let result = Scheduler::new().run(1, Origin::Watch, &request.cancel, |spawner| {
        run.execute_task(run.register_task(task), 1, 1, None, spawner)
    }).unwrap();
    assert!(result.archives.is_empty() && result.errors.is_empty() && result.cleanup_results.is_empty());
    assert!(result.checkpoints.is_empty());
    assert!(run.created_outputs.lock().unwrap().0.is_empty());
    assert!(run.cleanup_refs.lock().unwrap().paths.is_empty());
    assert!(matches!(observer.0.lock().unwrap().as_slice(), [Event::Skipped { id: 1 }]));
    assert_eq!(fs::read(&source).unwrap(), b"unchanged source");
    fs::remove_file(source).unwrap();
}

#[test]
fn discovery_baseline_visits_archive_without_starting_worker() {
    let source = crate::test_support::temp_file("discovery_baseline", b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00");
    let engine = Engine::new(PathBuf::from("must-not-start-worker.exe"));
    let mut request = Request::new(vec![source.clone()], Mode::Extract);
    request.origin = Origin::Watch;
    request.deep = true;
    let visited = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&visited);
    let expected_source = source.clone();
    let job = engine.submit_discovery(request, move |owner, inputs| {
        assert!(super::super::scheduling::in_stage());
        assert_eq!(owner, expected_source);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].format_hint, "zip");
        count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }, |result| result);
    super::super::scheduling::block_on(job.wait()).unwrap();
    assert_eq!(visited.load(Ordering::Relaxed), 1);
    assert!(engine.worker.lock().unwrap().process.is_none());
    assert!(source.is_file());
    fs::remove_file(source).unwrap();
}
