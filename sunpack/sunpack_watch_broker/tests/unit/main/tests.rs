use super::*;

#[test]
fn lifetime_waits_for_first_lease_and_exits_on_stop_or_last_client() {
    // The shape/dispatcher tests never run the accept loop. This single
    // real-pipe test covers initial standby, stop, overlapping short leases
    // and a connected client without a lease, including the old 5s/1s exits.
    use std::io::{Read, Write};
    use std::sync::mpsc::{self, RecvTimeoutError};

    let name = format!(
        r"\\.\pipe\SunPack.WatchBroker.Test.lifetime.{}",
        std::process::id()
    );
    CONFIG
        .set(BrokerConfig {
            service_name: "SunPackWatchBrokerTest_lifetime".to_owned(),
            pipe_name: name.clone(),
        })
        .unwrap();

    struct Server {
        stop: Arc<OwnedHandle>,
        thread: Option<thread::JoinHandle<io::Result<()>>>,
        done: mpsc::Receiver<()>,
    }
    impl Server {
        fn start() -> Self {
            let stop = Arc::new(OwnedHandle::event().unwrap());
            let worker_stop = Arc::clone(&stop);
            let (tx, done) = mpsc::channel();
            let thread = thread::spawn(move || {
                let result = serve_watch_lifetimes(&worker_stop);
                let _ = tx.send(());
                result
            });
            Self {
                stop,
                thread: Some(thread),
                done,
            }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.signal();
            assert!(self.thread.take().unwrap().join().unwrap().is_ok());
        }
    }
    fn connect(name: &str) -> std::fs::File {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(name)
            {
                Ok(pipe) => return pipe,
                Err(error)
                    if matches!(error.raw_os_error(), Some(2 | 231))
                        && Instant::now() < deadline =>
                {
                    thread::yield_now()
                }
                Err(error) => panic!("test pipe connection failed: {error}"),
            }
        }
    }
    fn request(pipe: &mut std::fs::File, opcode: Opcode) {
        pipe.write_all(&Request::simple(opcode, 1).encode().unwrap())
            .unwrap();
        let mut response = [0; RESPONSE_BYTES];
        pipe.read_exact(&mut response).unwrap();
        assert_eq!(Response::decode(&response).unwrap().status, Status::Ok);
    }

    {
        let server = Server::start();
        assert_eq!(
            server.done.recv_timeout(Duration::from_millis(5_100)),
            Err(RecvTimeoutError::Timeout)
        );
        server.stop.signal();
        server.done.recv_timeout(Duration::from_secs(3)).unwrap();
    }
    let server = Server::start();
    let mut owner = connect(&name);
    request(&mut owner, Opcode::Hello);
    for _ in 0..16 {
        let mut next = connect(&name);
        request(&mut next, Opcode::Hello);
        owner = next;
    }
    let mut unleased = connect(&name);
    // A valid probe before Hello confirms the connection is accepted and
    // cannot run journal commands without a lease.
    let mut probe = Request::simple(Opcode::ProbeVolume, 2);
    probe.volume_guid = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}";
    unleased
        .write_all(&probe.encode().unwrap())
        .unwrap();
    let mut response = [0; RESPONSE_BYTES];
    unleased.read_exact(&mut response).unwrap();
    assert_eq!(
        Response::decode(&response).unwrap().status,
        Status::InvalidRequest
    );
    drop(owner);
    assert_eq!(
        server.done.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    );
    request(&mut unleased, Opcode::Hello);
    drop(unleased);
    server
        .done
        .recv_timeout(Duration::from_millis(500))
        .unwrap();
    drop(server);

    // Stop must drain clients blocked in a read before releasing events.
    let server = Server::start();
    let mut owner = connect(&name);
    request(&mut owner, Opcode::Hello);
    server.stop.signal();
    server.done.recv_timeout(Duration::from_secs(3)).unwrap();
    match owner.read(&mut [0u8; 1]) {
        Ok(size) => assert_eq!(size, 0),
        Err(error) => assert!(matches!(error.raw_os_error(), Some(109 | 233))),
    }
    drop(owner);
    drop(server);

    // A wait failure must cancel too, and neither exit may leave kernel IO
    // pointing into caller-owned storage. Existing request tests only
    // cover successful IO and cannot detect this pending-operation leak.
    for failed_wait in [true, false] {
        let accept = PendingPipeAccept::start(true).unwrap();
        let _client = connect(&name);
        assert_eq!(
            unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(accept.event(), 3000)
            },
            WAIT_OBJECT_0
        );
        let pipe = accept.finish().unwrap();
        let stop = OwnedHandle::event().unwrap();
        stop.signal();
        let event = OwnedHandle::event().unwrap();
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.raw();
        let mut buffer = [0u8; 1];
        assert_eq!(
            unsafe {
                ReadFile(
                    pipe.raw(),
                    buffer.as_mut_ptr(),
                    1,
                    null_mut(),
                    &mut overlapped,
                )
            },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_IO_PENDING);
        let result = wait_io(
            pipe.raw(),
            if failed_wait { null_mut() } else { stop.raw() },
            &mut overlapped,
        );
        let mut transferred = 0;
        let completed =
            unsafe { GetOverlappedResult(pipe.raw(), &mut overlapped, &mut transferred, 0) };
        let error = unsafe { GetLastError() };
        // Keep the test memory safe even when the regression is present.
        cancel_io(pipe.raw(), &mut overlapped);
        assert_eq!(completed, 0);
        assert_eq!(
            error,
            windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED
        );
        if failed_wait {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(6));
        } else {
            assert_eq!(result.unwrap(), IoResult::Stopped);
        }
    }
}

#[test]
fn broker_identity_defaults_to_production_names() {
    let config = BrokerConfig::from_args(std::iter::empty());
    assert_eq!(config.service_name, SERVICE_NAME);
    assert_eq!(config.pipe_name, PIPE_NAME);
}

#[test]
fn broker_identity_can_be_isolated_for_tests() {
    let config = BrokerConfig::from_args(
        [
            "--service-name",
            "SunPackWatchBrokerTest_example",
            "--pipe-name",
            r"\\.\pipe\SunPack.WatchBroker.Test.example",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert_eq!(config.service_name, "SunPackWatchBrokerTest_example");
    assert_eq!(
        config.pipe_name,
        r"\\.\pipe\SunPack.WatchBroker.Test.example"
    );
}

#[test]
fn only_minimal_shapes_are_accepted_for_non_journal_operations() {
    assert!(request_shape_is_valid(&Request::simple(Opcode::Hello, 1)));
    let mut invalid = Request::simple(Opcode::Hello, 2);
    invalid.volume_guid = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}";
    assert!(!request_shape_is_valid(&invalid));
}

#[test]
fn journal_read_requires_a_bounded_usn_interval_and_file_identity() {
    let mut request = Request::simple(Opcode::ReadChangeReasons, 1);
    request.volume_guid = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}";
    request.file_id_len = 8;
    request.previous_usn = 100;
    request.current_usn = 101;
    assert!(request_shape_is_valid(&request));
    request.current_usn = 100;
    assert!(!request_shape_is_valid(&request));
    request.opcode = Opcode::ReadDirectoriesChanges;
    request.file_id_len = 0;
    request.previous_usn = 0;
    assert!(request_shape_is_valid(&request));
    request.previous_usn = -1;
    assert!(!request_shape_is_valid(&request));
}

#[test]
fn dispatcher_reuses_volume_contexts_and_allows_overlapping_reads() {
    let dispatcher = JournalDispatcher::new().unwrap();
    let deadline = Instant::now() + VOLUME_CONTEXT_IDLE_TTL;
    let first = dispatcher
        .reader_for(
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}",
            deadline,
        )
        .unwrap();
    let same = dispatcher
        .reader_for(
            r"\\?\VOLUME{01234567-89AB-CDEF-0123-456789ABCDEF}",
            deadline,
        )
        .unwrap();
    let other = dispatcher
        .reader_for(
            r"\\?\Volume{fedcba98-7654-3210-fedc-ba9876543210}",
            deadline,
        )
        .unwrap();
    assert!(Arc::ptr_eq(&first, &same));
    assert!(!Arc::ptr_eq(&first, &other));

    let busy = first.lock().unwrap();
    let cached_address = std::ptr::from_ref(&*busy).addr();
    let (sent, result) = std::sync::mpsc::channel();
    thread::scope(|workers| {
        workers.spawn(|| {
            let result = dispatcher.with_reader(
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}",
                |reader| Ok(std::ptr::from_ref(reader).addr() != cached_address),
            );
            let _ = sent.send(result);
        });
        let concurrent = result.recv_timeout(Duration::from_secs(5));
        drop(busy);
        assert!(concurrent.unwrap().unwrap());
    });
}

#[test]
fn dispatcher_schedules_expiry_and_preserves_in_use_readers() {
    let dispatcher = JournalDispatcher::new().unwrap();
    let now = Instant::now();
    let deadline = now + VOLUME_CONTEXT_IDLE_TTL;
    let reader = dispatcher
        .reader_for(
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}",
            deadline,
        )
        .unwrap();
    assert_eq!(dispatcher.reap_idle(now).unwrap(), Some(deadline));
    assert_eq!(dispatcher.reap_idle(deadline).unwrap(), None);
    assert_eq!(dispatcher.entries.lock().unwrap().len(), 1);
    drop(reader);
    assert_eq!(dispatcher.reap_idle(deadline).unwrap(), None);
    assert!(dispatcher.entries.lock().unwrap().is_empty());
}
