use super::*;
use crate::protocol::MAX_VOLUME_GUID_BYTES;
use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

static TEST_CLIENT: Mutex<()> = Mutex::new(());

fn listen(name: &[u16], instances: u32) -> BrokerConnection {
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            instances,
            4096,
            4096,
            0,
            null(),
        )
    };
    assert_ne!(pipe, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
    BrokerConnection(pipe)
}

fn accept(server: &BrokerConnection) {
    assert!(unsafe {
        ConnectNamedPipe(server.0, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED
    });
}

fn seed_lease(connection: BrokerConnection) {
    let mut state = STATE.lock().unwrap();
    assert_eq!(state.leases, 0);
    state.leases = 1;
    state.idle = Some(connection);
}

fn read_directory_query(pipe: &BrokerConnection) {
    let mut metadata = [0; DIRECTORY_QUERY_HEADER_BYTES];
    read_exact(pipe.0, &mut metadata).unwrap();
    let header = DirectoryQueryHeader::decode(&metadata).unwrap();
    assert_eq!(header.journal, 42);
    assert_eq!(header.id_bytes, FILE_ID_BYTES);
    let mut id = [0; FILE_ID_BYTES];
    read_exact(pipe.0, &mut id).unwrap();
    assert_eq!(id, [1; FILE_ID_BYTES]);
}

#[test]
fn startup_follows_retiring_instances_but_propagates_real_failures() {
    // Real service tests cannot force each SCM transition window. One
    // deterministic trace covers that gap without timers or admin rights.
    let status = |state, exit| SERVICE_STATUS_PROCESS {
        dwCurrentState: state,
        dwWin32ExitCode: exit,
        ..Default::default()
    };
    let mut states = [
        status(SERVICE_STOP_PENDING, 0),
        status(SERVICE_STOPPED, 0),
        status(SERVICE_STOPPED, 0),
        status(SERVICE_START_PENDING, 0),
        status(SERVICE_STOPPED, 0),
        status(SERVICE_START_PENDING, 0),
        status(SERVICE_RUNNING, 0),
    ]
    .into_iter();
    let (mut starts, mut waits) = (0, Vec::new());
    drive_service_start(
        || Ok(states.next().expect("startup must converge")),
        || {
            starts += 1;
            Ok(())
        },
        |state| {
            waits.push(state);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(starts, 3);
    assert_eq!(
        waits,
        [
            SERVICE_STOP_PENDING,
            SERVICE_START_PENDING,
            SERVICE_START_PENDING
        ]
    );
    for error in [5, 1066] {
        let mut states = [status(SERVICE_STOPPED, 0), status(SERVICE_STOPPED, error)].into_iter();
        let failure = drive_service_start(
            || Ok(states.next().unwrap()),
            || Ok(()),
            |_| panic!("no transition to wait for"),
        )
        .unwrap_err();
        assert_eq!(failure.raw_os_error(), Some(error as i32));
        let mut states = [
            status(SERVICE_START_PENDING, 0),
            status(SERVICE_STOPPED, error),
        ]
        .into_iter();
        let failure = drive_service_start(
            || Ok(states.next().unwrap()),
            || panic!("a failed concurrent startup must propagate"),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(failure.raw_os_error(), Some(error as i32));
    }
    let failure = drive_service_start(
        || Ok(status(SERVICE_STOPPED, 0)),
        || Err(io::Error::from_raw_os_error(5)),
        |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(failure.raw_os_error(), Some(5));
}

#[test]
fn replay_only_transport_failures_not_permission_or_protocol_failures() {
    assert!(is_transient_broker_io(&io::Error::from_raw_os_error(109)));
    assert!(is_transient_broker_io(&io::Error::new(
        io::ErrorKind::ConnectionReset,
        "disconnected",
    )));
    assert!(!is_transient_broker_io(&io::Error::from_raw_os_error(5)));
    assert!(!is_transient_broker_io(&io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid reply",
    )));
}

#[test]
fn invalid_local_request_keeps_the_idle_lease() {
    let _test_client = TEST_CLIENT.lock().unwrap();
    let name = wide(&format!(
        r"\\.\pipe\SunPack.WatchBroker.Test.invalid-request.{}",
        std::process::id()
    ));
    let server = listen(&name, 1);
    let client = open_pipe(&name).unwrap();
    accept(&server);
    let handle = client.0;
    seed_lease(client);

    let result = broker_volume_cursor(&"x".repeat(MAX_VOLUME_GUID_BYTES + 1));
    let idle = ClientState::lock().unwrap().idle.as_ref().map(|pipe| pipe.0);
    broker_release().unwrap();

    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert_eq!(idle, Some(handle));
}

#[test]
fn directory_recovery_allows_another_request_between_pages() {
    let _test_client = TEST_CLIENT.lock().unwrap();
    let name = wide(&format!(
        r"\\.\pipe\SunPack.WatchBroker.Test.interleave.{}",
        std::process::id()
    ));
    let server = listen(&name, 1);
    let client = open_pipe(&name).unwrap();
    accept(&server);
    seed_lease(client);
    thread::scope(|workers| {
        let server = workers.spawn(move || {
            // Keep ownership of the pipe in this thread even if a reply assertion fails.
            let server = server;
            let serve = |opcode, start, next, name: &[u8]| {
                let mut request = [0; REQUEST_BYTES];
                read_exact(server.0, &mut request).unwrap();
                let request = Request::decode(&request).unwrap();
                assert_eq!(request.opcode, opcode);
                assert_eq!(request.previous_usn, start);
                let mut reply = Response::ok(request.request_id);
                reply.journal_id = 42;
                reply.next_usn = next;
                let mut payload = Vec::new();
                if opcode == Opcode::ReadDirectoriesChanges {
                    read_directory_query(&server);
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
                    payload.extend_from_slice(name);
                    reply.reasons_all = payload.len() as u32;
                    reply.reasons_without_close = 1;
                }
                write_exact(server.0, &reply.encode()).unwrap();
                if !payload.is_empty() {
                    write_exact(server.0, &payload).unwrap();
                }
            };
            serve(Opcode::ReadDirectoriesChanges, 0, 2, b"first");
            serve(Opcode::ProbeVolume, 0, 3, b"");
            serve(Opcode::ReadDirectoriesChanges, 2, 3, b"second");
        });
        let mut names = Vec::new();
        let result = broker_for_each_directory_change(
            "volume",
            42,
            &[[1; FILE_ID_BYTES]],
            0,
            3,
            |index, name| {
                if index != 0 || STATE.try_lock().is_err() {
                    return Err(io::Error::other(
                        "directory observer ran inside the pipe lock",
                    ));
                }
                if name == "first" && broker_volume_cursor("volume")? != (42, 3) {
                    return Err(io::Error::other(
                        "probe cursor did not survive interleaving",
                    ));
                }
                names.push(name.to_owned());
                Ok(())
            },
        );
        broker_release().unwrap();
        let server_result = server.join();
        result.unwrap();
        server_result.unwrap();
        assert_eq!(names, ["first", "second"]);
    });
}

#[test]
fn overlapping_request_uses_another_pipe_and_release_closes_both() {
    use std::sync::mpsc;

    let _test_client = TEST_CLIENT.lock().unwrap();
    let pipe_name = format!("{TEST_PIPE_NAME_PREFIX}parallel.{}", std::process::id());
    let name = wide(&pipe_name);
    let slow = listen(&name, 2);
    let client = open_pipe(&name).unwrap();
    accept(&slow);
    seed_lease(client);
    let fast = listen(&name, 2);
    let previous_name = env::var_os(PIPE_NAME_ENV);
    env::set_var(PIPE_NAME_ENV, &pipe_name);
    let guard_timeout = Duration::from_secs(5);

    let (started, running) = mpsc::channel();
    let (finish, resume) = mpsc::channel();
    let (probed, probe_result) = mpsc::channel();
    let result = thread::scope(|workers| {
        let slow_server = workers.spawn(move || {
            let slow = slow;
            let mut bytes = [0; REQUEST_BYTES];
            read_exact(slow.0, &mut bytes).unwrap();
            let request = Request::decode(&bytes).unwrap();
            assert_eq!(request.opcode, Opcode::ReadDirectoriesChanges);
            read_directory_query(&slow);
            started.send(()).unwrap();
            resume.recv_timeout(guard_timeout).unwrap();
            let mut reply = Response::ok(request.request_id);
            reply.journal_id = 42;
            reply.next_usn = 2;
            write_exact(slow.0, &reply.encode()).unwrap();
            assert!(is_transient_broker_io(
                &read_exact(slow.0, &mut bytes).unwrap_err()
            ));
        });
        let directory = workers.spawn(|| {
            broker_for_each_directory_change("volume", 42, &[[1; FILE_ID_BYTES]], 1, 2, |_, _| {
                panic!("expected an empty page")
            })
        });
        running.recv_timeout(guard_timeout).unwrap();
        let fast_server = workers.spawn(move || {
            accept(&fast);
            let mut bytes = [0; REQUEST_BYTES];
            for opcode in [Opcode::Hello, Opcode::ProbeVolume] {
                read_exact(fast.0, &mut bytes)?;
                let request = Request::decode(&bytes)?;
                assert_eq!(request.opcode, opcode);
                let mut reply = Response::ok(request.request_id);
                reply.journal_id = 42;
                reply.next_usn = 2;
                write_exact(fast.0, &reply.encode())?;
            }
            assert!(is_transient_broker_io(
                &read_exact(fast.0, &mut bytes).unwrap_err()
            ));
            Ok::<_, io::Error>(())
        });
        let probe = workers.spawn(move || {
            let _ = probed.send(broker_volume_cursor("volume"));
        });

        let result = probe_result.recv_timeout(guard_timeout);
        broker_release().unwrap();
        // Let the blocked request finish after the last lease has left.
        let _ = finish.send(());
        if !matches!(result, Ok(Ok(_))) {
            // Unblock the test listener if the client failed before opening it.
            drop(open_pipe(&name));
        }
        probe.join().unwrap();
        directory.join().unwrap().unwrap();
        slow_server.join().unwrap();
        fast_server.join().unwrap().unwrap();
        result
    });
    match previous_name {
        Some(name) => env::set_var(PIPE_NAME_ENV, name),
        None => env::remove_var(PIPE_NAME_ENV),
    }
    assert_eq!(result.unwrap().unwrap(), (42, 2));
}

#[test]
fn runtime_identity_accepts_only_the_test_namespace() {
    let variable = "SUNPACK_TEST_BROKER_IDENTITY_NAMESPACE";
    std::env::set_var(variable, "OtherWatchBroker");
    assert_eq!(
        configured_name(variable, SERVICE_NAME, TEST_SERVICE_NAME_PREFIX),
        SERVICE_NAME
    );
    std::env::set_var(variable, "SunPackWatchBrokerTest_example");
    assert_eq!(
        configured_name(variable, SERVICE_NAME, TEST_SERVICE_NAME_PREFIX),
        "SunPackWatchBrokerTest_example"
    );
    std::env::remove_var(variable);
}
