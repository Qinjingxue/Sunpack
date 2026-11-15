use super::*;

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
        let mut states =
            [status(SERVICE_STOPPED, 0), status(SERVICE_STOPPED, error)].into_iter();
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
fn directory_recovery_allows_another_request_between_pages() {
    use crate::protocol::REQUEST_BYTES;
    use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    };

    let name = wide(&format!(
        r"\\.\pipe\SunPack.WatchBroker.Test.interleave.{}",
        std::process::id()
    ));
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            null(),
        )
    };
    assert_ne!(pipe, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
    let server = BrokerConnection(pipe);
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    assert_ne!(
        client,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    let client = BrokerConnection(client);
    assert!(unsafe {
        ConnectNamedPipe(server.0, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED
    });
    let mode = PIPE_READMODE_MESSAGE;
    assert_ne!(
        unsafe { SetNamedPipeHandleState(client.0, &mode, null(), null()) },
        0
    );

    let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
    *state.lock().unwrap() = ClientState {
        connection: Some(client),
        leases: 1,
    };
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
                    let mut length = [0; 4];
                    let mut query = [0; 8 + FILE_ID_BYTES];
                    read_exact(server.0, &mut length).unwrap();
                    assert_eq!(u32::from_le_bytes(length) as usize, query.len());
                    read_exact(server.0, &mut query).unwrap();
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
                if index != 0 || state.try_lock().is_err() {
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
fn empty_runtime_identity_uses_the_production_default() {
    let variable = "SUNPACK_TEST_EMPTY_BROKER_IDENTITY";
    std::env::set_var(variable, "");
    assert_eq!(
        configured_name(variable, SERVICE_NAME, TEST_SERVICE_NAME_PREFIX),
        SERVICE_NAME
    );
    std::env::remove_var(variable);
}

#[test]
fn runtime_identity_accepts_only_the_test_namespace() {
    let variable = "SUNPACK_TEST_BROKER_IDENTITY_NAMESPACE";
    std::env::set_var(variable, "SunPackWatchBroker");
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
