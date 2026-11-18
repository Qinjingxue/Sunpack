use super::*;
use std::sync::mpsc;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

#[test]
fn persistent_idle_can_be_disabled_and_reenabled_by_configuration() {
    let host = Host::new();
    let mut raw = serde_json::json!({"performance": {}});
    for (setting, idle) in [
        (serde_json::json!(0), Some(Duration::ZERO)),
        (serde_json::json!("+inf"), None),
        (serde_json::json!("invalid"), None),
        (serde_json::json!(3), Some(Duration::from_secs(3))),
    ] {
        raw["performance"]["persistent_server_idle_seconds"] = setting;
        host.configure_idle(&config::Config::parse(&raw).unwrap());
        assert_eq!(host.idle_policy().exit, idle);
    }
}

#[test]
fn competing_runtime_does_not_wait_for_a_live_owner_with_missing_endpoint() {
    let path = crate::test_support::temp_file("runtime_lock", b"invalid endpoint");
    let owner = StateFile::acquire(path.clone()).unwrap();
    fs::remove_file(&path).unwrap();
    let other_path = path.clone();
    let (send, receive) = mpsc::channel();
    let competitor = std::thread::spawn(move || {
        let result = StateFile::acquire(other_path);
        send.send(result.as_ref().err().and_then(io::Error::raw_os_error)).unwrap();
        result.is_err()
    });
    let result = receive.recv_timeout(Duration::from_secs(5));
    // Release before joining even on regression, so a blocking acquisition
    // cannot strand the test process.
    drop(owner);
    let rejected = competitor.join().unwrap();
    assert_eq!(result.unwrap(), Some(windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION as i32));
    assert!(rejected);
    drop(StateFile::acquire(path.clone()).unwrap());
    let mut lock_path = path.into_os_string();
    lock_path.push(".lock");
    fs::remove_file(lock_path).unwrap();
}

fn server() -> Arc<Server> {
    Arc::new(Server {
        host: Host::new(), activity: Mutex::default(),
        drained: Condvar::new(), wake: Arc::new(Event::new(false).unwrap()),
        shutdown: Cancellation::new(), io: transport::Reactor::new().unwrap(), token: [0; 32], build_id: [0; 16],
    })
}
fn pipe_pair() -> (File, OwnedHandle) {
    let name = format!(r"\\.\pipe\SunPack-connection-test-{}-{}", std::process::id(), hex(&windows::random_bytes::<16>().unwrap()));
    let security = windows::PipeSecurity::current_user().unwrap();
    let accept = Accept::arm(&windows::wide(OsStr::new(&name)), &security.attributes(), true).unwrap();
    let client = OpenOptions::new().read(true).write(true).open(name).unwrap();
    assert_eq!(unsafe { WaitForSingleObject(accept.event.raw(), INFINITE) }, WAIT_OBJECT_0);
    (client, accept.finish().unwrap())
}
fn connect(server: &Arc<Server>) -> (File, crate::pipeline::RequestHandle<io::Result<()>>) {
    let (client, peer) = pipe_pair();
    (client, server.submit(peer))
}
fn help_request(server: &Server) -> Vec<u8> {
    command_request(server, 0, &["-h"])
}
fn command_request(server: &Server, flags: u32, args: &[&str]) -> Vec<u8> {
    let cwd = std::env::current_dir().unwrap().to_string_lossy().into_owned();
    let mut bytes = [b"SPK2".as_slice(), &server.build_id, &server.token].concat();
    for word in [flags, cwd.len() as u32, args.len() as u32] { bytes.extend(word.to_be_bytes()); }
    bytes.extend(cwd.as_bytes());
    for arg in args {
        bytes.extend((arg.len() as u32).to_be_bytes());
        bytes.extend(arg.as_bytes());
    }
    bytes
}

#[test]
fn internal_toast_request_waits_for_the_next_pipe_instance() {
    let identity = format!("busy-test-{}", hex(&windows::random_bytes::<16>().unwrap()));
    let name = format!(r"\\.\pipe\SunPack-{identity}");
    let name_wide = windows::wide(OsStr::new(&name));
    let security = windows::PipeSecurity::current_user().unwrap();
    let accept = Accept::arm(&name_wide, &security.attributes(), true).unwrap();
    let mut client_options = OpenOptions::new();
    client_options.read(true).write(true);
    let _occupied = client_options.open(&name).unwrap();
    assert_eq!(unsafe { WaitForSingleObject(accept.event.raw(), INFINITE) }, WAIT_OBJECT_0);
    let _peer = accept.finish().unwrap();
    assert_eq!(client_options.open(&name).unwrap_err().raw_os_error(), Some(ERROR_PIPE_BUSY as i32));

    let server = server();
    let cwd = std::env::current_dir().unwrap();
    let path = state_path(&cwd, &identity).unwrap();
    let state = StateFile::acquire(path.clone()).unwrap();
    state.publish(&name, &server.token, &server.build_id, "test").unwrap();
    let (busy, blocked) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let client = std::thread::spawn(move || {
        PIPE_BUSY.with(|signal| signal.set(Some(busy)));
        let args = ["--cancel-watch-batch".into(), "missing".into()];
        done.send(submit_existing(&cwd, &identity, &args, false)).unwrap();
    });
    // Arm the second instance only after the internal client saw ERROR_PIPE_BUSY.
    blocked.recv_timeout(Duration::from_secs(5)).unwrap();
    let accept = Accept::arm(&name_wide, &security.attributes(), false).unwrap();
    assert_eq!(unsafe { WaitForSingleObject(accept.event.raw(), 5000) }, WAIT_OBJECT_0);
    let request = server.submit(accept.finish().unwrap());
    drop(state);
    let mut lock_path = path.into_os_string();
    lock_path.push(".lock");
    fs::remove_file(lock_path).unwrap();
    let response = result.recv_timeout(Duration::from_secs(5)).unwrap();
    client.join().unwrap();
    assert_eq!(response.unwrap(), Some(1)); // The command ran, but the batch does not exist.
    request.join().unwrap().unwrap();
}

#[test]
fn launcher_sessions_never_pause_inside_runtime() {
    let server = server();
    let cases: &[(&[&str], u32, i32)] = &[
        (&["watch", "list", "-pa"], 4, 0),
        (&["watch", "list", "-pa"], 0, 0),
        (&["watch", "list", "-pa", "-j"], 4, 0),
        (&["watch", "list", "-pa", "-h"], 4, 0),
        (&["version", "-pa"], 4, 2),
    ];
    for &(args, flags, expected) in cases {
        let (mut client, request) = connect(&server);
        client.write_all(&command_request(&server, flags, args)).unwrap();
        let mut handshake = [0; 20];
        client.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake[..4], b"SPS2");
        loop {
            let mut kind = [0];
            client.read_exact(&mut kind).unwrap();
            let length = read_u32(&mut client).unwrap() as usize;
            let bytes = read_field(&mut client, length).unwrap();
            match kind[0] {
                0 => {
                    assert_eq!(i32::from_be_bytes(bytes.try_into().unwrap()), expected, "{args:?}");
                    break;
                }
                1 | 2 => {}
                _ => panic!("unexpected interactive input frame for {args:?}"),
            }
        }
        request.join().unwrap().unwrap();
    }
}

#[test]
fn incomplete_and_invalid_connections_do_not_block_a_live_cli_or_stop_service() {
    let server = server();
    let mut held = Vec::new();
    for _ in 0..64 {
        let (mut client, request) = connect(&server);
        client.write_all(b"S").unwrap();
        held.push((client, request));
    }
    let (mut invalid, rejected) = connect(&server);
    invalid.write_all(&[0; 64]).unwrap();
    assert_eq!(rejected.join().unwrap().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(!server.activity.lock().unwrap().shutting_down);
    assert!(server.activity.lock().unwrap().last_completed.is_none());
    let (mut client, healthy) = connect(&server);
    client.write_all(&help_request(&server)).unwrap();
    let (finished, ready) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let result = (|| -> io::Result<i32> {
            let mut handshake = [0; 20];
            client.read_exact(&mut handshake)?;
            assert_eq!(&handshake[..4], b"SPS2");
            loop {
                let mut kind = [0];
                client.read_exact(&mut kind)?;
                let length = read_u32(&mut client)? as usize;
                let bytes = read_field(&mut client, length)?;
                if kind[0] == 0 { return Ok(i32::from_be_bytes(bytes.try_into().unwrap())); }
            }
        })();
        finished.send((client, result)).unwrap();
    });
    let response = ready.recv_timeout(Duration::from_secs(10));
    if response.is_err() { server.shutdown.cancel(); }
    reader.join().unwrap();
    let (_client, code) = response.expect("incomplete clients consumed CLI execution capacity");
    assert_eq!(code.unwrap(), 0);
    healthy.join().unwrap().unwrap();
    assert!(server.activity.lock().unwrap().last_completed.is_some());
    server.shutdown.cancel();
    for (_client, request) in held { assert!(request.join().unwrap().is_err()); }
    let activity = server.drained.wait_while(server.activity.lock().unwrap(), |state| state.active != 0).unwrap();
    assert!(!activity.shutting_down);
}

#[test]
fn cancel_and_shared_driver_progress_while_request_configuration_is_blocked() {
    let server = server();
    let (mut client, pipe) = pipe_pair();
    let connection = Arc::new(Connection {
        peer: server.io.bind(pipe, &server.shutdown).unwrap(),
        output: output::Output::default(), prompt: Mutex::default(), input: Mutex::default(),
        cancel: Cancellation::new(), finishing: AtomicBool::new(false), language: Default::default(),
        terminal_size: AtomicU32::new(0), flags: 0,
    });
    let cancel = connection.cancel.clone();
    let (cancelled, observed) = mpsc::channel();
    let _subscription = cancel.subscribe(move || { let _ = cancelled.send(()); });
    let (entered, blocked) = mpsc::channel();
    let (release, proceed) = mpsc::channel();
    struct Release(Option<mpsc::Sender<()>>);
    impl Drop for Release { fn drop(&mut self) { if let Some(sender) = self.0.take() { let _ = sender.send(()); } } }
    let release = Release(Some(release));
    let token = cancel.clone();
    let request = server.host.scheduler.submit(server.host.scheduler.next_id(), Origin::Foreground, &cancel,
        move |spawner| Box::pin(async move {
            let writer = connection.clone();
            let output = spawner.spawn(Box::pin(async move { writer.pump_output().await }));
            let reader = connection.clone();
            let control = spawner.spawn(Box::pin(async move {
                let _ = reader.read_control(PipeReader::default()).await;
            }));
            connection.finish_request(async move {
                crate::pipeline::stage("cli", &Cancellation::new()).await?;
                // Same blocking stage as request configuration loading. No
                // language has been published yet; CANCEL must use fallback.
                entered.send(()).unwrap();
                proceed.recv().unwrap();
                assert!(token.cancelled());
                Ok(())
            }, Some(control), output).await
        }));
    blocked.recv_timeout(Duration::from_secs(10)).unwrap();
    client.write_all(&CANCEL.to_be_bytes()).unwrap();
    observed.recv_timeout(Duration::from_secs(10)).expect("cancel waited for configuration");
    let (advanced, light) = mpsc::channel();
    let second = server.host.scheduler.submit(server.host.scheduler.next_id(), Origin::Foreground, &Cancellation::new(),
        move |_| Box::pin(async move { advanced.send(()).unwrap(); }));
    light.recv_timeout(Duration::from_secs(10)).expect("shared control driver was blocked");
    let mut kind = [0]; client.read_exact(&mut kind).unwrap();
    let length = read_u32(&mut client).unwrap() as usize;
    let notice = read_field(&mut client, length).unwrap();
    assert_eq!(kind, [Stream::Err as u8]);
    assert_eq!(notice, format!("{}\n", crate::core::i18n::Language::En.text("interrupt.stopping")).as_bytes());
    drop(release);
    request.join().unwrap().unwrap();
    second.join().unwrap();
}

#[test]
fn real_prompt_resize_cancel_and_panic_flush_settle_all_connection_work() {
    let server = server();
    let (mut client, pipe) = pipe_pair();
    let connection = Arc::new(Connection {
        peer: server.io.bind(pipe, &server.shutdown).unwrap(),
        output: output::Output::default(), prompt: Mutex::default(), input: Mutex::default(),
        cancel: Cancellation::new(), finishing: AtomicBool::new(false), language: Default::default(),
        terminal_size: AtomicU32::new(80 | 24 << 16), flags: 14,
    });
    connection.set_language(crate::core::i18n::Language::Zh);
    let cancel = connection.cancel.clone();
    let request = server.host.scheduler.submit(server.host.scheduler.next_id(), Origin::Foreground, &cancel,
        move |spawner| Box::pin(async move {
            let _close = CloseConnection(connection.clone());
            let writer = connection.clone();
            let output = spawner.spawn(Box::pin(async move { writer.pump_output().await }));
            let reader = connection.clone();
            let control = spawner.spawn(Box::pin(async move {
                if reader.read_control(PipeReader::default()).await.is_err() { reader.close(); }
            }));
            connection.finish_request(async {
                assert_eq!(connection.read_line_async("first").await?.as_deref(), Some("answer\r\n"));
                assert_eq!(connection.terminal_size(), (120, 40));
                assert_eq!(connection.read_line_async("second").await?, None);
                connection.awrite(Stream::Out, b"queued-before-panic").await?;
                let _prompt = connection.prompt.lock().unwrap();
                panic!("request failure after enqueue");
            }, Some(control), output).await
        }));
    let (finished, ready) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut frames = Vec::new();
        let mut prompts = 0;
        let result = (|| -> io::Result<()> {
            loop {
                let mut kind = [0];
                if client.read_exact(&mut kind).is_err() { return Ok(()); }
                let length = read_u32(&mut client)? as usize;
                let bytes = read_field(&mut client, length)?;
                if kind[0] == 3 {
                    prompts += 1;
                    if prompts == 1 {
                        for word in [RESIZE, 120, 40, 8] { client.write_all(&word.to_be_bytes())?; }
                        client.write_all(b"answer\r\n")?;
                    } else { client.write_all(&CANCEL.to_be_bytes())?; }
                }
                frames.push((kind[0], bytes));
            }
        })();
        finished.send((result, prompts, frames)).unwrap();
    });
    let response = ready.recv_timeout(Duration::from_secs(10));
    if response.is_err() { server.shutdown.cancel(); }
    reader.join().unwrap();
    let (result, prompts, frames) = response.expect("prompt/cancel or panic teardown stalled");
    result.unwrap();
    assert_eq!(prompts, 2);
    let notice = frames.iter().position(|(kind, _)| *kind == Stream::Err as u8).unwrap();
    let final_output = frames.iter().position(|(_, data)| data == b"queued-before-panic").unwrap();
    assert!(notice < final_output);
    assert_eq!(frames[notice].1, format!("{}\n", crate::core::i18n::Language::Zh.text("interrupt.stopping")).as_bytes());
    assert_eq!(frames.iter().filter(|(kind, _)| *kind == Stream::Err as u8).count(), 1);
    assert_eq!(frames.last(), Some(&(0, 1_i32.to_be_bytes().to_vec())));
    assert!(request.join().is_err());

    let (mut client, next) = connect(&server);
    client.write_all(&help_request(&server)).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.ends_with(&output_frame(0, &0_i32.to_be_bytes())));
    next.join().unwrap().unwrap();
}

#[test]
fn async_prompt_is_first_wins_and_old_waiter_cannot_remove_new_prompt() {
    let slot = Mutex::default();
    let cancel = Cancellation::new();
    let first = PromptReply::new(&slot, &cancel).unwrap().unwrap();
    assert!(PromptReply::new(&slot, &Cancellation::new()).is_err());
    let partial_reply = slot.lock().unwrap().take().unwrap();
    let next_cancel = Cancellation::new();
    let next = PromptReply::new(&slot, &next_cancel).unwrap().unwrap();
    cancel.cancel();
    assert!(block_on(first.reply.wait()).unwrap().is_empty());
    partial_reply.complete(Ok(b"late".to_vec()));
    assert!(block_on(first.reply.wait()).is_err());
    drop(first);
    assert!(slot.lock().unwrap().as_ref().is_some_and(|reply| Arc::ptr_eq(reply, &next.reply)));
    next.reply.complete(Ok(b"yes".to_vec()));
    next_cancel.cancel();
    assert_eq!(block_on(next.reply.wait()).unwrap(), b"yes");
    drop(next);
    assert!(slot.lock().unwrap().is_none());
    assert!(PromptReply::new(&slot, &next_cancel).unwrap().is_none());
}

#[test]
fn status_stream_is_passive_and_disconnect_releases_subscription() {
    let server = server();
    let (mut client, request) = connect(&server);
    client.write_all(&command_request(&server, 0, &["--watch-status-follow"])).unwrap();
    let mut handshake = [0; 20];
    client.read_exact(&mut handshake).unwrap();
    assert_eq!(&handshake[..4], b"SPS2");
    let mut kind = [0];
    client.read_exact(&mut kind).unwrap();
    assert_eq!(kind, [Stream::Out as u8]);
    let length = read_u32(&mut client).unwrap() as usize;
    let bytes = read_field(&mut client, length).unwrap();
    let status: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(status["running"].is_boolean());
    assert!(status["enabled"].is_boolean());
    assert!(status["phase"].is_string());
    {
        let activity = server.activity.lock().unwrap();
        assert_eq!(activity.active, 1);
        assert_eq!(activity.observers, 1);
    }
    let (done, finished) = mpsc::channel();
    let waiter = std::thread::spawn(move || { let _ = request.join(); let _ = done.send(()); });
    drop(client);
    finished.recv_timeout(Duration::from_secs(5)).expect("status subscriber retained after disconnect");
    waiter.join().unwrap();
    let (activity, _) = server.drained.wait_timeout_while(
        server.activity.lock().unwrap(), Duration::from_secs(5), |state| state.active != 0,
    ).unwrap();
    assert_eq!(activity.active, 0);
    assert_eq!(activity.observers, 0);
}
