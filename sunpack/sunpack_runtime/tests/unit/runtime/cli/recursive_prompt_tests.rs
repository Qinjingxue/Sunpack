use crate::pipeline::CleanupStatus;

#[test]
fn password_retry_keeps_only_failed_carrier_siblings_and_generated_anchors() {
    let marker = crate::test_support::temp_file("cli_retry_scope", b"source");
    let generation = crate::io::reader::capture_file_generation(&marker).unwrap();
    let checkpoint = |carrier: &str, source: &str, failed: bool| {
        let input = crate::io::archive_state::ArchiveInput::file(source.into(), "zip".into(), source.into());
        let failure = failed.then(|| json!({"partial":false,"password_signature":null,
            "failure":crate::pipeline::Failure::new(FailureKind::WrongPassword,"password"),"complete_files":0}));
        serde_json::from_value::<crate::pipeline::InputCheckpoint>(json!({
            "schema_version":1,"carrier":carrier,"input":input,"sources":[{"path":source,"generation":generation}],
            "output":format!("{carrier}-output"),"container":null,"files":1,"bytes":1,
            "encrypted":false,"discovery_source":"embedded","failure":failure
        })).unwrap()
    };
    let generated = |source: &str| serde_json::from_value::<crate::pipeline::GeneratedSource>(
        json!({"path":source,"generation":generation})).unwrap();
    let mut checkpoints = vec![checkpoint("outer.zip", "outer.zip", false)];
    for index in 0..1000 { let path = format!("outer/success-{index}.zip");
        checkpoints.push(checkpoint(&path, &path, false)); }
    // The selected generated source can identify an carrier through its
    // physical anchor; keep its successful logical sibling as well.
    checkpoints.push(checkpoint("old-carrier.bin", "generated-failed.zip", true));
    checkpoints.push(checkpoint("old-carrier.bin", "same-carrier-good.zip", false));
    let mut generated_sources = vec![generated("generated-failed.zip"), generated("same-carrier-good.zip"),
        generated("outer/success-1.zip")];
    trim_password_retry_recovery(&[PathBuf::from("generated-failed.zip")], &mut checkpoints, &mut generated_sources);
    assert_eq!(checkpoints.len(), 2);
    assert!(checkpoints.capacity() <= 8);
    assert!(checkpoints.iter().all(|entry| entry.carrier() == Path::new("old-carrier.bin")));
    assert_eq!(generated_sources.iter().map(|source| source.path()).collect::<Vec<_>>(),
        [Path::new("generated-failed.zip"), Path::new("same-carrier-good.zip")]);
    trim_password_retry_recovery(&[], &mut checkpoints, &mut generated_sources);
    assert!(checkpoints.is_empty() && generated_sources.is_empty());
    assert_eq!(checkpoints.capacity(), 0);
    assert_eq!(generated_sources.capacity(), 0);
    std::fs::remove_file(marker).unwrap();
}

use super::*;

#[derive(Default)]
struct Input {
    interactive: bool,
    ascii: bool,
    cancel_input: bool,
    reads: std::sync::atomic::AtomicUsize,
    answers: Mutex<VecDeque<String>>,
    stdout: Mutex<Vec<u8>>,
    stderr: Mutex<Vec<u8>>,
    combined: Mutex<Vec<u8>>,
}
impl Session for Input {
    fn write(&self, stream: Stream, bytes: &[u8]) -> io::Result<()> {
        self.combined.lock().unwrap().extend_from_slice(bytes);
        match stream {
            Stream::Out => self.stdout.lock().unwrap().extend_from_slice(bytes),
            Stream::Err => self.stderr.lock().unwrap().extend_from_slice(bytes),
        }
        Ok(())
    }
    fn read_line(&self, prompt: &str) -> io::Result<Option<String>> {
        self.write(Stream::Out, prompt.as_bytes())?;
        self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.cancel_input { return Err(crate::io::cancellation::cancelled_io()); }
        Ok(self.answers.lock().unwrap().pop_front())
    }
    fn interactive(&self) -> bool { self.interactive }
    fn unicode(&self) -> bool { !self.ascii }
    fn terminal_size(&self) -> (usize, usize) { (80, 25) }
}

#[test]
fn interrupted_cleanup_details_reach_stderr_once_in_both_modes() {
    for json in [false, true] {
        let input = Input::default();
        let args = if json { vec!["extract".into(), "-j".into(), "input.zip".into()] }
            else { vec!["extract".into(), "input.zip".into()] };
        let options = Options::parse(&args).unwrap();
        let error = "C:\\output: access denied".to_owned();
        let (code, result) = interrupted(&options, &input, Language::En, None, vec![error.clone()]).unwrap();
        if json { write_json(&input, &result).unwrap(); }
        else { result.emit_errors(&input).unwrap(); }
        assert_eq!(code, 130);
        let stderr = String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap();
        assert_eq!(stderr.matches(&error).count(), 1);
        if json {
            let value: Value = serde_json::from_slice(&input.stdout.lock().unwrap()).unwrap();
            assert_eq!(value["errors"][0], error);
            assert_eq!(value["summary"]["cleanup_complete"], false);
        }
    }
}

#[test]
fn noninteractive_disk_warning_is_emitted_once_per_wait() {
    for language in [Language::En, Language::Zh] {
        for volume_error in [None, Some(5)] {
            let input = Arc::new(Input::default());
            let progress = Progress {
                session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
                cancel: Cancellation::new(), language,
                display: Mutex::default(), reporting: reporting::Reports::default(),
                prompt: false, visible: true, verbose: false,
            };
            progress.notify(Event::Queued { id: 1, parent: None, path: "input.zip".into(), segment: None });
            progress.notify(Event::ResourceWait {
                id: 1, path: "input.zip".into(),
                state: crate::pipeline::ResourceWait { disk: true, memory: true, volume_error, ..Default::default() },
            });
            progress.flush_events();
            let text = String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap();
            let hint = match volume_error {
                Some(error) => language.translate("report.status.disk_unavailable", &[("error", &error.to_string())]),
                None => language.text("report.status.disk_resume_hint").into(),
            };
            assert_eq!(text, format!("input.zip: {hint}\n"));
            for memory in [false, true, false] {
                progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(),
                    state: crate::pipeline::ResourceWait { disk: true, memory, volume_error, ..Default::default() }, });
                progress.flush_events();
            }
            assert_eq!(String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap(), text);
            progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(), state: Default::default() });
            progress.flush_events();
            progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(),
                state: crate::pipeline::ResourceWait { disk: true, memory: false, volume_error, ..Default::default() }, });
            progress.flush_events();
            assert_eq!(String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap(), text.repeat(2));
        }
    }
}

#[test]
fn disk_episode_survives_worker_and_reporting_coalescing() {
    let frames = crate::pipeline::coalesced_wait_batches(&[
        vec![json!({"type":"progress", "event":"space_blocked", "episode_id":1})],
        vec![json!({"type":"progress", "event":"space_resumed", "episode_id":1}),
             json!({"type":"progress", "event":"space_blocked", "episode_id":2})],
        vec![json!({"type":"progress", "event":"space_resumed", "episode_id":2})],
        vec![json!({"type":"progress", "event":"space_blocked", "episode_id":3})],
        vec![json!({"type":"native_memory", "event":"memory_blocked", "episode_id":7})],
    ]);
    for language in [Language::En, Language::Zh] {
        let input = Arc::new(Input::default());
        let progress = Progress {
            session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
            cancel: Cancellation::new(), language,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            prompt: false, visible: true, verbose: false,
        };
        progress.notify(Event::Queued { id: 1, parent: None, path: "input.zip".into(), segment: None });
        let emit = |state| progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(), state });
        let expected = format!("input.zip: {}\n", language.text("report.status.disk_resume_hint"));
        emit(frames[0]);
        progress.flush_events();
        assert_eq!(*input.stderr.lock().unwrap(), expected.as_bytes());
        // Resume and new wait were already merged inside the worker mailbox.
        emit(frames[1]);
        progress.flush_events();
        assert_eq!(*input.stderr.lock().unwrap(), expected.repeat(2).as_bytes());
        // Reports overwrites resume before display, while retaining episode 3.
        emit(frames[2]);
        emit(frames[3]);
        progress.flush_events();
        assert_eq!(*input.stderr.lock().unwrap(), expected.repeat(3).as_bytes());
        emit(frames[4]);
        progress.flush_events();
        assert_eq!(*input.stderr.lock().unwrap(), expected.repeat(3).as_bytes());
    }
}

#[test]
fn parser_errors_match_main_text_stream_and_exit_code() {
    // Captured by executing main's real parser classes, registrations and
    // value converters. Usage is suppressed; diagnostics remain on stderr.
    let cases: &[(&[&str], &str)] = &[
        (&["extract", "x", "-p"], "sunpack extract: error: argument -p: expected one argument\n"),
        (&["e", "x", "-p"], "sunpack extract: error: argument -p: expected one argument\n"),
        (&["passwords", "-j=x"], "sunpack passwords: error: argument -j: ignored explicit argument 'x'\n"),
        (&["scan", "x", "-pa", "-npa"], "sunpack scan: error: argument -npa: not allowed with argument -pa\n"),
        (&["extract", "x", "-nf", "-f"], "sunpack extract: error: argument -f: not allowed with argument -nf\n"),
        (&["extract", "x", "--foo", "--bar"], "sunpack: error: unrecognized arguments: --foo --bar\n"),
        (&["nonsense"], "sunpack: error: argument command: invalid choice: 'nonsense' (choose from extract, e, watch, w, scan, s, passwords, pw, config, cfg, daemon, d, doctor, doc, version, ver)\n"),
        (&["watch", "nonsense"], "sunpack watch: error: argument watch_action: invalid choice: 'nonsense' (choose from enable, ea, disable, da, add, remove, rm, list, ls, reload, rl, relog, rlg, status, st)\n"),
        (&["config", "nonsense"], "sunpack config: error: argument config_action: invalid choice: 'nonsense' (choose from show, validate)\n"),
        (&["watch", "-j"], "sunpack watch: error: the following arguments are required: watch_action\n"),
        (&["config", "-j"], "sunpack config: error: the following arguments are required: config_action\n"),
        (&["config", "--"], "sunpack config: error: the following arguments are required: config_action\n"),
        (&["daemon", "startup", "nonsense"], "sunpack daemon startup: error: argument action: invalid choice: 'nonsense' (choose from enable, disable, status)\n"),
        (&["daemon", "startup", "enable", "disable"], "sunpack: error: unrecognized arguments: disable\n"),
        (&["scan", "-j"], "sunpack scan: error: the following arguments are required: paths\n"),
        (&["--foo"], "sunpack: error: the following arguments are required: command\n"),
        (&["--"], "sunpack: error: the following arguments are required: command\n"),
        (&["version", "-h=x"], "sunpack version: error: argument -h: ignored explicit argument 'x'\n"),
        (&["extract", "x", "-h=x"], "sunpack extract: error: argument -h: ignored explicit argument 'x'\n"),
        (&["scan", "x", "-jp"], "sunpack scan: error: argument -j: ignored explicit argument 'p'\n"),
        (&["scan", "x", "-junknown"], "sunpack scan: error: argument -j: ignored explicit argument 'unknown'\n"),
        (&["pw", "-hjunk"], "sunpack passwords: error: argument -j: ignored explicit argument 'unk'\n"),
        (&["passwords", "--", "-j"], "sunpack: error: unrecognized arguments: -- -j\n"),
        (&["config", "validate", "--"], "sunpack: error: unrecognized arguments: --\n"),
        (&["extract", "x", "-r", "0"], "sunpack extract: error: argument -r: recursive_extract must be \"*\", \"?\", or a positive integer\n"),
        (&["extract", "x", "-r=bad"], "sunpack extract: error: argument -r: recursive_extract must be \"*\", \"?\", or a positive integer\n"),
        (&["extract", "x", "-c", "bad"], "sunpack extract: error: argument -c: archive_cleanup_mode must be one of: d, r, k\n"),
        (&["scan", "x", "-j=thing"], "sunpack scan: error: argument -j: ignored explicit argument 'thing'\n"),
        (&["watch", "rm", "-pa", "-npa"], "sunpack watch remove: error: argument -npa: not allowed with argument -pa\n"),
        (&["watch", "--foo", "nonsense"], "sunpack watch: error: argument watch_action: invalid choice: 'nonsense' (choose from enable, ea, disable, da, add, remove, rm, list, ls, reload, rl, relog, rlg, status, st)\n"),
        (&["extract", "--foo"], "sunpack extract: error: the following arguments are required: paths\n"),
        (&["extract", "--foo", "--bar"], "sunpack extract: error: the following arguments are required: paths\n"),
        (&["--foo", "scan", "x", "--bar"], "sunpack: error: unrecognized arguments: --foo --bar\n"),
        (&["daemon", "startup", "-j"], "sunpack daemon startup: error: the following arguments are required: action\n"),
        (&["daemon", "startup", "bad", "-h"], "sunpack daemon startup: error: argument action: invalid choice: 'bad' (choose from enable, disable, status)\n"),
    ];
    let host = Host::new();
    for &(args, expected) in cases {
        let input = Arc::new(Input::default());
        let code = run_console(&host, Path::new("."),
            args.iter().map(|arg| (*arg).to_owned()).collect(),
            input.clone(), Cancellation::new()).unwrap();
        assert_eq!(code, 2, "{args:?}");
        assert!(input.stdout.lock().unwrap().is_empty(), "{args:?}");
        assert_eq!(&*input.stderr.lock().unwrap(), expected.as_bytes(), "{args:?}");
    }
}

#[test]
fn failed_request_drains_and_joins_queued_progress_before_unwinding() {
    let reports = Arc::new(reporting::Reports::default());
    reports.notify(Event::Working { id: 7 });
    // Capture the failure before releasing the request's reporter lifetime.
    let failure = crate::pipeline::block_on(settle_unwind(async { panic!("request failure") }));
    assert!(failure.is_err());
    reports.close();
    let scheduler = crate::pipeline::Scheduler::new();
    let (sent, received) = std::sync::mpsc::channel();
    let service = Arc::clone(&reports);
    let output = scheduler.submit(1, crate::pipeline::Origin::Foreground, &Cancellation::new(), move |_| Box::pin(async move {
        service.serve_async(|| {
            for event in service.take_events() { sent.send(event).unwrap(); }
        }).await;
    }));
    output.join().unwrap();
    assert!(matches!(received.try_recv().unwrap(), Event::Working { id: 7 }));
    assert!(received.try_recv().is_err());
    assert!(reports.take_events().is_empty());
}

#[test]
fn retry_replaces_all_carrier_segments_when_nested_input_becomes_root() {
    fn archive(path: &str, depth: usize, offset: u64, failed: bool) -> ArchiveResult {
        ArchiveResult {
            path: path.into(), format: "zip".into(), output: None,
            failure: failed.then(|| crate::pipeline::Failure::new(FailureKind::WrongPassword, "password")),
            files: 0, bytes: 0, encrypted: None, depth, offset, end_offset: None,
            volume_completeness: None, volume_attempts: None, source_paths: vec![],
            password: None, discovery_source: crate::pipeline::DiscoverySource::Embedded,
            partial: false, retained: false, recovered_complete_files: 0,
              scan_layout: Default::default(),
        }
    }
    let mut failed = HashSet::new();
    record_archive_failures(&mut failed, &[
        archive("C:/data/Carrier.bin", 2, 100, true),
        archive("C:/data/Carrier.bin", 2, 900, false),
        archive("C:/data/other.zip", 1, 0, false),
    ]);
    assert_eq!(failed, HashSet::from([path_key(Path::new("C:/data/Carrier.bin"))]));
    record_archive_failures(&mut failed, &[archive("c:/DATA/carrier.bin", 1, 100, false)]);
    assert!(failed.is_empty());
}

#[test]
fn settled_failure_and_partial_trees_keep_the_last_known_progress() {
    for (partial, known, interactive) in [
        (false, true, true), (true, true, true), (false, false, true),
        (false, true, false), (true, true, false), (false, false, false),
    ] {
        let input = Arc::new(Input { interactive, ..Input::default() });
        let progress = Progress {
            session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
            cancel: Cancellation::new(), language: Language::En,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            prompt: false, visible: true, verbose: false,
        };
        assert!(matches!(progress.worker_updates(), crate::pipeline::WorkerUpdates::All));
        progress.notify(Event::Queued { id: 7, parent: None, path: "embedded.bin".into(), segment: None });
        if known {
            progress.notify(Event::Progress { id: 7, completed_bytes: 40, total_bytes: 100 });
        }
        progress.flush_events();
        if !interactive { assert!(input.stdout.lock().unwrap().is_empty()); }
        input.stdout.lock().unwrap().clear();
        let archive = ArchiveResult {
            path: "embedded.bin".into(), format: "zip".into(), output: None,
            failure: Some(crate::pipeline::Failure::new(FailureKind::Damaged, "damage")),
            files: 0, bytes: 0, encrypted: None, depth: 1, offset: 123,
            end_offset: None, volume_completeness: None, volume_attempts: None,
            source_paths: vec![], password: None, discovery_source: crate::pipeline::DiscoverySource::Embedded,
            partial, retained: false, recovered_complete_files: 0,
              scan_layout: Default::default(),
        };
        // Production publishes the terminal task fact before scope reporting.
        progress.notify(Event::Finished { id: 7,
            result: crate::pipeline::TaskCompletion::from_result(&archive) });
        progress.finish_scope(7, &[archive]).unwrap();
        let text = String::from_utf8(input.stdout.lock().unwrap().clone()).unwrap();
        let status = Language::En.text(if partial { "report.status.partial" } else { "report.status.error" });
        let expected = if known { " [########------------]  40%" } else { " [--------------------]  --%" };
        assert!(text.contains(&format!("[{status}]{expected}")), "{text}");
        assert!(!text.contains("100%"), "{text}");
        if !interactive { assert!(!text.contains('\x1b'), "{text}"); }
        input.stdout.lock().unwrap().clear();
        progress.flush_events();
        assert!(input.stdout.lock().unwrap().is_empty());
    }
}

fn report_archive(path: &str, offset: u64) -> ArchiveResult {
    ArchiveResult {
        path: path.into(), format: "zip".into(), output: None, failure: None,
        files: 0, bytes: 0, encrypted: None, depth: 1, offset,
        end_offset: None, volume_completeness: None, volume_attempts: None,
        source_paths: vec![], password: None, discovery_source: crate::pipeline::DiscoverySource::Embedded,
        partial: false, retained: false, recovered_complete_files: 0,
          scan_layout: crate::pipeline::ScanLayout { range: offset != 0, volumes: false },
    }
}

#[test]
fn scan_keeps_inconclusive_errors_without_changing_retry_or_json() {
    for kind in [FailureKind::WrongPassword, FailureKind::PasswordInconclusive] {
        for language in [Language::En, Language::Zh] {
            for json in [false, true] {
                let mut archive = report_archive("encrypted.zip", 0);
                let mut failure = crate::pipeline::Failure::new(kind, "probe failed");
                failure.password_retry = true;
                let message = failure_message(&failure, language).into_owned();
                archive.failure = Some(failure);
                archive.encrypted = Some(true);
                assert!(password_failure(&archive));
                let mut outcome = Outcome::default();
                outcome.archives.push(archive);
                let mut options = Options::parse(&["scan".into(), "encrypted.zip".into()]).unwrap();
                options.json = json;
                let session = Input::default();
                let (_, result) = report_scan(outcome, vec![], &options, &session, language).unwrap();
                if json {
                    let report = serde_json::to_value(result).unwrap();
                    let item = report["items"].get(0).unwrap();
                    assert_eq!(item["error"], message);
                    assert_eq!(item["error_kind"], serde_json::to_value(kind).unwrap());
                } else {
                    let text = String::from_utf8(session.combined.lock().unwrap().clone()).unwrap();
                    let error_line = language.translate("cli.scan.error", &[("error", &message)]);
                    assert_eq!(text.contains(&error_line), kind == FailureKind::PasswordInconclusive, "{text}");
                }
            }
        }
    }
}

// Checks the carrier/segment hierarchy in both final output modes, including
// failed parent status and the shared two-space detail indentation.
#[test]
fn carrier_final_and_scan_reports_keep_parent_status_and_detail_indentation() {
    for ascii in [false, true] {
        let input = Arc::new(Input { ascii, ..Input::default() });
        let progress = Progress {
            session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
            cancel: Cancellation::new(), language: Language::En,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            prompt: false, visible: true, verbose: false,
        };
        let mut archives = vec![
            report_archive("carrier.bin", 10), report_archive("carrier.bin", 20),
            report_archive("child.zip", 0), report_archive("other.zip", 0),
        ];
        archives[2].depth = 2;
        archives[1].failure = Some(crate::pipeline::Failure::new(FailureKind::Damaged, "damage"));
        for (id, parent, position, segment) in [
            (1, None, 0, None),
            (2, Some(1), 0, Some(1)),
            (3, Some(1), 1, Some(2)),
            (4, Some(2), 2, None),
            (5, None, 3, None),
        ] {
            let archive = &archives[position];
            progress.notify(Event::Queued { id, parent, path: archive.path.clone(),
                segment: segment.map(|index| crate::pipeline::Segment {
                    index, offset: archive.offset, end_offset: archive.end_offset, format: archive.format.clone(),
                }) });
            progress.notify(Event::Finished { id,
                result: if id == 1 { crate::pipeline::TaskCompletion::from_group(&archives[..2]) }
                    else { crate::pipeline::TaskCompletion::from_result(archive) } });
        }
        progress.finish_scope(1, &archives[..3]).unwrap();
        progress.finish_scope(5, &archives[3..]).unwrap();
        let bytes = std::mem::take(&mut *input.stdout.lock().unwrap());
        let text = String::from_utf8(bytes).unwrap();
        let error = Language::En.text("report.status.error");
        assert!(text.starts_with(&format!("carrier.bin\n  [{error}]")), "{text}");
        assert_eq!(text.matches(&format!("[{error}]")).count(), 2, "{text}");
        let (_, continuation) = tree_edge(!ascii, false);
        let (edge, _) = tree_edge(!ascii, true);
        assert!(text.contains(&format!("\n{continuation}{edge}child.zip\n")), "{text}");
        let segment = Language::En.translate("cli.scan.segment", &[("index", "2")]);
        assert!(text.find("child.zip").unwrap() < text.find(&segment).unwrap(), "{text}");
        assert!(text.find(&segment).unwrap() < text.find("\nother.zip\n").unwrap(), "{text}");
        let options = Options::parse(&["scan".into(), "carrier.bin".into()]).unwrap();
        input.combined.lock().unwrap().clear();
        let mut outcome = Outcome::default();
        outcome.archives = archives;
        report_scan(outcome, vec![], &options, input.as_ref(), Language::En).unwrap();
        let text = String::from_utf8(input.stdout.lock().unwrap().clone()).unwrap();
        let combined = String::from_utf8(input.combined.lock().unwrap().clone()).unwrap();
        let segment = Language::En.translate("cli.scan.segment", &[("index", "2")]);
        let error = Language::En.translate("cli.scan.error", &[("error", Language::En.text("failure.damaged"))]);
        assert!(combined.find(&segment).unwrap() < combined.find(&error).unwrap(), "{combined}");
        let format = Language::En.translate("cli.scan.format", &[("format", "zip")]);
        for last in [false, true] {
            let (_, continuation) = tree_edge(!ascii, last);
            assert!(text.lines().any(|line| line == format!("{continuation}  {format}")), "{text}");
        }
    }
}

// One output fact has two uses: verbose recovery detail and accepted top-level
// summary location. Failed rescue bytes must not acquire success semantics.
#[test]
fn summary_output_requires_an_accepted_root_input_but_verbose_keeps_failure_output() {
    for (accepted_sibling, accepted_partial) in [(false, false), (true, false), (false, true)] {
        let session = Arc::new(Input::default());
        let progress = Progress {
            session: session.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
            cancel: Cancellation::new(), language: Language::En,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            prompt: false, visible: true, verbose: true,
        };
        let mut failed = report_archive("carrier.bin", 0);
        failed.failure = Some(crate::pipeline::Failure::new(
            if accepted_partial { FailureKind::Damaged } else { FailureKind::Unsupported }, "failure"));
        failed.output = Some(PathBuf::from("rescued-output"));
        failed.partial = accepted_partial;
        let mut archives = vec![failed];
        if accepted_sibling { archives.push(report_archive("carrier.bin", 100)); }
        // A complete recursive descendant does not authorize its failed root.
        let mut nested = report_archive("nested.zip", 0);
        nested.depth = 2;
        archives.push(nested);
        let mut completion = crate::pipeline::TaskCompletion::from_group(&archives[..archives.len() - 1]);
        completion.output = Some(PathBuf::from("rescued-output"));
        progress.notify(Event::Queued { id: 1, parent: None, path: "carrier.bin".into(), segment: None });
        progress.notify(Event::Finished { id: 1, result: completion });
        progress.finish_scope(1, &archives).unwrap();
        assert!(String::from_utf8(session.stdout.lock().unwrap().clone()).unwrap().contains("rescued-output"));
        let display = progress.display.lock().unwrap();
        assert_eq!(display.outputs.len(), usize::from(accepted_sibling || accepted_partial));
    }
}

// Rendering two completions separately protects the retry round boundary:
// counts and durations must not inherit a preceding attempt or prompt time.
#[test]
fn extract_round_summaries_keep_counts_times_and_cleanup_local() {
    let input = Input::default();
    let mut first = Outcome::default();
    first.archives.push(report_archive("good.zip", 0));
    let mut blocked = report_archive("locked.zip", 0);
    blocked.failure = Some(crate::pipeline::Failure::new(FailureKind::WrongPassword, "wrong"));
    first.archives.push(blocked);
    first.cleanup_results.push(crate::pipeline::CleanupResult {
        path: "good.zip".into(), mode: "delete", status: CleanupStatus::Failed,
        error_code: 5, message: "locked".into(),
    });
    report_extract_round(&first, &[PathBuf::from("carrier-output")], 1, &input, Language::En).unwrap();
    line(&input, Stream::Out, Language::En.text("cli.password_retry_prompt")).unwrap();
    let mut second = Outcome::default();
    second.archives.push(report_archive("locked.zip", 0));
    report_extract_round(&second, &[], 2, &input, Language::En).unwrap();
    let text = String::from_utf8(input.combined.lock().unwrap().clone()).unwrap();
    let prompt = text.find(Language::En.text("cli.password_retry_prompt")).unwrap();
    for (elapsed, failed, slice) in [("1", "1", &text[..prompt]), ("2", "0", &text[prompt..])] {
        let duration = Language::En.translate("duration.seconds", &[("seconds", elapsed)]);
        assert!(slice.contains(&Language::En.translate("report.time", &[("duration", &duration)])), "{slice}");
        assert!(slice.contains(&Language::En.translate("report.counts", &[
            ("complete", "1"), ("partial", "0"), ("failed", failed), ("scan_errors", "0"), ("input_errors", "0"),
        ])), "{slice}");
    }
    assert!(text[..prompt].contains("good.zip: locked"));
    assert!(!text[prompt..].contains("good.zip: locked"));
    assert!(text[..prompt].contains("carrier-output"));
}

#[test]
fn partial_recovery_warning_reuses_full_carrier_report_and_omits_confirmed_missing() {
    let mut archive = report_archive("split.7z.001", 0);
    archive.partial = true;
    archive.output = Some("recovered".into());
    archive.recovered_complete_files = 2;
    let mut failure = crate::pipeline::Failure::new(FailureKind::Damaged, "damaged")
        .with_context(crate::pipeline::FailureContext::Extraction);
    failure.evidence = Some(Box::new(crate::pipeline::FailureEvidence {
        possible_missing_volume: true, ..Default::default()
    }));
    failure.recovery = Some(Arc::new(serde_json::from_value(json!({
        "inputs":[], "output":"recovered", "input_count":1,
        "had_checkpoints":false, "retry_output":true,
    })).unwrap()));
    archive.failure = Some(failure);
    let summary = ArchiveSummary::collect([&archive], Language::En, true);
    let warning = summary.recovered[0].warning.as_ref().unwrap();
    assert_eq!(warning.as_object().unwrap().len(), 8);
    assert_eq!(warning, &serde_json::to_value(failures::archive_report(&[&archive], Language::En).unwrap()).unwrap());
    assert_eq!(warning["stage"], "extraction_report");
    assert_eq!(warning["message_key"], "failure.possible_missing_volume");
    assert_eq!(warning["details"]["missing_volume_confirmed"], false);
    assert_eq!(warning["details"]["partial_recovery"], true);
    assert_eq!(warning["details"]["retry_output_dir"], "recovered");
    assert!(warning["details"].get("input_recovery").is_some());
    assert_eq!(warning["causes"][0]["kind"], "damaged");
    let message = warning["message"].as_str().unwrap().to_owned();
    let mut outcome = Outcome::default();
    outcome.archives.push(archive);
    for confirmed in [false, true] {
        if confirmed { outcome.archives[0].failure.as_mut().unwrap().kind = FailureKind::MissingVolume; }
        let summary = ArchiveSummary::collect(&outcome.archives, Language::En, true);
        assert_eq!(summary.recovered[0].warning.is_some(), !confirmed);
        let input = Input::default();
        report_extract_round(&outcome, &[], 0, &input, Language::En).unwrap();
        let text = String::from_utf8(input.combined.lock().unwrap().clone()).unwrap();
        assert_eq!(text.contains(&Language::En.translate("report.partial_warning", &[("warning", &message)])), !confirmed);
    }
}

#[test]
fn final_failure_summary_uses_main_names_and_keeps_carrier_status() {
    let mut archive = report_archive("C:/inputs/blocked.zip", 0);
    archive.failure = Some(crate::pipeline::Failure::new(FailureKind::Damaged, "native detail"));
    let summary = ArchiveSummary::collect([&archive], Language::En, true);
    assert_eq!(summary.errors, [format!("blocked.zip [{}]", Language::En.text("failure.damaged"))]);
    archive.depth = 2;
    let summary = ArchiveSummary::collect([&archive], Language::En, true);
    assert_eq!(summary.errors, [format!("C:/inputs/blocked.zip [{}]", Language::En.text("failure.damaged"))]);
    archive.depth = 1;
    let mut sibling = report_archive("C:/inputs/blocked.zip", 10);
    sibling.failure = Some(crate::pipeline::Failure::new(FailureKind::WrongPassword, "native password"));
    let summary = ArchiveSummary::collect([&archive, &sibling], Language::En, false);
    let message = format!("blocked.zip [{}]", Language::En.text("failure.embedded_extract_failed"));
    assert_eq!(summary.errors, [Language::En.translate("report.failed", &[("task", &message)])]);
}

#[test]
fn scan_json_keeps_main_sparse_fields_without_internal_failure_evidence() {
    let options = Options::parse(&["scan".into(), "-j".into(), "-v".into(), "input.bin".into()]).unwrap();
    let mut archive = report_archive("input.bin", 0);
    archive.format.clear();
    let mut failure = crate::pipeline::Failure::new(FailureKind::Damaged, "damage");
    failure.evidence = Some(Box::new(crate::pipeline::FailureEvidence {
        stage: Some("item_extract".into()), ..Default::default()
    }));
    archive.failure = Some(failure);
    let mut outcome = Outcome::default();
    outcome.archives.push(archive);
    let mut second_segment = report_archive("input.bin", 200);
    second_segment.failure = Some(crate::pipeline::Failure::new(FailureKind::Damaged, "damage"));
    outcome.archives.push(second_segment);
    let mut other_task = report_archive("a-first-in-sorted-items.zip", 0);
    other_task.failure = Some(crate::pipeline::Failure::new(FailureKind::Unsupported, "unsupported"));
    outcome.archives.push(other_task);
    outcome.scan_failures.push(crate::pipeline::ScanTaskFailure {
        path: "input.bin".into(), archives: 0..2, preflight: None,
    });
    outcome.scan_failures.push(crate::pipeline::ScanTaskFailure {
        path: "a-first-in-sorted-items.zip".into(), archives: 2..3, preflight: None,
    });
    outcome.errors.push(InputError { path: "folder".into(), message: "access denied".into(),
        kind: InputErrorKind::FilesystemScan, scan_operation: Some("read_dir".into()), failure: None });
    let (_, report) = report_scan(outcome, vec![], &options, &Input::default(), Language::En).unwrap();
    assert_eq!(report.errors, [
        "Cannot read directory: folder (access denied)".to_owned(),
        format!("input.bin [{}]", Language::En.text("failure.embedded_extract_failed")),
        format!("a-first-in-sorted-items.zip [{}]", Language::En.text("failure.unsupported")),
    ]);
    assert_eq!(report.summary, json!({"archive_count": 3, "failed_count": 2, "scan_error_count": 1, "input_error_count": 0}));
    let report = serde_json::to_value(report).unwrap();
    let items = report["items"].as_array().unwrap();
    assert_eq!(items[0]["main_path"], "a-first-in-sorted-items.zip");
    let item = &items[1];
    assert!(item.get("format").is_none());
    assert!(item.get("damage_flags").is_none());
    assert!(item.get("failure").is_none());
    assert_eq!(item["error_kind"], "damaged");
    assert_eq!(item["error"], Language::En.text("failure.damaged"));
    assert_eq!(item["discovery_source"], "embedded");
}

// Both renderers consume descriptor facts, not a guessed meaning for a
// finite end or an internal completeness value. Each row distinguishes a
// public sparse-field boundary that the ordinary file case cannot cover.
#[test]
fn scan_sparse_layout_is_shared_by_text_and_json() {
    use crate::io::archive_state::{AnalysisOrigin, ArchiveInput, InputExtent, InputPart, InputRole, OpenMode};
    use crate::io::archive_state::VolumeCompleteness::{Complete, Missing, Unknown};
    for (mode, origin, start, complete, show_range, show_parts, public_complete) in [
        (OpenMode::FileRange, AnalysisOrigin::Embedded, 64, Complete, true, false, None),
        (OpenMode::FileRange, AnalysisOrigin::Embedded, 0, Complete, true, false, None),
        (OpenMode::NativeVolumes, AnalysisOrigin::Relations, 0, Complete, false, true, Some("complete")),
        (OpenMode::NativeVolumes, AnalysisOrigin::Relations, 0, Unknown, false, true, None),
        (OpenMode::File, AnalysisOrigin::Plain, 0, Missing, false, true, Some("missing")),
    ] {
        let mut descriptor = ArchiveInput::file("carrier.bin".into(), "zip".into(), "carrier".into());
        descriptor.mode = mode;
        descriptor.analysis.origin = origin;
        descriptor.parts = vec![InputPart {
            role: InputRole::Main, extent: InputExtent { path: "carrier.bin".into(), start, end: Some(100) },
            volume_number: None, canonical_name: String::new(),
        }].into_boxed_slice();
        for json in [false, true] {
            let mut archive = report_archive("carrier.bin", start);
            archive.end_offset = Some(100);
            archive.source_paths.push("carrier.bin".into());
            archive.volume_completeness = Some(complete);
            archive.scan_layout = crate::pipeline::ScanLayout::from_input(&descriptor);
            let mut outcome = Outcome::default();
            outcome.archives.push(archive);
            let mut options = Options::parse(&["scan".into(), "carrier.bin".into()]).unwrap();
            options.json = json;
            let session = Input::default();
            let (_, result) = report_scan(outcome, vec![], &options, &session, Language::En).unwrap();
            if json {
                let report = serde_json::to_value(result).unwrap();
                let item = report["items"].get(0).unwrap();
                assert_eq!(item.get("offset").is_some(), show_range, "{mode:?}");
                assert_eq!(item.get("end_offset").is_some(), show_range, "{mode:?}");
                assert_eq!(item.get("all_parts").is_some(), show_parts, "{mode:?}");
                assert_eq!(item.get("volume_completeness").and_then(Value::as_str), public_complete, "{mode:?}");
            } else {
                let text = String::from_utf8(session.stdout.lock().unwrap().clone()).unwrap();
                let range = Language::En.translate("cli.scan.range", &[("start", &start.to_string()), ("end", "100")]);
                let parts = Language::En.translate("cli.scan.parts", &[("parts", "carrier.bin")]);
                assert_eq!(text.contains(&range), show_range, "{mode:?}: {text}");
                assert_eq!(text.contains(&parts), show_parts, "{mode:?}: {text}");
                assert!(!text.contains("unknown"), "{text}");
                if let Some(value) = public_complete {
                    let state = Language::En.text(&format!("cli.scan.volumes.{value}")).to_owned();
                    let line = Language::En.translate("cli.scan.volumes", &[("state", &state)]);
                    assert!(text.contains(&line), "{text}");
                }
            }
        }
    }
}

// Rendering must not consume a native call frame per nesting level. The
// small thread stack catches recursive traversal without Windows fixtures.
#[test]
fn deeply_nested_final_tree_uses_an_explicit_traversal_stack() {
    std::thread::Builder::new().stack_size(128 * 1024).spawn(|| {
        let count = 2048;
        let mut panel = live::Panel::new(false);
        let session = Input::default();
        for id in 1..=count {
            panel.update(&session, Language::En, Event::Queued {
                id, parent: (id > 1).then_some(id - 1), path: format!("{id}.zip").into(),
                segment: None,
            }, true);
        }
        panel.write_scope(1, true, Language::En, &mut io::sink()).unwrap();
    }).unwrap().join().unwrap();
}

#[test]
fn scope_completion_flushes_queued_panel_events_before_removing_the_scope() {
    let input = Arc::new(Input { interactive: true, ..Input::default() });
    let progress = Progress {
        session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
        cancel: Cancellation::new(), language: Language::En,
        display: Mutex::default(), reporting: reporting::Reports::default(),
        prompt: false, visible: true, verbose: false,
    };
    progress.notify(Event::Queued { id: 7, parent: None, path: "test.zip".into(), segment: None });
    progress.finish_scope(7, &[]).unwrap();
    input.stdout.lock().unwrap().clear();
    progress.flush_events();
    assert!(input.stdout.lock().unwrap().is_empty(), "a queued old event must not resurrect a completed scope");
}

#[test]
fn completed_scope_releases_only_its_panel_tree() {
    for prompting in [false, true] {
        let session = Arc::new(Input::default());
        let progress = Progress {
            session: session.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
            cancel: Cancellation::new(), language: Language::En,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            prompt: false, visible: true, verbose: false,
        };
        progress.display.lock().unwrap().prompting = prompting;
        let parent = report_archive("parent.zip", 0);
        let mut child = report_archive("child.zip", 0);
        child.depth = 2;
        let other = report_archive("other.zip", 0);
        progress.notify(Event::Queued { id: 3, parent: None, path: other.path.clone(), segment: None });
        progress.notify(Event::Queued { id: 1, parent: None, path: parent.path.clone(), segment: None });
        progress.notify(Event::Queued { id: 2, parent: Some(1), path: child.path.clone(), segment: None });
        progress.notify(Event::Finished { id: 2,
            result: crate::pipeline::TaskCompletion { discovery: None, status: TaskStatus::Skipped,
                failure: None, output: None } });
        progress.finish_scope(1, &[parent, child]).unwrap();
        let mut display = progress.display.lock().unwrap();
        if prompting {
            assert!(session.stdout.lock().unwrap().is_empty());
            progress.resume_panel(&mut display);
        }
        let stdout = session.stdout.lock().unwrap();
        let text = std::str::from_utf8(&stdout).unwrap();
        assert_eq!(text.matches("parent.zip").count(), 1, "{text}");
        assert_eq!(text.matches("child.zip").count(), 1, "{text}");
        assert!(!text.contains("other.zip"), "{text}");
        let mut bytes = Vec::new();
        display.panel.as_ref().unwrap().write_scope(1, true, Language::En, &mut bytes).unwrap();
        assert!(bytes.is_empty());
        display.panel.as_ref().unwrap().write_scope(3, true, Language::En, &mut bytes).unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("other.zip"));
    }
}

#[test]
fn cancelling_password_prompt_returns_interrupted_not_usage() {
    let host = Host::new();
    // Prompt cancellation must finish before any worker can be started.
    assert!(host.engine.set(Arc::new(Engine::with_scheduler(
        PathBuf::from("missing-worker-for-cancelled-prompt.exe"), Arc::clone(&host.scheduler),
    ))).is_ok());
    let input = Arc::new(Input { cancel_input: true, ..Input::default() });
    let cwd = std::env::current_dir().unwrap();
    let result = crate::pipeline::block_on(run(
        &host, &cwd,
        vec!["extract".into(), "-a".into(), "-npa".into(), "cancelled.zip".into()],
        input.clone(), Cancellation::new(),
    ));
    assert_eq!(input.reads.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(result.unwrap(), 130);
}

#[test]
fn connection_command_future_can_move_between_shared_executor_polls() {
    fn assert_send(_: impl std::future::Future + Send) {}
    let host = Host::new();
    let input: Arc<dyn Session> = Arc::new(Input::default());
    assert_send(run(&host, Path::new("."), vec!["version".into()], input, Cancellation::new()));
}

#[test]
fn json_recursion_reads_authorization_without_polluting_stdout() {
    let input = Arc::new(Input::default());
    input.answers.lock().unwrap().extend(["invalid".into(), "yes".into(), "n".into()]);
    let watch = Arc::new(watch::Watch::new(Arc::new(|| {})));
    let cancel = Cancellation::default();
    let progress = Progress {
        session: input.clone(), watch, cancel, language: Language::En,
        display: Mutex::default(), reporting: reporting::Reports::default(),
        prompt: true, visible: false, verbose: false,
    };
    assert!(crate::pipeline::block_on(progress.allow_recursive_async(2, 1)));
    assert!(!crate::pipeline::block_on(progress.allow_recursive_async(3, 1)));
    assert!(input.answers.lock().unwrap().is_empty());
    assert!(input.stdout.lock().unwrap().is_empty());
    assert!(!input.stderr.lock().unwrap().is_empty());
}
