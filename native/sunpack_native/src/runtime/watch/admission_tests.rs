//! Real admission methods with a checkpoint-local barrier, not a simulated queue.
use super::*;
use crate::watch_store::PendingObservation;
use std::os::windows::fs::OpenOptionsExt;
use std::process::Command;

#[test]
fn stopped_watch_saves_conflicting_outputs_for_runtime_validation() {
    const CHILD: &str = "SUNPACK_WATCH_OUTPUT_CONFIG_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let watch = Watch::new(Arc::new(|| {}));
        let first = base.join("first");
        let second = base.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let output = base.join("output");
        let nested = output.join("nested");
        for (root, output) in [(&first, &output), (&second, &nested)] {
            let result = block_on(watch.add_async(
                &base, std::slice::from_ref(root), output.to_str(), false, false,
            )).unwrap();
            assert_eq!(result["added"], json!([root]));
        }
        let roots = read_roots(&roots_path(&base).unwrap()).unwrap();
        let error = validate_outputs(&roots).unwrap_err().to_string();
        for (root, output) in [(&first, &output), (&second, &nested)] {
            assert!(error.contains(&format!("{} -> {}", root.display(), output.display())));
        }
        return;
    }
    run_isolated("stopped_watch_saves_conflicting_outputs_for_runtime_validation", CHILD);
}

#[test]
fn checkpoint_submits_the_first_ready_generation() {
    const CHILD: &str = "SUNPACK_ADMISSION_CHECKPOINT_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        for case in ["stable", "resnapshot", "content", "claim", "owned", "owned_content", "error", "stop"] {
            let directory = base.join(case);
            let watched = directory.join("watched");
            fs::create_dir_all(&watched).unwrap();
            let source = watched.join("input.zip");
            fs::write(&source, b"initial archive bytes").unwrap();
            let id = watch_path_key(source.to_str().unwrap());
            let root_id = key(&watched);
            let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
            let settings = Arc::new(Config::default());
            let journal = Arc::new(journal::Journal::open(&directory.join("state"), 7).unwrap());
            let mut scheduler = Scheduler {
                candidate_diagnostics: CandidateDiagnostics::default(),
                admission_checkpoint: None,
                cwd: base.clone(), root_file: directory.join(ROOTS_FILE),
                roots: BTreeMap::from([(root_id.clone(), (Root { path: watched.clone(), output: None,
                    recursive: true, deep: false, scanned: true }, scope))]),
                available_roots: HashSet::from([root_id.clone()]),
                user_password_signature: user_password_signature(&settings.user_passwords),
                settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
                catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
                options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
                deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
                passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
                root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
                parent_observers: HashMap::new(), config_observers: Vec::new(),
                pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
                active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
                tray: None, monitor: None, toast: None, cache_deadline: None,
                external: Arc::new(Mutex::new(None)), _lease: None,
            };
            let source_text = source.to_str().unwrap();
            if case == "stable" {
                let candidate = watch_candidate_for_path(&source, None).unwrap().unwrap();
                scheduler.journal.commit(true, |_| {
                    let mut operations = crate::watch_store::NativeWatchOperations::empty();
                    operations.put_entry(Arc::new(observed_entry(&candidate, "interrupted", None)));
                    Ok(operations)
                }).unwrap();
                scheduler.enqueue(&root_id, source_text.to_owned(), CandidateAdmission::Observe).unwrap();
                assert!(scheduler.pending.is_empty());
                scheduler.enqueue(&root_id, source_text.to_owned(), CandidateAdmission::ExplicitRetry).unwrap();
                assert!(scheduler.journal.state().entry(source_text).is_none());
            } else {
                scheduler.enqueue(&root_id, source_text.to_owned(), CandidateAdmission::Retry).unwrap();
            }
            let admitted = scheduler.pending[&id].candidate.clone();
            let held = Arc::new(Mutex::new(None));
            let held_in_check = Arc::clone(&held);
            let check_source = source.clone();
            let check_id = id.clone();
            scheduler.admission_checkpoint = Some(Box::new(move |scheduler| {
                assert!(!scheduler.pending.contains_key(&check_id), "ready generation was reinserted: {case}");
                assert!(scheduler.journal.state().pending(check_source.to_str().unwrap()).is_some(),
                    "admission must be durable before checkpoint/submit");
                if matches!(case, "content" | "owned_content") {
                    fs::write(&check_source, b"new and larger archive generation written after checkpoint").unwrap();
                    scheduler.enqueue(&root_id, check_source.to_string_lossy().into_owned(), CandidateAdmission::Observe).unwrap();
                }
                if case == "claim" {
                    scheduler.hub.claims.lock().unwrap().insert(check_id.clone(), Arc::from("foreground"));
                }
                if case == "resnapshot" {
                    let file = fs::OpenOptions::new().write(true).open(&check_source).unwrap();
                    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(20)).unwrap();
                }
                if matches!(case, "owned" | "owned_content") {
                    let output = check_source.parent().unwrap().to_string_lossy().into_owned();
                    let identity = output_identity(&output).unwrap();
                    scheduler.journal.commit(true, |_| Ok(crate::watch_store::NativeWatchOperations::owned_outputs(
                        &[output], &[&identity],
                    ))).unwrap();
                }
                if case == "stop" { scheduler.hub.stopped.store(true, Ordering::Release); }
                // Every case now conflicts with a second readiness probe. main
                // still submits its first batch, including new checkpoint events.
                *held_in_check.lock().unwrap() = Some(fs::OpenOptions::new().write(true)
                    .share_mode(7).open(&check_source).unwrap());
                assert!(!filesystem::watch_file_is_ready(check_source.to_str().unwrap()).unwrap());
                if case == "error" { return Err(io::Error::other("checkpoint publication failed")); }
                Ok(())
            }));
            let result = scheduler.dispatch_ready();
            assert_eq!(result.is_err(), case == "error", "{case}: {result:?}");
            assert!(scheduler.admission_checkpoint.is_none(), "checkpoint barrier not reached: {case}");
            if matches!(case, "error" | "stop") {
                assert!(scheduler.active.is_empty());
                assert!(scheduler.journal.state().pending(source_text).unwrap().matches_observation(&admitted),
                    "failed/stopped admission lost its durable generation");
            } else if matches!(case, "owned" | "owned_content") {
                assert!(scheduler.active.is_empty());
                assert!(scheduler.journal.state().pending(source_text).is_none());
                if case == "owned_content" {
                    assert!(scheduler.pending[&id].candidate.size > admitted.size);
                    assert!(scheduler.unpublished.contains(&id), "retiring old admission cleared new generation's persistence");
                }
            } else if case == "claim" {
                assert!(scheduler.active.is_empty());
                assert_eq!(scheduler.pending[&id].candidate.size, admitted.size);
            } else {
                let active = scheduler.active.values().next().expect("first prepared batch was not submitted");
                assert!(active.inputs[&id].size == admitted.size && active.inputs[&id].mtime == admitted.mtime,
                    "checkpoint substituted a different generation: {case}");
                if matches!(case, "content" | "owned_content") {
                    assert!(scheduler.pending[&id].candidate.size > admitted.size,
                        "checkpoint's new generation was lost");
                }
            }
            held.lock().unwrap().take();
            scheduler.hub.claims.lock().unwrap().clear();
            scheduler.hub.stop();
            scheduler.drain_active(&mut Ok(0)).unwrap();
        }
        return;
    }
    run_isolated("checkpoint_submits_the_first_ready_generation", CHILD);
}

fn run_isolated(name: &str, child: &str) {
    // Isolate writable-data lookup and the existing empty BrokerLease drop,
    // like the Watch process-boundary tests.
    let marker = crate::test_support::temp_file("watch_admission", b"");
    let base = marker.with_extension("work");
    fs::create_dir_all(&base).unwrap();
    let module = module_path!().split_once("::").unwrap().1;
    let test = format!("{module}::{name}");
    let exe = base.join("sunpack-watch-test.exe");
    fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let output = Command::new(exe).args(["--exact", &test, "--nocapture"])
        .env(child, &base).output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    fs::remove_dir_all(base).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn watch_discovery_read_failure_retries_only_its_archive() {
    // Use the actual native worker at the same executable boundary as Watch.
    // Its installation is optional for standalone Rust library test runs.
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let Ok(worker) = resources::worker_path(&checkout) else { return; };
    let marker = crate::test_support::temp_file("watch_discovery_io", b"");
    let base = marker.with_extension("work");
    let watched = base.join("input");
    let output = base.join("output");
    fs::create_dir_all(&watched).unwrap();
    let bad = watched.join("blocked.rar");
    let good = watched.join("blocked.7z");
    use crate::password::rar::rar5_header_decryption_tests::{hex_bytes, SINGLE_HP_HEX};
    fs::write(&bad, hex_bytes(SINGLE_HP_HEX)).unwrap();
    let payload = base.join("payload.txt");
    fs::write(&payload, b"independent input").unwrap();
    let mut archive = sevenz_rust2::ArchiveWriter::create(&good).unwrap();
    archive.push_archive_entry(sevenz_rust2::ArchiveEntry::from_path(
        &payload, "payload.txt".into()), Some(fs::File::open(&payload).unwrap())).unwrap();
    archive.finish().unwrap();

    let options = NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
    let root = key(&watched);
    let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
    let mut settings = Config::default();
    settings.embedded_scan.enabled = false;
    settings.post_extract.archive_cleanup_mode = crate::core::config::CleanupMode::Keep;
    settings.user_passwords = Arc::from([Arc::from("secret")]);
    let journal = Arc::new(journal::Journal::open(&base.join("state"), 7).unwrap());
    let engine = Arc::new(Engine::new(worker));
    let catalog = Arc::new(NativeWatchCatalog::new(journal.state(), None));
    options.catalog_refresh(&catalog, &scope, None).unwrap();
    let mut scheduler = Scheduler {
        candidate_diagnostics: CandidateDiagnostics::default(),
        admission_checkpoint: None,
        cwd: base.clone(), root_file: base.join(ROOTS_FILE),
        roots: BTreeMap::from([(root.clone(), (Root { path: watched.clone(), output: Some(output.clone()),
            recursive: true, deep: false, scanned: true }, scope))]),
        available_roots: HashSet::from([root.clone()]),
        user_password_signature: user_password_signature(&settings.user_passwords),
        settings: Arc::new(settings), engine, catalog, journal,
        options: None, deep_options: options,
        passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
        root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
        parent_observers: HashMap::new(), config_observers: Vec::new(),
        pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
        active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
        tray: None, monitor: None, toast: None, cache_deadline: None,
        external: Arc::new(Mutex::new(None)), _lease: None,
    };
    scheduler.options = Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap());
    for path in [&good, &bad] {
        scheduler.enqueue(&root, path.to_string_lossy().into_owned(), CandidateAdmission::Retry).unwrap();
    }
    let protected = Arc::new(Mutex::new(None));
    let hold = Arc::clone(&protected);
    let failing = bad.clone();
    scheduler.admission_checkpoint = Some(Box::new(move |scheduler| {
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_WRITE};
        assert!(!scheduler.pending.contains_key(&key(&failing)));
        assert!(scheduler.journal.state().pending(failing.to_str().unwrap()).is_some());
        // Cache the native header in the checkpoint's current catalog. Hold
        // a real sharing conflict through the worker's password session open.
        let scope = &scheduler.roots[&root].1;
        scheduler.options.as_ref().unwrap().catalog_snapshot(&scheduler.catalog, scope, failing.to_str().unwrap())?;
        *hold.lock().unwrap() = Some(fs::OpenOptions::new().write(true)
            .share_mode(FILE_SHARE_WRITE | FILE_SHARE_DELETE).open(&failing)?);
        Ok(())
    }));
    scheduler.dispatch_ready().unwrap();
    scheduler.drain_active(&mut Ok(0)).unwrap();
    drop(protected);
    assert!(scheduler.pending.contains_key(&key(&bad)), "sharing error must requeue the affected archive");
    assert!(!scheduler.pending.contains_key(&key(&good)), "independent archive was retried");
    assert_eq!(fs::read(output.join("blocked/payload.txt")).unwrap(), b"independent input");
    drop(scheduler);
    crate::io::reader::release_reader_resources_under_roots(vec![watched.to_string_lossy().into_owned()]).unwrap();
    fs::remove_dir_all(base).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn recovery_scans_surviving_outputs_while_requeueing_missing_output_owner() {
    const CHILD: &str = "SUNPACK_SURVIVING_OUTPUT_RECOVERY_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        for case in ["source", "missing", "active"] {
            let directory = base.join(case);
            let watched = directory.join("watched");
            fs::create_dir_all(&watched).unwrap();
            let source = watched.join("owner.zip");
            fs::write(&source, b"outer archive").unwrap();
            let root_id = key(&watched);
            let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
            let settings = Arc::new(Config::default());
            let journal = Arc::new(journal::Journal::open(&directory.join("state"), 7).unwrap());
            let mut scheduler = Scheduler {
                admission_checkpoint: None,
                candidate_diagnostics: CandidateDiagnostics::default(),
                cwd: base.clone(), root_file: directory.join(ROOTS_FILE),
                roots: BTreeMap::from([(root_id.clone(), (Root { path: watched.clone(), output: None,
                    recursive: true, deep: false, scanned: true }, scope))]),
                available_roots: HashSet::from([root_id.clone()]),
                user_password_signature: user_password_signature(&settings.user_passwords),
                settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
                catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
                options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
                deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
                passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
                root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
                parent_observers: HashMap::new(), config_observers: Vec::new(),
                pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
                active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
                tray: None, monitor: None, toast: None, cache_deadline: None,
                external: Arc::new(Mutex::new(None)), _lease: None,
            };
            let owner = source.to_str().unwrap();
            let candidate = watch_candidate_for_path(&source, None).unwrap().unwrap();
            scheduler.journal.commit(true, |state| {
                Ok(state.pending_operations(
                    [(PendingObservation(owner.into(), candidate.size as i64, candidate.mtime,
                        candidate.observation.file_id.clone(), candidate.observation.change_usn),
                        watched.to_string_lossy().into_owned(), None)],
                    false, watched.to_str().unwrap(), false, true, None,
                )?.0)
            }).unwrap();
            if case == "active" {
                // The surviving outer archive cannot stand in for a nested
                // task that disappeared while owning uncommitted output.
                let output = watched.join("unfinished-output");
                let task = watched.join("missing-nested.zip");
                scheduler.journal.commit(true, |state| Ok(state.output_operation(owner,
                    task.to_string_lossy().into_owned(), output.to_string_lossy().into_owned(),
                    None, None)?.unwrap())).unwrap();
                scheduler.recover_pending(None).unwrap();
                assert!(!output.exists());
                assert!(scheduler.journal.state().pending(owner).is_some());
                assert!(scheduler.pending.is_empty());
                continue;
            }
            let surviving = watched.join("surviving");
            let missing = watched.join("missing");
            for output in [&surviving, &missing] {
                for keep in [None, Some(true)] {
                    scheduler.journal.commit(true, |state| Ok(state.output_operation(owner,
                        output.to_string_lossy().into_owned(), output.to_string_lossy().into_owned(),
                        keep, None)?.unwrap())).unwrap();
                }
            }
            let nested = surviving.join("unfinished.zip");
            fs::write(&nested, b"nested archive").unwrap();
            fs::remove_dir(&missing).unwrap();
            if case == "missing" { fs::remove_file(&source).unwrap(); }
            scheduler.recover_pending(None).unwrap();
            assert!(scheduler.journal.state().pending(owner).is_some(), "owner intent must survive");
            if case == "source" {
                assert_eq!(scheduler.pending.len(), 2);
                assert!(scheduler.pending.contains_key(&key(&source)));
                assert!(scheduler.pending.contains_key(&key(&nested)));
                assert!(scheduler.journal.state().pending(nested.to_str().unwrap()).is_some());
            } else {
                assert!(scheduler.pending.is_empty(), "unrebuildable owner must remain durable");
            }
        }
        return;
    }
    run_isolated("recovery_scans_surviving_outputs_while_requeueing_missing_output_owner", CHILD);
}

#[test]
fn semantic_reload_recovers_pending_after_output_unlock() {
    use std::os::windows::fs::OpenOptionsExt;
    const CHILD: &str = "SUNPACK_RELOAD_PENDING_RECOVERY_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        let configuration = base.join("sunpack_advanced_config.json");
        fs::write(&configuration, br#"{"cli":{"language":"en"}}"#).unwrap();
        let directory = base.join("recovery");
        let watched = directory.join("watched");
        fs::create_dir_all(&watched).unwrap();
        let source = watched.join("owner.zip");
        fs::write(&source, b"outer archive").unwrap();
            let root_id = key(&watched);
            let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
            let settings = Arc::new(config::load_snapshot(&base).unwrap().config);
            let journal = Arc::new(journal::Journal::open(&directory.join("state"), 7).unwrap());
            let lease = BrokerLease::acquire().unwrap();
            let mut scheduler = Scheduler {
                admission_checkpoint: None,
                candidate_diagnostics: CandidateDiagnostics::default(),
                cwd: base.clone(), root_file: directory.join(ROOTS_FILE),
                roots: BTreeMap::from([(root_id.clone(), (Root { path: watched.clone(), output: None,
                    recursive: true, deep: false, scanned: true }, scope))]),
                available_roots: HashSet::from([root_id.clone()]),
                user_password_signature: user_password_signature(&settings.user_passwords),
                settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
                catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
                options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
                deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
                passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
                root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
                parent_observers: HashMap::new(), config_observers: Vec::new(),
                pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
                active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
                tray: None, monitor: None, toast: None, cache_deadline: None,
                external: Arc::new(Mutex::new(None)), _lease: Some(lease),
            };
            let owner = source.to_str().unwrap();
            let candidate = watch_candidate_for_path(&source, None).unwrap().unwrap();
            scheduler.journal.commit(true, |state| {
                Ok(state.pending_operations(
                    [(PendingObservation(owner.into(), candidate.size as i64, candidate.mtime,
                        candidate.observation.file_id.clone(), candidate.observation.change_usn),
                        watched.to_string_lossy().into_owned(), None)],
                    false, watched.to_str().unwrap(), false, true, None,
                )?.0)
            }).unwrap();

        write_roots(&scheduler.root_file, &[scheduler.roots[&root_id].0.clone()]).unwrap();
        let output = watched.join("interrupted-output");
        scheduler.journal.commit(true, |state| Ok(state.output_operation(owner,
            owner.to_owned(), output.to_string_lossy().into_owned(),
            None, None)?.unwrap())).unwrap();
        let member = output.join("locked.txt");
        fs::write(&member, b"unfinished extraction").unwrap();
        let lock = fs::OpenOptions::new().read(true).share_mode(0).open(&member).unwrap();
        scheduler.recover_pending(None).unwrap();
        assert!(scheduler.pending.is_empty());
        assert!(scheduler.journal.state().pending(owner).is_some());
        drop(lock);
        // Exercise the real shutdown checkpoint with an observer installed.
        // Its fallback scan can admit this source before WAL recovery runs.
        scheduler.rearm_root_observers(None).unwrap();
        fs::write(&configuration, br#"{"cli":{"language":"zh"}}"#).unwrap();
        assert!(scheduler.reload().unwrap());
        assert!(!output.exists(), "semantic restart must retry interrupted cleanup");
        assert!(scheduler.pending.contains_key(&key(&source)), "unchanged durable work must be admitted again");

        // The live subscription must survive a root validation error during
        // an otherwise semantic reload.
        let original = Arc::clone(&scheduler.root_observers[&root_id].root
            .as_ref().unwrap().observer.changes);
        fs::write(&scheduler.root_file, format!("{} | | invalid\n", watched.display())).unwrap();
        fs::write(&configuration, br#"{"cli":{"language":"en"}}"#).unwrap();
        assert!(scheduler.reload().is_err());
        let observer = &scheduler.root_observers[&root_id].root.as_ref().unwrap().observer;
        assert!(observer.alive() && Arc::ptr_eq(&observer.changes, &original));

        // Removing the last root must release the data scheduler, not discard
        // unfinished output ownership. Re-adding it loads the same durable work.
        let root = scheduler.roots[&root_id].0.clone();
        let old_journal = Arc::clone(&scheduler.journal);
        let old_scopes = Arc::from([scheduler.roots[&root_id].1.clone()]);
        write_roots(&scheduler.root_file, std::slice::from_ref(&root)).unwrap();
        let held_output = watched.join("held-output");
        scheduler.journal.commit(true, |state| Ok(state.output_operation(owner,
            owner.to_owned(), held_output.to_string_lossy().into_owned(), None, None)?.unwrap())).unwrap();
        let held_member = held_output.join("locked.txt");
        fs::write(&held_member, b"unfinished output").unwrap();
        let held = fs::OpenOptions::new().read(true).share_mode(0).open(&held_member).unwrap();
        let receipt = Arc::downgrade(&scheduler.journal.state().pending(owner).unwrap());
        write_roots(&scheduler.root_file, &[]).unwrap();
        scheduler.reload().unwrap();
        assert!(scheduler.journal.suspended());
        assert!(scheduler.pending.is_empty() && scheduler.journal.state().pending_items().is_empty());
        assert!(receipt.upgrade().is_none(), "idle shell retained recovery receipts");
        assert!(scheduler.external.lock().unwrap().is_none());
        // A CLI create that captured the prior publication must still create
        // its output if the final root is removed before it reaches the gate.
        let watch = Watch::new(Arc::new(|| {}));
        *watch.external.lock().unwrap() = Some(ExternalOutputs {
            journal: Arc::downgrade(&old_journal), scopes: old_scopes,
        });
        let foreground_output = watched.join("foreground-output");
        watch.register_external_output(&foreground_output).unwrap();
        assert!(foreground_output.is_dir());
        fs::remove_dir(&foreground_output).unwrap();
        scheduler.password_update(false).unwrap();
        scheduler.journal.rebuild_log().unwrap();
        scheduler.journal.flush().unwrap();
        drop(held);
        write_roots(&scheduler.root_file, &[root]).unwrap();
        scheduler.reload().unwrap();
        assert!(!scheduler.journal.suspended());
        assert!(!held_output.exists(), "re-attached scheduler lost output cleanup intent");
        assert!(scheduler.pending.contains_key(&key(&source)));
        return;
    }
    run_isolated("semantic_reload_recovers_pending_after_output_unlock", CHILD);
}

#[test]
fn password_retry_keeps_existing_quiet_and_checks_failure_snapshot() {
    use std::time::Duration;
    const CHILD: &str = "SUNPACK_PASSWORD_RETRY_QUIET_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        let directory = base.join("password");
        let watched = directory.join("watched");
        fs::create_dir_all(&watched).unwrap();
        let source = watched.join("input.7z.001");
        fs::write(&source, b"old archive").unwrap();
        let id = watch_path_key(source.to_str().unwrap());
        let root_id = key(&watched);
        let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
        let settings = Arc::new(Config::default());
        let journal = Arc::new(journal::Journal::open(&directory.join("state"), 7).unwrap());
        let mut scheduler = Scheduler {
            candidate_diagnostics: CandidateDiagnostics::default(),
            admission_checkpoint: None,
            cwd: base.clone(), root_file: directory.join(ROOTS_FILE),
            roots: BTreeMap::from([(root_id.clone(), (Root { path: watched.clone(), output: None,
                recursive: true, deep: false, scanned: true }, scope))]),
            available_roots: HashSet::from([root_id.clone()]),
            user_password_signature: user_password_signature(&settings.user_passwords),
            settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
            catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
            options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
            deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
            passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
            root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
            parent_observers: HashMap::new(), config_observers: Vec::new(),
            pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
            active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
            tray: None, monitor: None, toast: None, cache_deadline: None,
            external: Arc::new(Mutex::new(None)), _lease: None,
        };
        let path = source.to_str().unwrap();
        let failed = watch_candidate_for_path(&source, None).unwrap().unwrap();
        scheduler.journal.commit(true, |_| {
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            operations.put_entry(Arc::new(observed_entry(&failed, "password", None)));
            Ok(operations)
        }).unwrap();
        fs::write(&source, b"archive still being downloaded").unwrap();
        scheduler.enqueue(&root_id, path.into(), CandidateAdmission::Observe).unwrap();
        let pending = scheduler.pending.get_mut(&id).unwrap();
        scheduler.due.remove(&(pending.due, id.clone()));
        pending.quiet.set_seconds(10.0);
        pending.due = Instant::now() + Duration::from_secs(10);
        scheduler.due.insert((pending.due, id.clone()), ());
        let before = Instant::now();
        scheduler.retry_password_failures(&scheduler.passwords.snapshot(), None).unwrap();
        assert!(scheduler.pending[&id].due >= before + Duration::from_secs(9));

        // A new pending also must not use the old password failure shortcut
        // when only its latest catalog observation matches the input.
        let pending = scheduler.pending.remove(&id).unwrap();
        scheduler.due.remove(&(pending.due, id.clone()));
        let before = Instant::now();
        scheduler.observe_candidate_with_quiet(&root_id, path.into(),
            CandidateAdmission::PasswordRetry, None, None, Some(pending.quiet)).unwrap();
        assert!(scheduler.pending[&id].due >= before + Duration::from_secs(9));

        // A stable, matching password failure with no pending remains immediate.
        let candidate = scheduler.pending[&id].candidate.clone();
        scheduler.journal.commit(true, |_| {
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            operations.put_entry(Arc::new(observed_entry(&candidate, "password", None)));
            Ok(operations)
        }).unwrap();
        let pending = scheduler.pending.remove(&id).unwrap();
        scheduler.due.remove(&(pending.due, id.clone()));
        scheduler.observe_candidate_with_quiet(&root_id, path.into(),
            CandidateAdmission::PasswordRetry, None, None, Some(pending.quiet)).unwrap();
        assert!(scheduler.pending[&id].due <= Instant::now());

        // A newly arrived volume retries its stable head. This must keep the
        // learned wait without recording a new content event for the head.
        let pending = scheduler.pending.remove(&id).unwrap();
        scheduler.due.remove(&(pending.due, id.clone()));
        drop(pending);
        let (_, scope) = &scheduler.roots[&root_id];
        scheduler.scan_options(false).unwrap()
            .catalog_update(&scheduler.catalog, scope, None).unwrap();
        scheduler.catalog.remember_observation(path, candidate.size, candidate.mtime,
            &candidate.observation.file_id, candidate.observation.change_usn, false);
        scheduler.catalog.retire_observation(path, Some(10.0), Some(2.0), 1.0, 0.0);
        assert_eq!(scheduler.catalog.observation(path).unwrap().quiet_seconds, 10.0);
        scheduler.journal.commit(true, |_| {
            let mut entry = observed_entry(&candidate, "suspended_missing_volume", None);
            entry.failure_payload.insert("blockers".into(), json!(["missing_volume"]));
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            operations.put_entry(Arc::new(entry));
            Ok(operations)
        }).unwrap();
        let tail = watched.join("input.7z.002");
        fs::write(&tail, b"new split volume").unwrap();
        let before = Instant::now();
        scheduler.observe_file_changes_blocking(
            &HashMap::from([(root_id.clone(), HashSet::from([tail.clone()]))]),
            &HashMap::from([(tail, CandidateEvent::Created)]),
            &HashSet::new(),
            &mut HashMap::new(),
        ).unwrap();
        assert!(scheduler.pending[&id].due >= before + Duration::from_secs(9),
            "quiet summary after volume arrival: {:?}", scheduler.pending[&id].quiet.summary());
        assert_eq!(scheduler.pending[&id].quiet.summary(), (10.0, Some(2.0), 1.0, 0.0));
        let pending = scheduler.pending.remove(&id).unwrap();
        scheduler.due.remove(&(pending.due, id.clone()));
        scheduler.observe_candidate_with_quiet(&root_id, path.into(),
            CandidateAdmission::CrashRecovery, None, None, Some(pending.quiet)).unwrap();
        assert!(scheduler.pending[&id].due <= Instant::now());
        return;
    }
    run_isolated("password_retry_keeps_existing_quiet_and_checks_failure_snapshot", CHILD);
}

#[path = "../../../examples/support/display_events.rs"]
mod display_events;

#[test]
fn native_event_provenance_survives_ordinary_and_checkpoint_admission() {
    const CHILD: &str = "SUNPACK_WATCH_EVENT_PROVENANCE_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        // This child owns its environment. Force the real missing-Broker
        // fallback regardless of the parent's installed test service.
        unsafe {
            let suffix = format!("MissingCursor_{}", std::process::id());
            std::env::set_var(sunpack_usn_core::SERVICE_NAME_ENV,
                format!("{}{suffix}", sunpack_usn_core::TEST_SERVICE_NAME_PREFIX));
            std::env::set_var(sunpack_usn_core::PIPE_NAME_ENV,
                format!("{}{suffix}", sunpack_usn_core::TEST_PIPE_NAME_PREFIX));
        }
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        let directory = base.join("events");
        let watched = directory.join("watched");
        fs::create_dir_all(&watched).unwrap();
        let root_id = key(&watched);
        let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
        let settings = Arc::new(Config::default());
        let journal = Arc::new(journal::Journal::open(&directory.join("state"), 7).unwrap());
        let mut scheduler = Scheduler {
            candidate_diagnostics: CandidateDiagnostics::default(),
            admission_checkpoint: None,
            cwd: base.clone(), root_file: directory.join(ROOTS_FILE),
            roots: BTreeMap::from([(root_id.clone(), (Root { path: watched.clone(), output: None,
                recursive: true, deep: false, scanned: true }, scope))]),
            available_roots: HashSet::from([root_id.clone()]),
            user_password_signature: user_password_signature(&settings.user_passwords),
            settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
            catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
            options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
            deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
            passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
            root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
            parent_observers: HashMap::new(), config_observers: Vec::new(),
            pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
            active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
            tray: None, monitor: None, toast: None, cache_deadline: None,
            external: Arc::new(Mutex::new(None)), _lease: None,
        };

        let mut expected = Vec::new();
        for (name, event) in [("created.zip", CandidateEvent::Created), ("modified.zip", CandidateEvent::Modified)] {
            let path = watched.join(name);
            fs::write(&path, b"archive").unwrap();
            let kind = event.kind();
            let mut signals = Signals::default();
            signals.changes.root_changed(&root_id, Some(vec![path.clone()]));
            if kind == "modified" { signals.changes.modified_paths.insert(path.clone()); }
            signals.changes.candidate_events.insert(path.clone(), event);
            let id = key(&path);
            let activity = scheduler.hub.activities.bind(id.clone(), quiet::Activity::default);
            let observation = activity.capture(&path, &scheduler.hub.claims, &id).unwrap().unwrap();
            signals.changes.observations.insert(path.clone(), (activity, observation));
            // A second identity lookup would fail. The event already has the
            // matching observation, and readiness still rechecks on admission.
            *crate::postprocess::WATCH_OBSERVATION_FAILURE.lock().unwrap() = Some(path.clone());
            let result = scheduler.observe_root_changes(&mut signals.changes);
            *crate::postprocess::WATCH_OBSERVATION_FAILURE.lock().unwrap() = None;
            result.unwrap();
            assert!(scheduler.pending.contains_key(&key(&path)));
            expected.push((path, "candidate_active", kind, String::new()));
        }
        for fail in [false, true] {
            let old = watched.join(if fail { "failed-old.zip" } else { "old.zip" });
            let new = watched.join(if fail { "failed-new.zip" } else { "new.zip" });
            fs::write(&old, b"archive").unwrap();
            fs::rename(&old, &new).unwrap();
            // Native rename supplies both old (now missing) and new paths,
            // selecting the actual checkpoint branch rather than ordinary enqueue.
            let mut signals = Signals::default();
            signals.changes.root_changed(&root_id, Some(vec![old.clone(), new.clone()]));
            signals.changes.candidate_events.insert(new.clone(), CandidateEvent::Moved(old.clone()));
            if fail { *crate::postprocess::WATCH_OBSERVATION_FAILURE.lock().unwrap() = Some(new.clone()); }
            scheduler.observe_root_changes(&mut signals.changes).unwrap();
            *crate::postprocess::WATCH_OBSERVATION_FAILURE.lock().unwrap() = None;
            assert_eq!(scheduler.pending.contains_key(&key(&new)), !fail);
            expected.push((new, if fail { "candidate_ignored" } else { "candidate_active" },
                "moved", old.to_string_lossy().into_owned()));
        }
        // A catalog/USN-only discovery keeps its business origin, not a native event.
        let recovery = watched.join("recovery.zip");
        fs::write(&recovery, b"archive").unwrap();
        // A known file departure updates only that catalog row, even with no
        // USN Broker. An unrelated arrival belongs to a subsequent checkpoint.
        let departed = &expected[0].0;
        assert!(scheduler.catalog.path_is_directory(
            &scheduler.roots[&root_id].1, departed.to_str().unwrap()) == Some(false));
        fs::remove_file(departed).unwrap();
        let mut signals = Signals::default();
        signals.changes.root_changed(&root_id, Some(vec![departed.clone()]));
        scheduler.observe_root_changes(&mut signals.changes).unwrap();
        assert!(!scheduler.pending.contains_key(&key(departed)));
        assert!(!scheduler.pending.contains_key(&key(&recovery)));
        scheduler.checkpoint(&HashMap::new(), true, false).unwrap();
        expected.push((recovery.clone(), "candidate_active", "usn_recovery", String::new()));
        scheduler.journal.flush().unwrap();
        let records = display_events::read(&directory.join("state/events.json")).unwrap();
        let history = records["history"].as_array().unwrap();
        for (path, action, kind, source) in expected {
            let record = history.iter().find(|record| record["event"] == action
                && record["path"].as_str().is_some_and(|value| Path::new(value) == path)).unwrap();
            assert_eq!(record["event_type"], kind);
            assert_eq!(record["src_path"], source);
            if action == "candidate_ignored" {
                assert_eq!(record["reason"], "observation_error");
                assert!(record["error"].as_str().unwrap().starts_with("PermissionError:"));
            }
        }

        // A readable initial inventory is complete independently of a USN
        // cursor. Its pending intent must already be durable at publication.
        let root = &mut scheduler.roots.get_mut(&root_id).unwrap().0;
        root.scanned = false;
        write_roots(&scheduler.root_file, std::slice::from_ref(root)).unwrap();
        assert!(filesystem::watch_volume_cursor(&watched.to_string_lossy()).is_err());
        scheduler.checkpoint(&HashMap::new(), true, false).unwrap();
        assert!(read_roots(&scheduler.root_file).unwrap()[0].scanned);
        assert!(scheduler.journal.state().pending(recovery.to_str().unwrap()).is_some());
        scheduler.journal.flush().unwrap();
        let records = display_events::read(&directory.join("state/events.json")).unwrap();
        assert!(records["history"].as_array().unwrap().iter().any(|record| {
            record["event"] == "initial_scan_completed" && record["roots"] == json!([watched])
        }));
        return;
    }
    run_isolated("native_event_provenance_survives_ordinary_and_checkpoint_admission", CHILD);
}

#[test]
fn scheduler_fault_keeps_reload_control_and_reopens_the_store() {
    const CHILD: &str = "SUNPACK_SCHEDULER_FAULT_SERVICE_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), br#"{"watch":{"clipboard_monitor_enabled":false,"toast_enabled":false}}"#).unwrap();
        let watched = base.join("watched");
        fs::create_dir_all(&watched).unwrap();
        write_roots(&roots_path(&base).unwrap(), &[Root { path: watched,
            output: None, recursive: true, deep: false, scanned: true }]).unwrap();
        let hub = Arc::new(Hub::new());
        let mut scheduler = Scheduler::open(base.clone(), Arc::new(Engine::new(base.join("unused-worker.exe"))),
            Arc::clone(&hub), true, false, Arc::new(Mutex::new(None)), config::load_snapshot(&base).unwrap()).unwrap();
        // This test drives explicit reloads deterministically; do not race the
        // native filesystem notification against the corresponding waiter.
        scheduler.config_observers.clear();
        let original = Arc::downgrade(&scheduler.journal);
        let broker_lease = Arc::downgrade(scheduler._lease.as_ref().unwrap());
        scheduler.journal.fail_for_test();
        let last_error = Arc::new(Mutex::new(None));
        let error = Arc::clone(&last_error);
        let (once, once_wait) = command_reply();
        assert!(hub.queue_once(once));
        let thread = std::thread::spawn(move || scheduler.run_service(false, &error));
        assert!(block_on(once_wait.wait()).is_err());
        assert!(!hub.stopped.load(Ordering::Acquire));
        assert!(original.upgrade().is_none(), "faulted Journal must be released before reload");
        assert!(broker_lease.upgrade().is_some(), "the repair shell keeps the original Broker lease");
        assert!(last_error.lock().unwrap().is_some());
        let (rebuild, rebuild_wait) = command_reply();
        hub.update(|signals| signals.rebuild.push(rebuild));
        assert!(block_on(rebuild_wait.wait()).unwrap(), "the service log outlives its faulted WAL");
        // Service-only configuration still applies while the data scheduler is
        // unavailable, without attempting to reopen its failed state stream.
        fs::write(base.join("sunpack_advanced_config.json"), br#"{"runtime":{"process_mode":"background"},"watch":{"clipboard_monitor_enabled":false,"toast_enabled":false,"tray_enabled":false}}"#).unwrap();
        let (shell_reload, shell_wait) = command_reply();
        hub.queue_reload(Some(shell_reload));
        assert!(block_on(shell_wait.wait()).unwrap());
        assert!(last_error.lock().unwrap().is_some(), "shell-only reload must not rebuild scheduler");
        assert_eq!(crate::core::process::effective_mode(), crate::core::config::ProcessMode::Background);
        let (reload, reload_wait) = command_reply();
        hub.queue_reload(Some(reload));
        assert!(block_on(reload_wait.wait()).unwrap());
        assert!(broker_lease.upgrade().is_some(), "reopening reuses the service's Broker lease");
        hub.stop();
        assert_eq!(thread.join().unwrap().unwrap(), 0);
        assert!(broker_lease.upgrade().is_none(), "service shutdown releases the Broker lease");
        return;
    }
    run_isolated("scheduler_fault_keeps_reload_control_and_reopens_the_store", CHILD);
}

#[test]
fn process_mode_only_change_is_shell_policy_not_scheduler_policy() {
    let previous = Config::default();
    let mut next = previous.clone();
    next.runtime.process_mode = if previous.runtime.process_mode == crate::core::config::ProcessMode::Normal {
        crate::core::config::ProcessMode::Background
    } else { crate::core::config::ProcessMode::Normal };
    assert!(!scheduler_configuration_changed(&previous, &next));
    assert!(previous != next, "shell changes must not be reported as no-op");
}

#[test]
fn a_retired_toast_activation_is_successful_and_leaves_current_request_running() {
    const CHILD: &str = "SUNPACK_WATCH_RETIRED_TOAST_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        let mut scheduler = Scheduler::open(base.clone(), Arc::new(Engine::new(base.join("unused-worker.exe"))),
            Arc::new(Hub::new()), false, false, Arc::new(Mutex::new(None)), config::load_snapshot(&base).unwrap()).unwrap();
        let retired = "80000000000000000000000000000000";
        assert!(!scheduler.cancel_display_batch(retired).unwrap());
        let toast = super::super::toast::Toast::start(
            &base, Arc::clone(&scheduler.engine), base.join("state/toast_host_events.jsonl"),
            7, |_, _| {},
        ).unwrap();
        let current = toast.register(Arc::from("00000000000000000000000000000001"), crate::core::i18n::Language::En);
        scheduler.toast = Some(toast);
        assert!(scheduler.cancel_display_batch(retired).unwrap());
        // The active request can still finish through its original activity.
        assert!(current.prepare_finish(&Ok(Outcome::default()), false, false, |_| None).is_some());
        return;
    }
    run_isolated("a_retired_toast_activation_is_successful_and_leaves_current_request_running", CHILD);
}

#[test]
fn coalesced_watch_completion_keeps_the_leaders_blocker() {
    const CHILD: &str = "SUNPACK_WATCH_COALESCED_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let watched = base.join("watched");
        fs::create_dir_all(&watched).unwrap();
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        let mut scheduler = Scheduler::open(
            base.clone(), Arc::new(Engine::new(base.join("unused-worker.exe"))),
            Arc::new(Hub::new()), false, false, Arc::new(Mutex::new(None)),
            config::load_snapshot(&base).unwrap(),
        ).unwrap();
        scheduler.journal.resume().unwrap();
        let source = watched.join("family.7z.002");
        fs::write(&source, b"follower generation").unwrap();
        let candidate = watch_candidate_for_path(&source, None).unwrap().unwrap();
        let id = watch_path_key(&candidate.path);
        let blocker = Arc::new(observed_entry(&candidate, "failed_password", None));
        scheduler.journal.commit(true, |state| {
            let (mut operations, _) = state.pending_operations(
                [(PendingObservation(candidate.path.clone(), candidate.size as i64,
                    candidate.mtime, candidate.observation.file_id.clone(),
                    candidate.observation.change_usn), String::new(), None)],
                false, "", false, true, None,
            )?;
            operations.put_entry(Arc::clone(&blocker));
            Ok(operations)
        }).unwrap();
        scheduler.active_paths.insert(id.clone(), Arc::from("follower"));
        let release = Arc::new(super::super::cli::reporting::Reply::default());
        let wait = Arc::clone(&release);
        let cancel = Cancellation::new();
        let request = scheduler.engine.spawn_control(Origin::Watch, &cancel, async move {
            wait.wait().await.unwrap();
            let mut outcome = Outcome::default();
            outcome.coalesced_from = Some(1);
            Completed {
                cancelled: false,
                result: Ok(outcome),
                promoted: HashMap::new(), outputs: BTreeMap::new(),
            }
        }).unwrap();
        let claimed = Arc::new(Mutex::new(ClaimedSources { coalesced: true, ..Default::default() }));
        scheduler.active.insert("follower".into(), Active {
            deep: false, root: key(&watched), recovery: None, password_scope: watched.clone(),
            passwords: scheduler.passwords.snapshot(), inputs: HashMap::from([(id.clone(), candidate.clone())]),
            quiet: HashMap::new(), dirty: HashSet::new(), claimed,
            groups: Arc::default(), toast: None, cancel: cancel.clone(), request,
        });
        // The leader has already released its physical claim but the follower
        // still awaits request completion. Stop must preserve the blocker.
        let stopped = scheduler.cancel_batch("follower");
        release.complete(Ok(()));
        assert!(stopped && cancel.cancelled());
        assert!(Arc::ptr_eq(&blocker, &scheduler.journal.state().entry(&candidate.path).unwrap()));
        scheduler.complete("follower").unwrap();
        assert!(!scheduler.active_paths.contains_key(&id));
        assert!(scheduler.journal.state().pending(&candidate.path).is_none());
        assert!(Arc::ptr_eq(&blocker, &scheduler.journal.state().entry(&candidate.path).unwrap()));
        return;
    }
    run_isolated("coalesced_watch_completion_keeps_the_leaders_blocker", CHILD);
}
