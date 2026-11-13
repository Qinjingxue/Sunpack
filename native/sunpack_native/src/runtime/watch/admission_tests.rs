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
fn checkpoint_admission_reuses_only_unchanged_unclaimed_readiness() {
    const CHILD: &str = "SUNPACK_ADMISSION_CHECKPOINT_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        for case in ["stable", "content", "claim", "error", "stop"] {
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
                external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
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
            let held = Arc::new(Mutex::new(None));
            let held_in_check = Arc::clone(&held);
            let check_source = source.clone();
            let check_id = id.clone();
            scheduler.admission_checkpoint = Some(Box::new(move |scheduler| {
                assert!(scheduler.pending[&check_id].admission_ready, "first real probe did not prepare {case}");
                assert!(scheduler.journal.state().pending(check_source.to_str().unwrap()).is_some(),
                    "checkpoint must publish durable intent before reusing readiness");
                if case == "content" {
                    fs::write(&check_source, b"new and larger archive generation written after checkpoint").unwrap();
                    scheduler.enqueue(&root_id, check_source.to_string_lossy().into_owned(), CandidateAdmission::Observe).unwrap();
                    assert!(!scheduler.pending[&check_id].admission_ready);
                }
                if case == "claim" {
                    scheduler.hub.claims.lock().unwrap().insert(check_id, Arc::from("foreground"));
                }
                if case == "stop" { scheduler.hub.stopped.store(true, Ordering::Release); }
                // A live writer conflicts with watch_file_is_ready's read-only
                // sharing, while permitting catalog readers and metadata probes.
                // Stable admission must reuse its real first successful probe.
                *held_in_check.lock().unwrap() = Some(fs::OpenOptions::new().write(true)
                    .share_mode(7).open(&check_source).unwrap());
                assert!(!filesystem::watch_file_is_ready(check_source.to_str().unwrap()).unwrap(),
                    "writer must block a fresh readiness probe");
                if case == "error" { return Err(io::Error::other("checkpoint publication failed")); }
                if case == "stable" {
                    // Admission, not extraction, is under test. Retire the root
                    // after publication so start_batch cannot launch a worker.
                    scheduler.roots.clear();
                }
                Ok(())
            }));
            let result = scheduler.dispatch_ready();
            assert_eq!(result.is_err(), case == "error", "{case}: {result:?}");
            assert!(scheduler.admission_checkpoint.is_none(), "checkpoint barrier not reached: {case}");
            if case == "stable" {
                assert!(scheduler.pending.is_empty(), "stable candidate was re-probed");
                assert!(scheduler.due.is_empty());
            } else {
                assert!(!scheduler.pending[&id].admission_ready, "readiness leaked past {case}");
                assert!(scheduler.active.is_empty());
                if case == "content" {
                    assert!(scheduler.pending[&id].candidate.size > b"initial archive bytes".len() as u64);
                }
                scheduler.hub.claims.lock().unwrap().clear();
                scheduler.hub.stopped.store(false, Ordering::Release);
                let now = Instant::now();
                let pending = scheduler.pending.get_mut(&id).unwrap();
                scheduler.due.remove(&(pending.due, id.clone()));
                pending.due = now;
                scheduler.due.insert((now, id.clone()), ());
                assert!(scheduler.prepare_ready_blocking(now, 1).unwrap().is_empty(),
                    "parked {case} reused readiness despite a locked file");
                held.lock().unwrap().take();
                assert_eq!(scheduler.prepare_ready_blocking(Instant::now(), 1).unwrap().len(), 1,
                    "parked {case} was lost after becoming readable");
            }
            held.lock().unwrap().take();
        }
        return;
    }
    run_isolated("checkpoint_admission_reuses_only_unchanged_unclaimed_readiness", CHILD);
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
fn recovery_scans_surviving_outputs_while_requeueing_missing_output_owner() {
    const CHILD: &str = "SUNPACK_SURVIVING_OUTPUT_RECOVERY_TEST";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        for source_present in [true, false] {
            let directory = base.join(if source_present { "source" } else { "missing" });
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
                external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
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
            if !source_present { fs::remove_file(&source).unwrap(); }
            scheduler.recover_pending(None).unwrap();
            assert!(scheduler.journal.state().pending(owner).is_some(), "owner intent must survive");
            if source_present {
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
        fs::write(&configuration, b"{}").unwrap();
        let directory = base.join("recovery");
        let watched = directory.join("watched");
        fs::create_dir_all(&watched).unwrap();
        let source = watched.join("owner.zip");
        fs::write(&source, b"outer archive").unwrap();
            let root_id = key(&watched);
            let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
            let settings = Arc::new(config::load_snapshot(&base).unwrap().config);
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
                external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
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
            output.to_string_lossy().into_owned(), output.to_string_lossy().into_owned(),
            None, None)?.unwrap())).unwrap();
        let member = output.join("locked.txt");
        fs::write(&member, b"unfinished extraction").unwrap();
        let lock = fs::OpenOptions::new().read(true).share_mode(0).open(&member).unwrap();
        scheduler.recover_pending(None).unwrap();
        assert!(scheduler.pending.is_empty());
        assert!(scheduler.journal.state().pending(owner).is_some());
        drop(lock);
        fs::write(&configuration, br#"{"cli":{"language":"zh"}}"#).unwrap();
        assert!(scheduler.reload().unwrap());
        assert!(!output.exists(), "semantic restart must retry interrupted cleanup");
        assert!(scheduler.pending.contains_key(&key(&source)), "unchanged durable work must be admitted again");
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
        let source = watched.join("input.zip");
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
            external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
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
        pending.quiet.seconds = 10.0;
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

        // A volume-change retry is forced, but is not crash recovery. It must
        // still respect the learned quiet window even with no current pending.
        let pending = scheduler.pending.remove(&id).unwrap();
        scheduler.due.remove(&(pending.due, id.clone()));
        let before = Instant::now();
        scheduler.observe_candidate_with_quiet(&root_id, path.into(),
            CandidateAdmission::Retry, None, None, Some(pending.quiet)).unwrap();
        assert!(scheduler.pending[&id].due >= before + Duration::from_secs(9));
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
            external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
        };

        let mut expected = Vec::new();
        for (name, event) in [("created.zip", CandidateEvent::Created), ("modified.zip", CandidateEvent::Modified)] {
            let path = watched.join(name);
            fs::write(&path, b"archive").unwrap();
            let kind = event.kind();
            let mut signals = Signals::default();
            signals.root_changed(&root_id, Some(vec![path.clone()]));
            if kind == "modified" { signals.modified_paths.insert(path.clone()); }
            signals.candidate_events.insert(path.clone(), event);
            scheduler.observe_root_changes(&mut signals.changed_roots, &signals.topology_roots,
                &signals.modified_paths, &signals.candidate_events, false).unwrap();
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
            signals.root_changed(&root_id, Some(vec![old.clone(), new.clone()]));
            signals.candidate_events.insert(new.clone(), CandidateEvent::Moved(old.clone()));
            assert!(Signals::prepare_root_changes(&mut signals.changed_roots,
                &signals.topology_roots, &signals.modified_paths, false));
            if fail { *crate::postprocess::WATCH_OBSERVATION_FAILURE.lock().unwrap() = Some(new.clone()); }
            scheduler.observe_root_changes(&mut signals.changed_roots, &signals.topology_roots,
                &signals.modified_paths, &signals.candidate_events, false).unwrap();
            *crate::postprocess::WATCH_OBSERVATION_FAILURE.lock().unwrap() = None;
            assert_eq!(scheduler.pending.contains_key(&key(&new)), !fail);
            expected.push((new, if fail { "candidate_ignored" } else { "candidate_active" },
                "moved", old.to_string_lossy().into_owned()));
        }
        // A catalog/USN-only discovery keeps its business origin, not a native event.
        let recovery = watched.join("recovery.zip");
        fs::write(&recovery, b"archive").unwrap();
        scheduler.checkpoint(&HashMap::new(), true, false).unwrap();
        expected.push((recovery, "candidate_active", "usn_recovery", String::new()));
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
        return;
    }
    run_isolated("native_event_provenance_survives_ordinary_and_checkpoint_admission", CHILD);
}
