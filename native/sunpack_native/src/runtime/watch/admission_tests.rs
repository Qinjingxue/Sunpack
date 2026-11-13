//! Real admission methods with a checkpoint-local barrier, not a simulated queue.
use super::*;
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
                parent_observers: HashMap::new(), config_observers: Vec::new(), config_sources: Default::default(),
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
