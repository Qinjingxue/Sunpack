//! Completion counters must survive the real event writer, per physical root.
use super::*;
use super::tests::completion_archive;
use std::fs;

#[test]
fn done_counts_survive_disk_per_root_without_counting_volume_aliases_twice() {
    const CHILD: &str = "SUNPACK_WATCH_DONE_COUNTS_TEST";
    let Some(base) = std::env::var_os(CHILD) else {
        // Isolate process-wide writable-data lookup in a copied child EXE.
        let marker = crate::test_support::temp_file("done_counts", b"");
        let base = marker.with_extension("workspace");
        fs::create_dir_all(&base).unwrap();
        let exe = base.join("sunpack-watch-test.exe");
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let test = concat!("runtime::watch::completion_tests::",
            "done_counts_survive_disk_per_root_without_counting_volume_aliases_twice");
        let output = std::process::Command::new(exe).args(["--exact", test, "--nocapture"])
            .env(CHILD, &base).output().unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        fs::remove_dir_all(base).unwrap();
        fs::remove_file(marker).unwrap();
        return;
    };
    let base = PathBuf::from(base);
    fs::create_dir_all(base.join("native")).unwrap();
    fs::write(base.join("native/Cargo.toml"), b"").unwrap();
    fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
    let directory = base.join("state");
    let settings = Arc::new(Config::default());
    let journal = Arc::new(journal::Journal::open(&directory, 7).unwrap());
    // Completion does not need a broker or an SCM service. Keep the real
    // scheduler completion/WAL/log path without installing a system service.
    let mut scheduler = Scheduler {
        candidate_diagnostics: CandidateDiagnostics::default(), admission_checkpoint: None,
        cwd: base.clone(), root_file: base.join(ROOTS_FILE),
        roots: BTreeMap::new(), available_roots: HashSet::new(),
        user_password_signature: user_password_signature(&settings.user_passwords),
        settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
        catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
        options: None,
        deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
        passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
        root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
        parent_observers: HashMap::new(), dependency_observers: HashMap::new(), config_observers: Vec::new(),
        volume_checks: HashMap::new(),
        pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
        active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
        tray: None, monitor: None, toast: None, cache_deadline: None,
        external: Arc::default(), _lease: None,
    };
    let head_path = base.join("outer.001");
    let tail_path = base.join("outer.002");
    let other_path = base.join("other.zip");
    let head = head_path.as_path();
    let tail = tail_path.as_path();
    let other = other_path.as_path();
    for path in [head, tail, other] { fs::write(path, b"archive").unwrap(); }
    let group = Arc::new(SourceGroup {
        path: head.into(), name: "outer".into(), multipart: true,
        members: vec![head.to_string_lossy().into(), tail.to_string_lossy().into()],
    });
    let groups = HashMap::from([(key(head), Arc::clone(&group)), (key(tail), group)]);
    let outputs = BTreeMap::from([(key(&base.join("outer")), tail.to_string_lossy().into_owned())]);
    let mut full = completion_archive(head.to_str().unwrap(), 1, None);
    full.source_paths.push(tail.into());
    let mut partial = completion_archive(head.to_str().unwrap(), 1, Some(FailureKind::Damaged));
    partial.offset = 100;
    partial.partial = true;
    partial.source_paths.push(tail.into());
    let mut outcome = Outcome::default();
    outcome.archives = vec![full, partial,
        completion_archive(base.join("outer/inner.zip").to_str().unwrap(), 2, None),
        completion_archive(other.to_str().unwrap(), 1, None)];
    let context = CompletionContext {
            max_depth: usize::MAX,
        deep: true, root: key(&base), recovery: None, password_scope: base.clone(),
        passwords: scheduler.passwords.snapshot(),
        inputs: [head, tail, other].into_iter().map(|path|
            watch_candidate_for_path(path, None).unwrap().unwrap()).collect(),
        quiet: HashMap::new(), dirty: HashSet::new(), claimed: Arc::default(),
        groups, toast: None, task: None,
    };
    scheduler.apply_completion("one-batch", context, Completed {
        cancelled: false, result: Ok(outcome),  outputs,
    }).unwrap();
    scheduler.journal.flush().unwrap();
    // Read the actual compressed disk records, not the in-memory submitted JSON.
    let manifest: crate::io::display_store::Manifest = serde_json::from_slice(
        &fs::read(directory.join("events.json")).unwrap()).unwrap();
    let mut recorded = HashMap::new();
    unsafe extern "C" {
        fn LZ4_decompress_safe(src: *const u8, dst: *mut u8, size: i32, capacity: i32) -> i32;
    }
    for run in &manifest.runs {
        let store = directory.join("events.json.store");
        let data = fs::read(store.join(format!("{}.data", run.name))).unwrap();
        let index = fs::read(store.join(format!("{}.index", run.name))).unwrap();
        for row in index.chunks_exact(crate::io::display_store::ENTRY_BYTES)
            .skip(run.head as usize).take((run.count - run.head) as usize)
        {
            let offset = u64::from_le_bytes(row[8..16].try_into().unwrap()) as usize;
            let packed = u32::from_le_bytes(row[16..20].try_into().unwrap()) as usize;
            let size = u32::from_le_bytes(row[20..24].try_into().unwrap()) as usize;
            assert!(packed > 0 && size > 0, "small completion record uses a normal block");
            let mut raw = vec![0; size];
            let block = &data[offset..offset + packed];
            assert_eq!(unsafe { LZ4_decompress_safe(block.as_ptr(), raw.as_mut_ptr(), packed as i32, size as i32) }, size as i32);
            let value: Value = rmp_serde::from_slice(&raw).unwrap();
            if value["event"] != "done" { continue; }
            recorded.insert(watch_path_key(value["path"].as_str().unwrap()), value);
        }
    }
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[&key(head)]["success_count"], 2);
    assert_eq!(recorded[&key(head)]["partial_success_count"], 1);
    assert_eq!(recorded[&key(other)]["success_count"], 1);
    assert_eq!(recorded[&key(other)]["partial_success_count"], 0);
    drop(scheduler);
}
