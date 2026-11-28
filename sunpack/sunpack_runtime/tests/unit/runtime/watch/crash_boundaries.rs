use super::*;
use crate::io::reader::capture_file_generation;
use crate::watch_store::{NativeWatchOperations, PendingObservation};
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(windows)]
#[test]
fn recycle_replay_preserves_replacement_and_ordinary_recycle_named_directory() {
    let original = crate::test_support::temp_file("recycle_replay_identity", b"archive");
    let base = original.with_extension("tree");
    let apparent_bin = base.join("$Recycle.Bin").join(crate::runtime::current_user_sid().unwrap());
    fs::create_dir_all(&apparent_bin).unwrap();
    let source = CleanupSource { path: original.clone(), generation: capture_file_generation(&original).unwrap(), recycle: true };
    fs::rename(&original, apparent_bin.join("$Rsample.bin")).unwrap();
    fs::write(&original, b"replacement").unwrap();
    let info = apparent_bin.join("$Isample.bin");
    fs::write(&info, [0; 88]).unwrap();
    assert!(!crate::pipeline::cleanup::clean_source(&source, true).unwrap());
    assert_eq!(fs::read(&info).unwrap(), [0; 88]);
    assert_eq!(fs::read(&original).unwrap(), b"replacement");
    fs::remove_dir_all(base).unwrap();
    fs::remove_file(original).unwrap();
}

// A normal Journal drop can finish persistence and conceal a crash ordering
// defect. This owner is killed with real WAL, directory identities alive. No production fault hook or timing race is involved.
#[test]
fn hard_death_recovers_flatten_publication_and_rebase_boundaries() {
    const CHILD: &str = "SUNPACK_FLATTEN_CRASH_CHILD";
    const PHASE: &str = "SUNPACK_FLATTEN_CRASH_PHASE";
    const READY: &str = "sunpack-flatten-crash-ready";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let owner = base.join("carrier.bin");
        let root = base.join("output");
        let destination = base.join("inner(1)");
        let work = base.join("work");
        let leaf = root.join("wrapper/inner");
        let nested = leaf.join("nested.zip");
        let settled_child = leaf.join("settled.zip");
        let nested_output = leaf.join("nested");
        fs::create_dir_all(&nested_output).unwrap();
        fs::write(&owner, b"carrier input").unwrap();
        fs::write(&nested, b"nested archive").unwrap();
        fs::write(&settled_child, b"completed child archive").unwrap();
        fs::write(nested_output.join("payload"), b"committed payload").unwrap();
        let payload_identity = output_identity(nested_output.to_str().unwrap()).unwrap();
        fs::write(base.join("identity"), payload_identity).unwrap();
        let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
        let owner_text = owner.to_str().unwrap();
        journal.commit(true, |state| {
            Ok(state.pending_operations(
                [(PendingObservation(owner_text.into(), 13, 1.0, String::new(), 0),
                    String::new(), None)], false, "", false, None,
            ))
        }).unwrap();
        journal.commit(true, |state| {
            let mut operations = NativeWatchOperations::empty();
            let wrapper = leaf.parent().unwrap();
            let segment = base.join("segment.bin");
            for (task, output) in [(owner.as_path(), root.as_path()),
                (segment.as_path(), wrapper), (nested.as_path(), nested_output.as_path())] {
                operations.extend(state.output_operation(owner_text, task.to_string_lossy().into_owned(),
                    output.to_string_lossy().into_owned(), None, false)?.unwrap());
            }
            store_source_cleanup(&mut operations, source_cleanup_id("crashed", 2), owner_text,
                (nested_output.to_str().unwrap(), &fs::read_to_string(base.join("identity"))?),
                None, &[CleanupSource { recycle: false, path: settled_child.clone(), generation: capture_file_generation(&settled_child)? }]);
            Ok(operations)
        }).unwrap();
        let deletes = [CleanupSource { recycle: false, path: owner.clone(), generation: capture_file_generation(&owner).unwrap() }];
        prepare_flatten(&journal, owner_text, &root, &work, &leaf, &destination, None,
            Some(("crashed", Some(CleanupReceipt { id: 1, sources: &deletes })))).unwrap();
        let phase = std::env::var(PHASE).unwrap();
        if phase != "prepared" {
            crate::io::atomic_file::rename_no_replace(&root, &work).unwrap();
        }
        if matches!(phase.as_str(), "published" | "rebased") {
            crate::io::atomic_file::rename_no_replace(&work.join("wrapper/inner"), &destination).unwrap();
        }
        if phase == "rebased" {
            // The wrappers are still present, so the durable intent remains
            // with outputs_rebased=true until the recovery cleanup completes.
            finish_flatten(&journal, root.to_str().unwrap()).unwrap();
            let record = journal.state().runtime_record(&format!("flatten|{}", key(&root))).unwrap();
            assert_eq!(record["outputs_rebased"], true);
        }
        println!("{READY}");
        io::stdout().flush().unwrap();
        let mut byte = [0];
        io::stdin().read_exact(&mut byte).unwrap();
        panic!("parent must terminate owner without unwinding");
    }

    for phase in ["prepared", "root_moved", "published", "rebased"] {
        let marker = crate::test_support::temp_file("flatten_hard_death", b"");
        let base = marker.with_extension("case");
        fs::create_dir(&base).unwrap();
        let test_name = format!("{}::hard_death_recovers_flatten_publication_and_rebase_boundaries",
            module_path!().split_once("::").unwrap().1);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD, &base).env(PHASE, phase)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, ready) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                if line.unwrap().contains(READY) { let _ = send.send(()); return; }
            }
        });
        let reached = ready.recv_timeout(Duration::from_secs(30));
        let killed = child.kill();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        reached.expect("flatten owner did not reach the requested durable boundary");
        killed.unwrap();
        assert!(!status.success());
        let owner = base.join("carrier.bin");
        let root = base.join("output");
        let destination = base.join("inner(1)");
        let work = base.join("work");
        let leaf = root.join("wrapper/inner");
        for reopen in 0..2 {
            let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
            recover_flattens(&journal, |_| true).unwrap();
            recover_source_cleanup(&journal, &Engine::new(base.join("unused-worker.exe")),
                std::iter::once(base.as_path()), |_, _| true).unwrap();
            assert!(!owner.exists(), "{phase}/{reopen}: committed carrier was not cleaned up");
            assert!(!leaf.join("settled.zip").exists() && !destination.join("settled.zip").exists(),
                "{phase}/{reopen}: pending child cleanup did not follow its output");
            assert_eq!(fs::read(leaf.join("nested.zip")).or_else(|_| fs::read(destination.join("nested.zip"))).unwrap(),
                b"nested archive", "the pending child was not an authorized cleanup member");
            assert_eq!(fs::read(destination.join("nested/payload")).unwrap(), b"committed payload");
            assert_eq!(output_identity(destination.join("nested").to_str().unwrap()).unwrap(),
                fs::read_to_string(base.join("identity")).unwrap());
            assert!(!work.exists(), "{phase}/{reopen}");
            assert!(journal.state().runtime_keys("flatten|").is_empty());
            let pending = journal.state().pending(owner.to_str().unwrap()).unwrap();
            assert!(recovery_output_matches(&pending, destination.to_str().unwrap()));
            assert!(pending.active_outputs.iter().any(|(task, output)|
                Path::new(task) == base.join("segment.bin") && Path::new(output) == destination));
            assert!(pending.active_outputs.iter().any(|(task, output)|
                Path::new(task) == destination.join("nested.zip") && Path::new(output) == destination.join("nested")));
            assert!(!journal.state().owns_path(root.to_str().unwrap()));
            assert!(!journal.state().owns_path(work.to_str().unwrap()));
        }
        fs::remove_dir_all(&base).unwrap();
        fs::remove_file(marker).unwrap();
    }
}

#[test]
fn hard_death_replays_delete_receipt_without_reissuing_wal_or_deleting_replacements() {
    const CHILD: &str = "SUNPACK_DELETE_CRASH_CHILD";
    const CASE: &str = "SUNPACK_DELETE_CRASH_CASE";
    const READY: &str = "sunpack-delete-crash-ready";
    let id = source_cleanup_id("crashed", 1);
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let source = base.join("archive.zip");
        let output = base.join("output");
        let path = source.to_str().unwrap();
        let target = output.to_str().unwrap();
        fs::write(&source, b"archive").unwrap();
        let deletes = [CleanupSource { recycle: false, path: source.clone(), generation: capture_file_generation(&source).unwrap() }];
        let journal = Arc::new(journal::Journal::open(&base.join("state"), 7).unwrap());
        journal.commit(true, |state| Ok(state.pending_operations(
            [(PendingObservation(path.into(), 7, 1.0, String::new(), 0), String::new(), None)],
            false, "", false, None,
        ))).unwrap();
        let catalog = Arc::new(NativeWatchCatalog::new(journal.state(), None));
        let observer = WatchObserver {
            deep: false, dedup_generation: None,
            dedup: Arc::new(Mutex::new(dedup::Index::open(&base.join("state"),
                config::WatchDeduplication::None, config::WatchDeduplicationScope::Root, Default::default()).unwrap())),
            dedup_scope: NativeDiscoveryScope::new(base.to_string_lossy().into_owned(), None, Vec::new()),
            catalog, journal: Arc::clone(&journal), owners: HashMap::from([(key(&source), path.into())]),
            outputs: Mutex::new(ObservedOutputs::from(BTreeMap::new())),
            batch: Arc::from("crashed"), toast: None, hub: Arc::new(Hub::new()),
            groups: Arc::default(), claimed: Arc::default(),
        };
        let mut archive = super::tests::completion_archive(path, 1, None);
        observer.register_output(&archive, &output).unwrap();
        fs::write(output.join("payload"), b"delivered").unwrap();
        fs::write(base.join("output_identity"), output_identity(target).unwrap()).unwrap();
        archive.output = Some(output);
        let before = journal.frontier_seq_for_test();
        observer.after_output(&archive, Some(CleanupReceipt { id: 1, sources: &deletes })).unwrap();
        assert_eq!(journal.frontier_seq_for_test(), before + 1);
        assert!(journal.state().runtime_record(&id).is_some());
        if std::env::var(CASE).unwrap() == "after_delete" {
            assert!(crate::pipeline::cleanup::clean_source(&deletes[0], true).unwrap());
            observer.source_cleanup_done(1);
            assert!(journal.state().runtime_record(&id).is_none());
            assert_eq!(journal.frontier_seq_for_test(), before + 1);
        }
        println!("{READY}");
        io::stdout().flush().unwrap();
        io::stdin().read_exact(&mut [0]).unwrap();
        panic!("parent must terminate owner without unwinding");
    }

    use std::os::windows::fs::OpenOptionsExt;
    for case in ["ordinary", "busy", "changed_in_place", "replace_source", "replace_output", "after_delete"] {
        let marker = crate::test_support::temp_file("delete_hard_death", b"");
        let base = marker.with_extension("case");
        fs::create_dir(&base).unwrap();
        let test = format!("{}::hard_death_replays_delete_receipt_without_reissuing_wal_or_deleting_replacements",
            module_path!().split_once("::").unwrap().1);
        let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", &test, "--nocapture"])
            .env(CHILD, &base).env(CASE, case)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, ready) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                if line.unwrap().contains(READY) { let _ = send.send(()); return; }
            }
        });
        let reached = ready.recv_timeout(Duration::from_secs(30));
        let killed = child.kill();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        reached.expect("delete owner did not reach the durable boundary");
        killed.unwrap();
        assert!(!status.success());
        let output = base.join("output");
        let source = base.join("archive.zip");
        if case == "replace_source" { fs::rename(&source, base.join("original.zip")).unwrap(); }
        if matches!(case, "replace_source" | "after_delete") { fs::write(&source, b"replacement").unwrap(); }
        if case == "replace_output" {
            fs::rename(&output, base.join("original_output")).unwrap();
            fs::create_dir(&output).unwrap();
            fs::write(output.join("payload"), b"replacement").unwrap();
        }
        let held = matches!(case, "busy" | "changed_in_place").then(|| {
            fs::OpenOptions::new().write(true).share_mode(7).open(&source).unwrap()
        });
        let engine = Engine::new(base.join("unused-worker.exe"));
        let state_dir = base.join("state");
        {
            let journal = journal::Journal::open(&state_dir, 7).unwrap();
            let before = journal.frontier_seq_for_test();
            recover_source_cleanup(&journal, &engine, std::iter::once(base.as_path()), |_, _| true).unwrap();
            assert_eq!(journal.frontier_seq_for_test(), before, "{case}: replay appended a WAL record");
            assert_eq!(journal.state().runtime_record(&id).is_none(), held.is_none(), "{case}: incorrect receipt status");
            if held.is_some() { assert!(source.exists()); }
        }
        if case == "changed_in_place" { held.as_ref().unwrap().set_len(1).unwrap(); }
        drop(held);
        {
            let journal = journal::Journal::open(&state_dir, 7).unwrap();
            recover_source_cleanup(&journal, &engine, std::iter::once(base.as_path()), |_, _| true).unwrap();
            assert!(journal.state().runtime_record(&id).is_none(), "{case}: did not settle the original receipt");
            if case != "replace_output" {
                assert_eq!(output_identity(output.to_str().unwrap()).unwrap(),
                    fs::read_to_string(base.join("output_identity")).unwrap());
            }
            if matches!(case, "ordinary" | "busy") { assert!(!source.exists()); }
            if matches!(case, "replace_source" | "after_delete") { assert_eq!(fs::read(&source).unwrap(), b"replacement"); }
            if case == "changed_in_place" { assert_eq!(fs::read(&source).unwrap(), b"a"); }
            if case == "replace_output" {
                assert_eq!(fs::read(&source).unwrap(), b"archive");
                assert_eq!(fs::read(output.join("payload")).unwrap(), b"replacement");
            }
            journal.flush().unwrap();
        }
        let journal = journal::Journal::open(&state_dir, 7).unwrap();
        assert!(journal.state().runtime_record(&id).is_none(), "{case}: flush did not persist receipt retirement");
        drop(journal);
        fs::remove_dir_all(&base).unwrap();
        fs::remove_file(marker).unwrap();
    }
}



#[test]
fn claimed_release_reobserves_cancelled_replacement_and_remembers_late_sibling() {
    const CHILD: &str = "SUNPACK_CLAIM_RELEASE_CHILD";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let watched = base.join("watched");
        fs::create_dir_all(&watched).unwrap();
        fs::create_dir_all(base.join("sunpack")).unwrap();
        fs::write(base.join("sunpack/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        let source = watched.join("source.001");
        let sibling = watched.join("source.002");
        fs::write(&source, b"old generation").unwrap();
        fs::write(&sibling, b"unchanged sibling").unwrap();
        let old = watch_candidate_for_path(&source, None).unwrap().unwrap();
        let same = watch_candidate_for_path(&sibling, None).unwrap().unwrap();
        let captured = Arc::new(Mutex::new(ClaimedSources::default()));
        captured.lock().unwrap().capture(&[old.path.clone(), same.path.clone()]).unwrap();
        let journal = Arc::new(journal::Journal::open(&base.join("state"), 7).unwrap());
        let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
        let settings = Arc::new(Config::default());
            let mut scheduler = Scheduler {
                dedup_rebuild: None, dedup_job_id: 0,
                dedup: Arc::new(Mutex::new(dedup::Index::open(&base.join("state"), crate::core::config::WatchDeduplication::None, crate::core::config::WatchDeduplicationScope::Root, Default::default()).unwrap())),
                resuming: false, baseline_roots: HashSet::new(),
                candidate_diagnostics: CandidateDiagnostics::default(),
                root_scope_records: HashMap::new(),
                admission_checkpoint: None,
                cwd: base.clone(), root_file: base.join(ROOTS_FILE),
                roots: BTreeMap::from([(key(&watched), (Root { enabled: true, path: watched.clone(), output: None,
                    recursive: true, deep: true, scanned: true }, scope))]),
                available_roots: HashSet::from([key(&watched)]),
                user_password_signature: user_password_signature(&settings.user_passwords),
                settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
                catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), recovery_ids: HashMap::new(), journal,
                options: None,
                deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
                passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
                root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
                parent_observers: HashMap::new(), dependency_observers: HashMap::new(), config_observers: Vec::new(),
                pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
                active: HashMap::new(), active_paths: HashMap::new(), tray_enabled: false,
                tray: None, monitor: None, toast: None, cache_deadline: None,
                external: Arc::default(), broker_lease: None,
            };

        let mut interrupted = NativeWatchOperations::empty();
        interrupted.put_entry(Arc::new(observed_entry(&old, "interrupted")));
        scheduler.journal.commit(true, |_| Ok(interrupted)).unwrap();
        fs::write(&source, b"replacement generation with a different size").unwrap();
        let group = Arc::new(SourceGroup { path: source.clone(),
            members: vec![old.path.clone(), same.path.clone()] });
        let groups: HashMap<_, _> = group.members.iter().map(|path| (watch_path_key(path), Arc::clone(&group))).collect();
        scheduler.hub.claims.lock().unwrap().extend(groups.keys().map(|path| (path.clone(), Arc::<str>::from("owner"))));
        let dirty = HashSet::from([key(&source), key(&sibling)]);
        scheduler.apply_completion("owner", CompletionContext {
            max_depth: usize::MAX,
            deep: false,
            root: key(&watched), recovery: None, password_scope: watched.clone(), passwords: Arc::default(),
            inputs: vec![old, same], quiet: HashMap::new(), dirty, claimed: captured, groups, toast: None, task: None,
        }, Completed { cancelled: true, result: Err(io::Error::other("cancelled owner")),
             outputs: BTreeMap::new() }).unwrap();
        assert_eq!(scheduler.pending.len(), 1);
        assert_eq!(scheduler.pending[&key(&source)].candidate.size, fs::metadata(&source).unwrap().len());
        assert!(!scheduler.pending.contains_key(&key(&sibling)));
        assert!(scheduler.catalog.observation(sibling.to_str().unwrap()).is_some());
        // A late notification no longer carries the sealed claim observation.
        scheduler.enqueue(&key(&watched), sibling.to_string_lossy().into_owned(), CandidateAdmission::Observe).unwrap();
        assert_eq!(scheduler.pending.len(), 1);
        assert_eq!(scheduler.due.len(), 1);

        // The old request is already released and awaiting its root report.
        // A later complete family is recorded through the production observer
        // before the old result reaches the actual completion/WAL path.
        for kind in [FailureKind::MissingVolume, FailureKind::WrongPassword] {
            let head = watched.join(format!("late-{kind:?}.001"));
            let tail = watched.join(format!("late-{kind:?}.002"));
            let output = watched.join(format!("late-{kind:?}-output"));
            fs::write(&head, b"same head retained after successful extraction").unwrap();
            let candidate = watch_candidate_for_path(&head, None).unwrap().unwrap();
            let old = super::tests::completion_archive(head.to_str().unwrap(), 1, Some(kind));
            fs::write(&tail, b"new complete tail").unwrap();
            fs::create_dir(&output).unwrap();
            let generations: SourceGenerations = [&head, &tail].into_iter().map(|path|
                (key(path), capture_file_generation(path).unwrap())).collect();
            let observer = WatchObserver {
                dedup_generation: None,
                dedup: Arc::new(Mutex::new(dedup::Index::open(&base.join("state"), crate::core::config::WatchDeduplication::None, crate::core::config::WatchDeduplicationScope::Root, Default::default()).unwrap())),
                dedup_scope: NativeDiscoveryScope::new(base.join("state").to_string_lossy().into_owned(), None, Vec::new()),
                catalog: Arc::clone(&scheduler.catalog),
                deep: false, journal: Arc::clone(&scheduler.journal),
                owners: HashMap::new(),
                outputs: Mutex::new(ObservedOutputs::from(BTreeMap::new())),
                batch: Arc::from("new-success"), toast: None, hub: Arc::clone(&scheduler.hub),
                groups: Arc::default(), claimed: Arc::default(),
            };
            // Main remembers complete source output even if a child failed.
            observer.sources_processed(generations.clone(), 1, Some(&output), None).unwrap();
            assert_eq!(observer.completed_sources(&generations, 1).unwrap(), Some(output.clone()));
            let mut outcome = Outcome::default();
            outcome.archives.push(old);
            scheduler.apply_completion("late-old-failure", CompletionContext {
            max_depth: usize::MAX,
                deep: false, root: key(&watched), recovery: None, password_scope: watched.clone(), passwords: Arc::default(),
                inputs: vec![candidate.clone()], quiet: HashMap::new(), dirty: HashSet::new(),
                claimed: Arc::default(), groups: HashMap::new(), toast: None, task: None,
            }, Completed { cancelled: false, result: Ok(outcome),
                 outputs: BTreeMap::new() }).unwrap();
            assert!(scheduler.journal.state().entry(&candidate.path).is_none());
            assert!(scheduler.journal.state().pending(&candidate.path).is_none());
            assert!(!scheduler.pending.contains_key(&key(&head)));
        }
        // Reopen the durable journal: this assertion is not just live-map state.
        let state = base.join("state");
        drop(scheduler);
        let reopened = journal::Journal::open(&state, 7).unwrap();
        for kind in [FailureKind::MissingVolume, FailureKind::WrongPassword] {
            let head = watched.join(format!("late-{kind:?}.001"));
            assert!(reopened.state().entry(&head.to_string_lossy()).is_none());
            assert!(reopened.state().pending(&head.to_string_lossy()).is_none());
        }
        return;
    }
    let base = std::env::temp_dir().join(format!("sunpack-claim-release-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&base).unwrap();
    let base = PathBuf::from(crate::path_keys::normalize_windows_extended_prefix(
        fs::canonicalize(&base).unwrap().to_string_lossy().into_owned(),
    ));
    let test = format!("{}::claimed_release_reobserves_cancelled_replacement_and_remembers_late_sibling", module_path!().split_once("::").unwrap().1);
    let output = Command::new(std::env::current_exe().unwrap()).args(["--exact", &test, "--nocapture"])
        .env(CHILD, &base).output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    fs::remove_dir_all(base).unwrap();
}
