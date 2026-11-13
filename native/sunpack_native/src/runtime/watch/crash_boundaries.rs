use super::*;
use crate::io::reader::capture_file_generation;
use crate::watch_store::{NativeWatchOperations, PendingObservation};
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

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
        let work = base.join("work");
        let leaf = root.join("wrapper/inner");
        let nested = leaf.join("nested.zip");
        let nested_output = leaf.join("nested");
        fs::create_dir_all(&nested_output).unwrap();
        fs::write(&owner, b"carrier input").unwrap();
        fs::write(&nested, b"nested archive").unwrap();
        fs::write(nested_output.join("payload"), b"committed payload").unwrap();
        let payload_identity = output_identity(nested_output.to_str().unwrap()).unwrap();
        fs::write(base.join("identity"), payload_identity).unwrap();
        let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
        let owner_text = owner.to_str().unwrap();
        journal.commit(true, |state| {
            Ok(state.pending_operations(
                [(PendingObservation(owner_text.into(), 13, 1.0, String::new(), 0),
                    String::new(), None)], false, "", false, true, None,
            )?.0)
        }).unwrap();
        journal.commit(true, |state| {
            Ok(state.output_operation(owner_text, owner_text.into(),
                root.to_string_lossy().into_owned(), None, None)?.unwrap())
        }).unwrap();
        prepare_flatten(&journal, owner_text, &root, &work, &leaf).unwrap();
        let phase = std::env::var(PHASE).unwrap();
        if phase != "prepared" {
            crate::io::atomic_file::rename_no_replace(&root, &work).unwrap();
        }
        if matches!(phase.as_str(), "published" | "rebased") {
            crate::io::atomic_file::rename_no_replace(&work.join("wrapper/inner"), &root).unwrap();
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
        let work = base.join("work");
        let leaf = root.join("wrapper/inner");
        for reopen in 0..2 {
            let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
            recover_flattens(&journal, |_| true).unwrap();
            if phase == "prepared" && reopen == 0 {
                // No filesystem move occurred. Recovery retires the untouched
                // intent; the resumed pipeline can perform the same operation.
                assert!(leaf.join("nested/payload").is_file());
                let result = crate::postprocess::flatten_single_branch_directories(
                    &root, Some(&work),
                    |root, work, leaf| prepare_flatten(&journal, owner.to_str().unwrap(), root, work, leaf),
                    None,
                );
                assert!(result.errors.is_empty(), "{:?}", result.errors);
                finish_flatten(&journal, root.to_str().unwrap()).unwrap();
            }
            assert_eq!(fs::read(root.join("nested/payload")).unwrap(), b"committed payload");
            assert_eq!(output_identity(root.join("nested").to_str().unwrap()).unwrap(),
                fs::read_to_string(base.join("identity")).unwrap());
            assert!(!work.exists(), "{phase}/{reopen}");
            assert!(journal.state().runtime_keys("flatten|").is_empty());
            let pending = journal.state().pending(owner.to_str().unwrap()).unwrap();
            assert!(recovery_output_matches(journal.state(), &pending, root.to_str().unwrap()));
            assert!(journal.state().owned_root(work.to_str().unwrap()).is_none());
        }
        fs::remove_dir_all(&base).unwrap();
        fs::remove_file(marker).unwrap();
    }
}


// Promotion recovery has to retain both sides of a partially moved multipart
// family. A whole-process death must bypass the move routine's error rollback.
#[test]
fn hard_death_recovers_partially_promoted_family_without_duplicate_admission() {
    const CHILD: &str = "SUNPACK_PROMOTION_CRASH_CHILD";
    const PHASE: &str = "SUNPACK_PROMOTION_CRASH_PHASE";
    const MODE: &str = "SUNPACK_PROMOTION_CRASH_MODE";
    const READY: &str = "sunpack-promotion-crash-ready";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let watched = base.join("watched");
        let output = watched.join("output");
        let owner = watched.join("carrier.bin");
        let names = ["series.7z.001", "series.7z.002"];
        let phase = std::env::var(PHASE).unwrap();
        let moved = match phase.as_str() { "prepared" => 0, "partial" => 1, _ => 2 };
        if std::env::var(MODE).as_deref() == Ok("recover") {
            // Only the recovery method is under test: no worker, observers or
            // broker connection is started. This isolated process has no
            // acquired broker lease, so its empty lease Drop is a no-op.
            let journal = Arc::new(journal::Journal::open(&base.join("state"), 7).unwrap());
            let scope = NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new());
            let settings = Arc::new(Config::parse(&json!({})).unwrap());
            let mut scheduler = Scheduler {
                candidate_diagnostics: CandidateDiagnostics::default(),
                admission_checkpoint: None,
                cwd: base.clone(), root_file: base.join(ROOTS_FILE),
                roots: BTreeMap::from([(key(&watched), (Root { path: watched.clone(), output: None,
                    recursive: true, deep: true, scanned: true }, scope))]),
                available_roots: HashSet::from([key(&watched)]),
                user_password_signature: user_password_signature(&settings.user_passwords),
                settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
                catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
                options: None,
                deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
                passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
                root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
                parent_observers: HashMap::new(), config_observers: Vec::new(),
                pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
                active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
                tray: None, monitor: None, toast: None, cache_deadline: None,
                external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
            };
            scheduler.recover_pending(None).unwrap();
            let expected = names.iter().enumerate().map(|(index, name)| {
                if index < moved { watched.join(name) } else { output.join(name) }
            }).collect::<Vec<_>>();
            assert_eq!(scheduler.pending.len(), 2, "{phase}");
            assert_eq!(scheduler.journal.state().pending_items().len(), 2, "{phase}");
            assert!(scheduler.journal.state().pending(owner.to_str().unwrap()).is_none());
            for (index, path) in expected.iter().enumerate() {
                assert!(scheduler.pending.contains_key(&key(path)), "{}", path.display());
                assert_eq!(fs::read(path).unwrap(), format!("volume-{index}").as_bytes());
                let identity = capture_file_generation(path).unwrap().persisted();
                let saved: Value = serde_json::from_slice(&fs::read(base.join(format!("generation-{index}.json"))).unwrap()).unwrap();
                // A rename may change USN/change-time; the physical file ID
                // and payload must remain the original, not regenerated data.
                let current = serde_json::to_value(identity).unwrap();
                assert!(!saved["windows"]["file_id"].is_null());
                assert_eq!(current["windows"]["file_id"], saved["windows"]["file_id"]);
                assert_eq!(current["windows"]["volume"], saved["windows"]["volume"]);
                assert_eq!(usize::from(watched.join(names[index]).is_file())
                    + usize::from(output.join(names[index]).is_file()), 1);
            }
            return;
        }
        fs::create_dir_all(&output).unwrap();
        // BuiltinStore resolves this explicit test development root, not the
        // actual checkout's editable password file.
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
        fs::write(base.join("sunpack_advanced_config.json"), b"{}").unwrap();
        fs::write(&owner, b"carrier").unwrap();
        let sources = names.iter().map(|name| output.join(name)).collect::<Vec<_>>();
        let destinations = names.iter().map(|name| watched.join(name)).collect::<Vec<_>>();
        for (index, source) in sources.iter().enumerate() {
            fs::write(source, format!("volume-{index}")).unwrap();
            fs::write(base.join(format!("generation-{index}.json")),
                serde_json::to_vec(&capture_file_generation(source).unwrap().persisted()).unwrap()).unwrap();
        }
        let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
        let owner_text = owner.to_str().unwrap();
        journal.commit(true, |state| Ok(state.pending_operations(
            [(PendingObservation(owner_text.into(), 7, 1.0, String::new(), 0),
                watched.to_string_lossy().into_owned(), None)], false, "", false, true, None,
        )?.0)).unwrap();
        journal.commit(true, |state| Ok(state.output_operation(owner_text, owner_text.into(),
            output.to_string_lossy().into_owned(), None, None)?.unwrap())).unwrap();
        journal.commit(true, |state| Ok(state.output_operation(owner_text, owner_text.into(),
            output.to_string_lossy().into_owned(), Some(true), None)?.unwrap())).unwrap();
        journal.commit(true, |state| Ok(state.promotion_operation(owner_text,
            destinations.iter().map(|path| path.to_string_lossy().into_owned()).collect(),
            sources.iter().map(|path| path.to_string_lossy().into_owned()).collect()).unwrap())).unwrap();
        for (source, destination) in sources.iter().zip(&destinations).take(moved) {
            crate::io::atomic_file::rename_no_replace(source, destination).unwrap();
        }
        if phase == "receipts" {
            journal.commit(true, |_| {
                let mut operations = NativeWatchOperations::empty();
                for path in &destinations {
                    operations.put_promoted(serde_json::from_value(json!({
                        "path": path, "generation": capture_file_generation(path)?.persisted(),
                    }))?);
                }
                Ok(operations)
            }).unwrap();
        }
        println!("{READY}");
        io::stdout().flush().unwrap();
        let mut byte = [0];
        io::stdin().read_exact(&mut byte).unwrap();
        panic!("parent must kill promotion owner without unwinding");
    }
    for phase in ["prepared", "partial", "moved", "receipts"] {
        let marker = crate::test_support::temp_file("promotion_hard_death", b"");
        let base = marker.with_extension("case");
        fs::create_dir(&base).unwrap();
        let test_name = format!("{}::hard_death_recovers_partially_promoted_family_without_duplicate_admission",
            module_path!().split_once("::").unwrap().1);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD, &base).env(PHASE, phase)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().unwrap();
        let (send, ready) = mpsc::sync_channel(1);
        let stdout = child.stdout.take().unwrap();
        let reader = thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                if line.unwrap().contains(READY) { let _ = send.send(()); return; }
            }
        });
        let reached = ready.recv_timeout(Duration::from_secs(30));
        let killed = child.kill();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        reached.expect("promotion owner did not reach the durable boundary");
        killed.unwrap();
        assert!(!status.success());
        for _ in 0..2 {
            let recovered = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env(CHILD, &base).env(PHASE, phase).env(MODE, "recover")
                .output().unwrap();
            assert!(recovered.status.success(), "{phase}: {}\n{}",
                String::from_utf8_lossy(&recovered.stdout), String::from_utf8_lossy(&recovered.stderr));
        }
        fs::remove_dir_all(&base).unwrap();
        fs::remove_file(marker).unwrap();
    }
}


// Exercise the real release/observation path in an isolated process, so the
// existing empty BrokerLease does not affect another test's acquired lease.
#[test]
fn claimed_release_reobserves_cancelled_replacement_and_remembers_late_sibling() {
    const CHILD: &str = "SUNPACK_CLAIM_RELEASE_CHILD";
    if let Some(base) = std::env::var_os(CHILD) {
        let base = PathBuf::from(base);
        let watched = base.join("watched");
        fs::create_dir_all(&watched).unwrap();
        fs::create_dir_all(base.join("native")).unwrap();
        fs::write(base.join("native/Cargo.toml"), b"").unwrap();
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
                candidate_diagnostics: CandidateDiagnostics::default(),
                admission_checkpoint: None,
                cwd: base.clone(), root_file: base.join(ROOTS_FILE),
                roots: BTreeMap::from([(key(&watched), (Root { path: watched.clone(), output: None,
                    recursive: true, deep: true, scanned: true }, scope))]),
                available_roots: HashSet::from([key(&watched)]),
                user_password_signature: user_password_signature(&settings.user_passwords),
                settings, engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
                catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
                options: None,
                deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
                passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
                root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
                parent_observers: HashMap::new(), config_observers: Vec::new(),
                pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
                active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
                tray: None, monitor: None, toast: None, cache_deadline: None,
                external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
            };

        let mut interrupted = NativeWatchOperations::empty();
        interrupted.put_entry(Arc::new(observed_entry(&old, "interrupted", None)));
        scheduler.journal.commit(true, |_| Ok(interrupted)).unwrap();
        fs::write(&source, b"replacement generation with a different size").unwrap();
        let group = Arc::new(SourceGroup { path: source.clone(), name: "source".into(),
            members: vec![old.path.clone(), same.path.clone()], multipart: true });
        let groups: HashMap<_, _> = group.members.iter().map(|path| (watch_path_key(path), Arc::clone(&group))).collect();
        scheduler.hub.claims.lock().unwrap().extend(groups.keys().map(|path| (path.clone(), Arc::<str>::from("owner"))));
        let dirty = HashSet::from([key(&source), key(&sibling)]);
        scheduler.apply_completion("owner", CompletionContext {
            root: key(&watched), recovery: None, passwords: Arc::default(),
            inputs: vec![old, same], quiet: HashMap::new(), dirty, claimed: captured, groups, toast: None, task: None,
        }, Completed { cancelled: true, result: Err(io::Error::other("cancelled owner")),
            promoted: HashMap::new(), outputs: BTreeMap::new() }).unwrap();
        assert_eq!(scheduler.pending.len(), 1);
        assert_eq!(scheduler.pending[&key(&source)].candidate.size, fs::metadata(&source).unwrap().len());
        assert!(!scheduler.pending.contains_key(&key(&sibling)));
        assert!(scheduler.catalog.observation(sibling.to_str().unwrap()).is_some());
        // A late notification no longer carries the sealed claim observation.
        scheduler.enqueue(&key(&watched), sibling.to_string_lossy().into_owned(), CandidateAdmission::Observe).unwrap();
        assert_eq!(scheduler.pending.len(), 1);
        assert_eq!(scheduler.due.len(), 1);
        return;
    }
    let base = std::env::temp_dir().join(format!("sunpack-claim-release-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&base).unwrap();
    let test = format!("{}::claimed_release_reobserves_cancelled_replacement_and_remembers_late_sibling", module_path!().split_once("::").unwrap().1);
    let output = Command::new(std::env::current_exe().unwrap()).args(["--exact", &test, "--nocapture"])
        .env(CHILD, &base).output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    fs::remove_dir_all(base).unwrap();
}
