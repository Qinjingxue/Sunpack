use super::*;
use crate::io::reader::capture_file_generation;
use crate::watch_store::{NativeWatchOperations, PendingObservation};
#[test]
fn foreground_output_reservation_survives_scheduler_replacement_and_is_published_once() {
    let marker = crate::test_support::temp_file("output_publication_handoff", b"");
    let root = marker.with_extension("watch");
    let output = root.join("output");
    let state_dir = marker.with_extension("state");
    let watch = Watch::new(Arc::new(|| {}));
    watch.register_external_output(&output).unwrap();
    let member = output.join("nested.zip");
    fs::write(&member, b"generated content").unwrap();
    let leaf = output.join("leaf");
    fs::create_dir(&leaf).unwrap();
    let work = root.join("flatten-work");
    watch.prepare_external_flatten(&output, &work, &leaf).unwrap();
    let scope = NativeDiscoveryScope::new(root.to_string_lossy().into_owned(), None, Vec::new());
    let options = NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
    for generation in 0..2 {
        let journal = Arc::new(journal::Journal::open_with_outputs(&state_dir, 7,
            Arc::clone(&watch.external.reservations)).unwrap());
        let catalog = Arc::new(NativeWatchCatalog::new(journal.state(), None));
        options.catalog_update(&catalog, &scope, None).unwrap();
        assert!(catalog.is_owned(member.to_str().unwrap()));
        assert!(catalog.candidate_paths(&scope, None).is_empty());
        *watch.external.current.write().unwrap() = Some(ExternalOutputs {
            journal: Arc::downgrade(&journal), scopes: Arc::from([scope.clone()]),
            catalog: Arc::clone(&catalog), options: options.clone(), hub: Weak::new(),
        });
        if generation == 1 {
            // An inventory publication pins the current target. Another
            // foreground worker can still register an independent output.
            let concurrent = root.join("other-output");
            std::thread::scope(|threads| {
                let publication = watch.external.current.read().unwrap();
                let (registered, receive) = mpsc::channel();
                let (watch, concurrent) = (&watch, &concurrent);
                threads.spawn(move || {
                    let _ = registered.send(watch.register_external_output(concurrent));
                });
                let result = receive.recv_timeout(std::time::Duration::from_secs(5));
                drop(publication);
                result.expect("output registration waited on publication").unwrap();
            });
            watch.finish_external_outputs(&[
                output.to_string_lossy().into_owned(),
                concurrent.to_string_lossy().into_owned(),
            ]).unwrap();
            assert!(!catalog.is_owned(member.to_str().unwrap()));
            let before = catalog.observation(member.to_str().unwrap()).unwrap();
            let current = watch_candidate_for_path(&member, Some(before.change_usn)).unwrap().unwrap();
            assert!(catalog.generated_observation(member.to_str().unwrap()).is_some());
            assert!(!quiet::content_changed(before.size, before.mtime, &before.file_id(), before.change_usn, &current));
            assert!(watch.external.reservations.lock().unwrap().is_empty());
        }
        *watch.external.current.write().unwrap() = None;
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(state_dir).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn completed_family_requires_full_generation_mode_and_live_output() {
    let directory = std::env::temp_dir().join(format!("sunpack-completed-family-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&directory).unwrap();
    let head = directory.join("archive.001");
    let tail = directory.join("archive.002");
    let output = directory.join("output");
    fs::write(&head, b"head").unwrap();
    fs::write(&tail, b"tail").unwrap();
    fs::create_dir(&output).unwrap();
    let generations: SourceGenerations = [&head, &tail].into_iter().map(|path|
        (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect();
    let cache = CompletedFamilies::default();
    cache.remember(generations.clone(), false, &output);
    assert_eq!(cache.output(&generations, false), Some(output.clone()));
    assert_eq!(cache.output(&generations, true), None);
    let subset = HashMap::from([(key(&head), generations[&key(&head)].clone())]);
    assert_eq!(cache.output(&subset, false), None);
    assert!(cache.covers(&head, false));
    assert!(cache.covers(&tail, false));
    assert!(!cache.covers(&head, true));
    fs::rename(&tail, directory.join("away")).unwrap();
    assert!(!cache.covers(&head, false));
    fs::rename(directory.join("away"), &tail).unwrap();
    assert!(cache.covers(&head, false));
    fs::write(&tail, b"changed tail generation").unwrap();
    assert!(!cache.covers(&head, false));
    let refreshed: SourceGenerations = [&head, &tail].into_iter().map(|path|
        (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect();
    assert_eq!(cache.output(&refreshed, false), None);
    cache.remember(refreshed.clone(), false, &output);
    assert_eq!(cache.output(&refreshed, false), Some(output.clone()));
    fs::remove_dir(&output).unwrap();
    assert_eq!(cache.output(&refreshed, false), None);
    assert!(!cache.covers(&head, false));
    assert_eq!(cache.0.lock().unwrap().len(), 0);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn completed_family_reuses_renamed_members_but_rejects_new_objects() {
    let head = crate::test_support::temp_file("renamed_family_head", b"head");
    let tail = head.with_extension("downloading");
    let arrived = head.with_extension("arrived");
    let old = head.with_extension("old");
    let output = head.with_extension("output");
    fs::write(&tail, b"tail").unwrap();
    fs::create_dir(&output).unwrap();
    let capture = |tail: &Path| -> SourceGenerations {
        [&*head, tail].into_iter().map(|path|
            (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect()
    };
    let cache = CompletedFamilies::default();
    cache.remember(capture(&tail), false, &output);
    fs::rename(&tail, &arrived).unwrap();
    let renamed = capture(&arrived);
    assert_eq!(cache.output(&renamed, false), Some(output.clone()));
    assert!(cache.covers(&arrived, false));
    assert!(cache.covers(&head, false));
    assert!(!cache.covers(&tail, false));
    assert_eq!(cache.output(&renamed, true), None);
    // A newly created object at the same name is not a completed member,
    // even if it has the same bytes and size. Keep the old object alive.
    fs::rename(&arrived, &old).unwrap();
    fs::write(&arrived, b"tail").unwrap();
    assert_eq!(cache.output(&capture(&arrived), false), None);
    assert_ne!(CompletedMember::Object(1, [7; 16]), CompletedMember::Object(2, [7; 16]));
    fs::remove_file(head).unwrap();
    fs::remove_file(arrived).unwrap();
    fs::remove_file(old).unwrap();
    fs::remove_dir(output).unwrap();
}

#[test]
fn idle_completed_families_release_old_output_but_live_requests_reuse_it() {
    let head = crate::test_support::temp_file("idle_family_head", b"head");
    let tail = crate::test_support::temp_file("idle_family_tail", b"tail");
    let output = head.with_extension("output");
    fs::create_dir(&output).unwrap();
    let generations: SourceGenerations = [&head, &tail].into_iter().map(|path|
        (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect();
    let hub = Hub::new();
    hub.completed_families.remember(generations.clone(), false, &output);
    assert_eq!(hub.completed_families.output(&generations, false), Some(output.clone()));
    hub.clear_idle_completed_families();
    let cache = &hub.completed_families;
    assert_eq!(cache.output(&generations, false), None);
    assert_eq!(cache.0.lock().unwrap().len(), 0);
    fs::remove_dir(output).unwrap();
    fs::remove_file(head).unwrap();
    fs::remove_file(tail).unwrap();
}

#[test]
fn completed_family_cache_is_bounded_and_refreshes_lru() {
    let directory = std::env::temp_dir().join(format!("sunpack-family-lru-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&directory).unwrap();
    let head = directory.join("head");
    fs::write(&head, b"head").unwrap();
    let generation = crate::io::reader::capture_file_generation(&head).unwrap();
    let cache = CompletedFamilies::default();
    cache.remember(HashMap::from([(key(&head), generation.clone())]), false, &directory);
    // Synthetic unrelated families exercise the LRU without thousands of
    // filesystem objects; spellings of the same object now intentionally coalesce.
    for n in 1..COMPLETED_FAMILY_LIMIT {
        let family: CompletedFamilyKey = (Arc::from([CompletedMember::Path(format!("other-{n}"))]), false);
        let generations = Arc::new(CompletedGenerations::new(vec![(format!("other-{n}"), generation.clone())]));
        cache.0.lock().unwrap().insert(family, (generations, Arc::from(directory.as_path())), COMPLETED_FAMILY_LIMIT);
    }
    assert!(cache.covers(&head, false));
    cache.remember(HashMap::from([(key(&head), generation)]), true, &directory);
    assert!(cache.covers(&head, false));
    let cache = cache.0.lock().unwrap();
    assert_eq!(cache.len(), COMPLETED_FAMILY_LIMIT);
    assert!(!cache.iter().any(|((members, _), _)| members.iter().any(|member| matches!(member, CompletedMember::Path(path) if path == "other-1"))));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn recovery_scan_preserves_readable_files_with_local_errors() {
    let marker = crate::test_support::temp_file("recovery_scan_errors", b"archive");
    let directory = marker.with_extension("state");
    let journal = journal::Journal::open(&directory, 7).unwrap();
    let paths = recovery_scan_paths(&journal, "owner.zip", "output",
        Ok((vec![marker.clone()], vec![("read_dir".into(), "output/locked".into(),
            "access denied".into())]))).unwrap();
    assert_eq!(paths, [marker.clone()]);
    let failure = recovery_scan_paths(&journal, "owner.zip", "output",
        Err(io::ErrorKind::PermissionDenied.into())).unwrap_err();
    assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
    journal.flush().unwrap();
    let manifest: crate::io::display_store::Manifest = serde_json::from_slice(
        &fs::read(directory.join("events.json")).unwrap(),
    ).unwrap();
    assert_eq!(manifest.runs.iter().map(|run| run.count - run.head).sum::<u64>(), 2);
    drop(journal);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn configuration_subscriptions_share_directory_and_preserve_live_intersections() {
    let marker = crate::test_support::temp_file("shared_config_observer", b"");
    let directory = marker.with_extension("directory");
    fs::create_dir(&directory).unwrap();
    let config = directory.join("config.json");
    let passwords = directory.join("passwords.json");
    let first = observe_files(&[config.clone()], &passwords, |_, _| {}).unwrap();
    let second = observe_files(&[config.clone(), directory.join("roots.txt")], &passwords, |_, _| {}).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert!(Arc::ptr_eq(&first[0].directory, &second[0].directory));
    assert!(observes_files(&[config.clone()], &passwords, &first));
    assert!(!observes_files(&[config.clone()], &passwords, &second));
    let weak = Arc::downgrade(&first[0].directory);
    let directory_key = key(&first[0].directory.observer.path);
    assert_eq!(first[0].directory.listeners.lock().unwrap().len(), 2);
    drop(first);
    assert!(second[0].alive());
    assert_eq!(second[0].directory.listeners.lock().unwrap().len(), 1);
    // Re-arming a changed file set adds a listener, not a native observer.
    let third = observe_files(&[config], &passwords, |_, _| {}).unwrap();
    assert!(Arc::ptr_eq(&second[0].directory, &third[0].directory));
    drop(second);
    drop(third);
    assert!(weak.upgrade().is_none());
    assert!(!CONFIG_DIRECTORIES.get().unwrap().lock().unwrap().contains_key(&directory_key));

    let child = directory.join("new");
    let paths = [child.join("config.json")];
    let ancestor = observe_files(&paths, &passwords, |_, _| {}).unwrap();
    assert!(observes_files(&paths, &passwords, &ancestor));
    fs::create_dir(&child).unwrap();
    assert!(!observes_files(&paths, &passwords, &ancestor));
    let moved = observe_files(&paths, &passwords, |_, _| {}).unwrap();
    assert_eq!(moved.len(), 2);
    assert!(moved.iter().any(|subscription| Arc::ptr_eq(&ancestor[0].directory, &subscription.directory)));
    drop(ancestor);
    assert!(observes_files(&paths, &passwords, &moved));
    drop(moved);
    fs::remove_dir(child).unwrap();
    fs::remove_dir(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn ordinary_observation_diagnostics_preserve_native_event_provenance() {
    let path = Path::new("destination.zip");
    let mut source = None;
    let error = io::Error::new(io::ErrorKind::PermissionDenied, "locked");
    for (action, expected) in [(1, "created"), (3, "modified")] {
        let event = CandidateEvent::native(action, path, &mut source).unwrap();
        let record = CandidateDiagnostics::observation_record("destination.zip", &error, Some(&event));
        assert_eq!(record["event_type"], expected);
        assert_eq!(record["src_path"], "");
        assert_eq!(record["event"], "candidate_ignored");
        assert_eq!(record["reason"], "observation_error");
        assert_eq!(record["error"], "PermissionError: locked");
    }
    assert_eq!(CandidateEvent::native(4, Path::new("source.zip"), &mut source), None);
    let moved = CandidateEvent::native(5, path, &mut source).unwrap();
    let record = CandidateDiagnostics::observation_record("destination.zip", &error, Some(&moved));
    assert_eq!(record["event_type"], "moved");
    assert_eq!(record["src_path"], "source.zip");
    assert_eq!(record["path"], "destination.zip");
    // An unmatched new-name record cannot supply an invented source.
    assert_eq!(CandidateEvent::native(5, path, &mut source), None);
    let recovery = CandidateDiagnostics::observation_record("destination.zip", &error, None);
    assert_eq!(recovery["event_type"], "unknown");
    assert_eq!(recovery["src_path"], "");
    // Coalescing retains the first actual ordinary event, as main's
    // diagnostic throttle would, until this Signals burst is consumed.
    let mut signals = Signals::default();
    signals.changes.root_changed("root", [(path.to_owned(), PathChange {
        modified_only: false, event: Some(moved), observation: None,
    })]);
    signals.changes.root_changed("root", [(path.to_owned(), PathChange {
        modified_only: true, event: Some(CandidateEvent::Modified), observation: None,
    })]);
    assert_eq!(signals.changes.paths[path].event.as_ref().unwrap().kind(), "moved");
    assert!(!signals.changes.paths[path].modified_only);
    let captured = std::mem::take(&mut signals);
    assert!(signals.changes.paths.is_empty());
    assert_eq!(captured.changes.paths[path].event.as_ref().unwrap().source(), "source.zip");
}

#[test]
fn candidate_wait_history_survives_pending_retirement_and_expires_with_a_bound() {
    let marker = crate::test_support::temp_file("candidate_diagnostics", b"");
    let directory = marker.with_extension("state");
    let journal = journal::Journal::open(&directory, 7).unwrap();
    let now = Instant::now();
    let mut history = CandidateDiagnostics::default();
    let error = io::Error::new(io::ErrorKind::PermissionDenied, "locked");
    // No Pending owner is retained: a same-path re-entry shares history.
    for seconds in [0, 1, 29, 30, 31] {
        let at = now + std::time::Duration::from_secs(seconds);
        history.log_wait(&journal, at, "path", "path", None);
        history.log_wait(&journal, at, "path", "path", Some(&error));
    }
    journal.flush().unwrap();
    let manifest: crate::io::display_store::Manifest = serde_json::from_slice(
        &fs::read(directory.join("events.json")).unwrap(),
    ).unwrap();
    assert_eq!(manifest.runs.iter().map(|run| run.count - run.head).sum::<u64>(), 4);
    // Observation and readiness errors have independent main intervals.
    // A long-lived observation entry must not hide a later 30s expiry.
    let observation_at = now + std::time::Duration::from_secs(31);
    history.log_observation(&journal, observation_at, "observe", "observe", &error, None);
    history.log_wait(&journal, observation_at, "later", "later", Some(&error));
    history.clear_expired(now + std::time::Duration::from_secs(61));
    assert_eq!(history.len(), 1);
    assert!(history.paths.contains_key("observe"));
    assert!(!history.paths.contains_key("later"));
    history.log_observation(&journal, now + std::time::Duration::from_secs(330), "observe", "observe", &error, None);
    assert_eq!(history.len(), 1);
    let at = now + std::time::Duration::from_secs(331);
    history.log_observation(&journal, at, "observe", "observe", &error, None);
    assert_eq!(history.deadline(), Some(at + std::time::Duration::from_secs(300)));
    for index in 0..2048 {
        let path = index.to_string();
        history.log_wait(&journal, at, &path, &path, None);
    }
    assert_eq!(history.len(), 2048);
    assert_eq!(history.paths.len(), 2048);
    assert!(!history.paths.contains_key("path"));
    history.clear_expired(at + std::time::Duration::from_secs(30));
    assert!(history.paths.is_empty());
    assert!(history.deadline().is_none());
    drop(journal);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn root_policy_normalizes_only_equivalent_nonrecursive_output_layouts() {
    let path = PathBuf::from(r"C:\downloads");
    let mut implicit = Root { path: path.clone(), output: None, recursive: false,
        deep: true, scanned: false };
    let mut explicit = implicit.clone();
    explicit.output = Some(path);
    explicit.scanned = true;
    assert!(implicit.same_policy(&explicit));
    assert!(explicit.same_policy(&implicit));
    implicit.recursive = true;
    explicit.recursive = true;
    assert!(!implicit.same_policy(&explicit));
    explicit.output = None;
    assert!(implicit.same_policy(&explicit));
    explicit.deep = false;
    assert!(!implicit.same_policy(&explicit));
}

#[test]
fn partial_catalog_refresh_preserves_arrivals_before_fallback() {
    let mut paths = vec!["previous.zip".to_owned()];
    let errors = vec![("metadata".into(), "locked.zip".into(), "access denied".into())];
    assert!(collect_catalog_arrivals(Ok((errors, vec!["new.zip".into()])), &mut paths).is_err());
    // The catalog already contains new.zip; a successful full retry can
    // legitimately report no arrivals. It must still reach admission.
    collect_catalog_arrivals(Ok((Vec::new(), Vec::new())), &mut paths).unwrap();
    assert_eq!(paths, ["previous.zip", "new.zip"]);
    assert!(collect_catalog_arrivals(Err(io::ErrorKind::PermissionDenied.into()), &mut paths).is_err());
    assert_eq!(paths.len(), 2);
}

#[test]
fn flatten_recovery_keeps_intent_after_local_probe_failure() {
    let source = crate::test_support::temp_file("flatten_probe_failure", b"owner");
    let directory = source.with_extension("state");
    let root = directory.join("missing");
    let work = directory.join("work");
    let journal = journal::Journal::open(&directory, 7).unwrap();
    let record_key = format!("flatten|{}", key(&root));
    journal.commit(true, |_| {
        let mut operations = crate::watch_store::NativeWatchOperations::empty();
        operations.set_runtime(record_key.clone(), Some(json!({
            "owner":"owner","root":root,"work":work,"work_paths":[work],
            "leaf":root.join("leaf"),"old_identity":"old","new_identity":"new",
        })));
        Ok(operations)
    }).unwrap();
    assert!(finish_flatten(&journal, root.to_str().unwrap()).is_err());
    recover_finish_flatten(&journal, root.to_str().unwrap()).unwrap();
    assert!(journal.state().runtime_record(&record_key).is_some());
    drop(journal);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn modified_directories_wait_for_merged_maintenance_but_topology_recovers() {
    let directory = std::env::temp_dir().join(format!("sunpack-event-action-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join("input.zip");
    std::fs::write(&file, b"archive").unwrap();
    let missing = directory.join("departed.zip");
    let mut signals = Signals::default();
    signals.changes.root_changed("root", [directory.clone(), file.clone(), missing.clone()]
        .map(|path| (path, PathChange { modified_only: true, ..PathChange::default() })));
    assert!(signals.changes.prepare(|_, _| false).is_some());
    assert!(!signals.changes.changed_roots["root"].contains(&directory));
    assert!(signals.changes.changed_roots["root"].contains(&file));
    for path in [directory.clone(), missing] {
        let mut signals = Signals::default();
        signals.changes.root_changed("root", [(path, PathChange::default())]);
        assert!(signals.changes.prepare(|_, _| false).is_none());
    }
    let mut signals = Signals::default();
    signals.changes.topology_changed("root".into());
    assert!(signals.changes.prepare(|_, _| false).is_none());
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn completion_opens_physical_container_with_one_or_many_retained_segments() {
    let container = Path::new(r"C:\output\carrier");
    let a = Path::new(r"C:\output\carrier\zip");
    let b = Path::new(r"C:\output\carrier\7z");
    let containers = HashMap::from([(a, container), (b, container)]);
    assert_eq!(completion_output_dirs([a], &containers), vec![container.to_path_buf()]);
    assert_eq!(completion_output_dirs([b, a], &containers), vec![container.to_path_buf()]);
    assert_eq!(completion_output_dirs([a], &HashMap::new()), vec![a.to_path_buf()]);
    assert!(completion_output_dirs([], &containers).is_empty());
}

#[test]
fn volume_notifications_select_only_matching_roots_and_preserve_arrivals() {
    let c = Path::new(r"C:\downloads");
    let d = Path::new(r"D:\downloads");
    let unc = Path::new(r"\\server\share");
    let mut changes = VolumeChanges::default();
    assert!(changes.is_empty());
    changes.add(1 << 2, false);
    assert!(changes.affects(c, true));
    assert!(!changes.arrives(c, true));
    assert!(!changes.affects(d, false));
    assert!(!changes.affects(unc, false));
    changes.add(1 << 3, true);
    changes.add(1 << 3, false);
    assert!(changes.affects(c, true));
    assert!(changes.arrives(d, true));
    let mut initial = VolumeChanges::default();
    initial.add(0, true);
    for root in [c, d, unc] {
        assert!(!initial.affects(root, true));
        assert!(initial.affects(root, false));
        assert!(initial.arrives(root, false));
    }
}

#[test]
fn password_notifications_do_not_reload_unrelated_configuration() {
    let files = HashMap::from([
        ("builtin_passwords.json".into(), (false, true)),
        ("sunpack_config.json".into(), (true, false)),
        // Both sources can live below a missing directory watched through
        // its ancestor: its appearance must rearm all affected sources.
        ("new-directory".into(), (true, true)),
    ]);
    let names = |name: &str| vec![name.to_owned()];
    assert_eq!(configuration_changes(&files, Some(&names("BUILTIN_PASSWORDS.JSON"))), (false, true));
    assert_eq!(configuration_changes(&files, Some(&names("sunpack_config.json"))), (true, false));
    assert_eq!(configuration_changes(&files, Some(&names("unrelated.tmp"))), (false, false));
    assert_eq!(configuration_changes(&files, Some(&names("new-directory"))), (true, true));
    assert_eq!(configuration_changes(&files, None), (true, true));
}

#[test]
fn native_burst_updates_activity_before_scheduler_drains_its_coalesced_signal() {
    use std::io::Write;
    use std::time::Duration;
    let marker = crate::test_support::temp_file("watch_capture", b"");
    let directory = marker.with_extension("work");
    let watched = directory.join("watched");
    fs::create_dir_all(&watched).unwrap();
    let root = Root { path: watched.clone(), output: None, recursive: true, deep: false, scanned: true };
    let state = directory.join("state");
    let journal = Arc::new(journal::Journal::open(&state, 7).unwrap());
    let catalog = Arc::new(NativeWatchCatalog::new(journal.state(), None));
    let hub = Arc::new(Hub::new());
    let source = watched.join("growing.zip");
    let activity = hub.activities.bind(&key(&source), quiet::Activity::default);
    let observer = RootObserver::start(&watched, &root, root.scope(&[], &[state.to_string_lossy().into_owned()]),
        &watched.join("builtin_passwords.json"), &hub, &journal, &catalog, false).unwrap();
    let mut file = fs::File::create(&source).unwrap();
    // Wait for each size to reach the shared activity without draining the
    // scheduler's signals. Cadence confirmation is tested with a controlled clock.
    for size in 1..=4 {
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        file.sync_data().unwrap();
        let signals = hub.signals.lock().unwrap();
        let (_signals, wait) = hub.wake.wait_timeout_while(signals, Duration::from_secs(5), |signals| {
            !signals.changes.paths.get(&source).and_then(|change| change.observation.as_deref())
                .is_some_and(|(_, value)| value.candidate.size == size)
                || activity.observed_size() != Some(size)
        }).unwrap();
        assert!(!wait.timed_out(), "observer did not publish size {size}");
    }
    let deadline = activity.deadline().unwrap();
    // No scheduler tick has run, so all wakes still occupy one path slot.
    let signals = std::mem::take(&mut *hub.signals.lock().unwrap());
    assert_eq!(signals.changes.changed_roots[&key(&watched)].len(), 1);
    let (candidate, _, _) = activity.probe(&source, None).unwrap();
    assert_eq!(activity.content_deadline(&candidate.unwrap(),
        Instant::now() + Duration::from_secs(60), windows::monotonic_seconds() + 60.0,
        false, false, None), deadline);
    drop(file);
    drop(observer);
    drop(signals);
    drop(catalog);
    drop(journal);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn business_root_routes_password_file_notification_only_to_password_reload() {
    let marker = crate::test_support::temp_file("watch_password_event", b"");
    let directory = marker.with_extension("work");
    let watched = directory.join("watched");
    fs::create_dir_all(&watched).unwrap();
    let root = Root { path: watched.clone(), output: None, recursive: true, deep: false, scanned: true };
    let state = directory.join("state");
    let journal = Arc::new(journal::Journal::open(&state, 7).unwrap());
    let hub = Arc::new(Hub::new());
    let passwords = watched.join("builtin_passwords.json");
    let observer = RootObserver::start(
        &watched, &root, root.scope(&[], &[state.to_string_lossy().into_owned()]), &passwords, &hub, &journal, &Arc::new(NativeWatchCatalog::new(journal.state(), None)), false,
    ).unwrap();
    fs::write(&passwords, b"{}").unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let signals = hub.wait(Some(deadline));
    assert!(signals.password_changed);
    assert!(signals.changes.changed_roots.is_empty());
    drop(observer);
    drop(journal);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn relative_roots_use_process_directory_not_roots_file_directory() {
    let marker = crate::test_support::temp_file("relative_watch_roots", b"");
    fs::write(&marker, "relative-input | child-output | false | true | false\n").unwrap();
    let roots = read_roots(&marker).unwrap();
    let input = std::env::current_dir().unwrap().join("relative-input");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].path, input);
    assert_eq!(roots[0].output.as_ref().unwrap(), &input.join("child-output"));
    fs::remove_file(marker).unwrap();
}

#[test]
fn open_error_dialog_does_not_retain_watch_state_across_restart() {
    let marker = crate::test_support::temp_file("watch_dialog_restart", b"");
    let directory = marker.with_extension("state");
    let journal = Arc::new(journal::Journal::open(&directory, 7).unwrap());
    let (opened_tx, opened_rx) = mpsc::channel();
    let (dismiss_tx, dismiss_rx) = mpsc::channel();
    let dialog = spawn_error_dialog(&journal, move || {
        opened_tx.send(()).unwrap();
        dismiss_rx.recv().unwrap();
        Err(io::Error::other("dialog unavailable"))
    }).unwrap();
    opened_rx.recv().unwrap();
    let old = Arc::downgrade(&journal);
    drop(journal); // scheduler has stopped, but the modal dialog is still open
    let released = old.upgrade().is_none();
    let restarted = journal::Journal::open(&directory, 7);
    // Release the simulated dialog even if reopening failed.
    dismiss_tx.send(()).unwrap();
    dialog.join().unwrap();
    assert!(released);
    drop(restarted.expect("an undismissed notice must not block watch start"));
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn published_policy_keeps_full_scan_obligation_across_retirement_and_scan_failures() {
    let mut progress = RootPolicyProgress::default();
    // An already-scanned root changes deep=false to deep=true. Retirement
    // fails after its new policy is published; the next compare is equal.
    assert!(progress.observe(true, false));
    assert!(progress.observe(false, false));
    progress.retirement = false; // the retry successfully retires old scope
    assert!(progress.checkpoint); // still must scan all roots, not pending only
    progress.checkpoint_finished(&Err(io::Error::other("checkpoint failed")));
    assert!(!progress.observe(false, false));
    assert!(progress.checkpoint);
    progress.checkpoint_finished(&Ok(()));
    assert!(!progress.checkpoint);
    assert!(progress.recovery); // a scan does not acknowledge pending/blocker recovery
    progress.recovery = false;
    assert!(!progress.observe(false, false));
    assert!(!progress.recovery);
}

#[test]
fn reload_scheduler_policy_excludes_only_tray_and_process_priority() {
    let previous = Config::parse(&json!({})).unwrap();
    let mut next = previous.clone();
    next.watch.tray_enabled = !previous.watch.tray_enabled;
    next.runtime.process_mode = config::ProcessMode::Background;
    assert!(previous != next);
    assert!(!scheduler_configuration_changed(&previous, &next));
    next.watch.toast_enabled = !previous.watch.toast_enabled;
    assert!(scheduler_configuration_changed(&previous, &next));
    next = previous.clone();
    next.cli.language = match previous.cli.language {
        crate::core::i18n::Language::En => crate::core::i18n::Language::Zh,
        crate::core::i18n::Language::Zh => crate::core::i18n::Language::En,
    };
    assert!(scheduler_configuration_changed(&previous, &next));
}

#[test]
fn content_batches_do_not_invalidate_topology_but_overflow_does() {
    let mut signals = Signals::default();
    for _ in 0..100 {
        signals.changes.root_changed("root-a", [(PathBuf::from("root-a/archive.zip"), PathChange::default())]);
    }
    assert!(signals.changes.topology_roots.is_empty());
    assert_eq!(signals.changes.changed_roots.len(), 1);
    // A content event batched after an overflow must not erase the rearm.
    signals.changes.topology_changed("root-a".into());
    signals.changes.root_changed("root-a", [(PathBuf::from("root-a/archive.zip"), PathChange::default())]);
    assert_eq!(signals.changes.topology_roots, HashSet::from(["root-a".to_owned()]));
    assert_eq!(signals.changes.changed_roots["root-a"].len(), 1);
}

#[test]
fn parent_subscription_is_shared_and_routes_only_affected_roots() {
    let temp = std::env::temp_dir().join(format!("sunpack-parent-sharing-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let roots = ["one", "two", "missing/child"].map(|name| Root {
        path: temp.join(name), output: None, recursive: false, deep: false, scanned: false,
    });
    let groups = parent_memberships(roots.iter());
    assert_eq!(groups.len(), 1); // one sentinel, not one per sibling root
    let (directory, members) = groups.values().next().unwrap();
    assert_eq!(members.len(), 3);
    assert_eq!(affected_parent_roots(members, Some(&[key(&directory.join("one"))])), vec![key(&roots[0].path)]);
    assert_eq!(affected_parent_roots(members, Some(&[key(&directory.join("missing"))])), vec![key(&roots[2].path)]);
    assert!(affected_parent_roots(members, Some(&[key(&directory.join("unrelated"))])).is_empty());
    assert_eq!(affected_parent_roots(members, None).len(), 3);
    assert!(parent_memberships(std::iter::empty::<&Root>()).is_empty());
    std::fs::remove_dir(&temp).unwrap();
}

#[test]
fn completion_blockers_follow_reloaded_roots_without_losing_recovery_routes() {
    let root = Root { path: r"C:\watch".into(), output: None,
        recursive: true, deep: false, scanned: false };
    let id = key(&root.path);
    let recursive = NativeDiscoveryScope::new(r"C:\watch".into(), None, Vec::new());
    let shallow = NativeDiscoveryScope::new(r"C:\watch".into(), Some(0), Vec::new());
    let candidate = WatchCandidateRow {
        path: r"C:\watch\sub\archive.part1.rar".into(), size: 42, mtime: 1.0,
        observation: crate::filesystem::WatchFileObservation {
            file_id: String::new(), change_usn: 0, change_reasons: None,
        },
    };
    // Both kinds can return from a request admitted before root reload.
    for status in ["failed_password", "suspended_missing_volume"] {
        let mut entry = observed_entry(&candidate, status, None);
        let roots = BTreeMap::from([(id.clone(), (root.clone(), recursive.clone()))]);
        assert!(route_blocker(&entry, &roots).is_some());
        assert!(route_blocker(&entry, &BTreeMap::new()).is_none());
        let roots = BTreeMap::from([(id.clone(), (root.clone(), shallow.clone()))]);
        assert!(route_blocker(&entry, &roots).is_none());
        // A different current root may legitimately own the old input.
        let sub = Root { path: r"C:\watch\sub".into(), ..root.clone() };
        let roots = BTreeMap::from([(key(&sub.path), (sub,
            NativeDiscoveryScope::new(r"C:\watch\sub".into(), None, Vec::new())))]);
        assert!(route_blocker(&entry, &roots).is_some());

        // Promoted recovery is intentionally allowed outside the ordinary
        // scan scope, but only while its original input root still exists.
        entry.path = r"D:\output\inner.zip".into();
        entry.failure_payload.insert("source_input_root".into(), json!(root.path));
        entry.failure_payload.insert("discovery_scope".into(), Value::Object(scope_record(
            &NativeDiscoveryScope::new(r"D:\output".into(), Some(0), Vec::new()))));
        entry.failure_payload.insert("password_scope_dir".into(), json!(r"C:\watch"));
        let roots = BTreeMap::from([(id.clone(), (root.clone(), shallow.clone()))]);
        assert!(route_blocker(&entry, &roots).unwrap().1.is_some());
        assert!(route_blocker(&entry, &BTreeMap::new()).is_none());
    }
}

#[test]
fn retained_regroup_handoff_persists_the_new_current_root() {
    let marker = crate::test_support::temp_file("watch_rerouted_recovery", b"");
    let directory = marker.with_extension("state");
    let root = Root { path: r"C:\watch".into(), output: None,
        recursive: true, deep: false, scanned: false };
    let root_id = key(&root.path);
    let roots = BTreeMap::from([(root_id.clone(), (root.clone(),
        NativeDiscoveryScope::new(r"C:\watch".into(), None, Vec::new())))]);
    let candidate = WatchCandidateRow {
        path: r"C:\watch\old\inner.part1.rar".into(), size: 42, mtime: 1.0,
        observation: crate::filesystem::WatchFileObservation {
            file_id: "retained-generation".into(), change_usn: 9, change_reasons: None,
        },
    };
    let recovery = Recovery {
        max_depth: None,
        scope: NativeDiscoveryScope::new(r"C:\watch\old".into(), Some(0), Vec::new()),
        password_scope: r"C:\passwords".into(),
    };
    let mut entry = Arc::new(observed_entry(&candidate, "suspended_missing_volume", None));
    let payload = &mut Arc::make_mut(&mut entry).failure_payload;
    payload.insert("discovery_scope".into(), Value::Object(recovery.record()));
    payload.insert("password_scope_dir".into(), json!(recovery.password_scope));
    let mut pending = Pending {
        root: watch_path_key(r"C:\watch\old"), candidate,
        quiet: quiet::Activity::default(), due: Instant::now(), force: true, recovery: None,
    };
    let due = pending.due;
    // Old A was removed; current B covers the retained file. This is the
    // exact fallback route that completion must hand to an existing queue.
    let (route, _) = route_blocker(&entry, &roots).unwrap();
    handoff_nested_blocker(&mut entry, &route, &roots[&route].0,
        recovery, Some(&mut pending));
    assert_eq!(pending.root, root_id);
    assert_eq!(pending.due, due);
    assert_eq!(pending.candidate.observation.change_usn, 9);
    let (current, _) = &roots[&pending.root];
    let recovery = pending.recovery.as_ref().unwrap();
    {
        let journal = journal::Journal::open(&directory, 7).unwrap();
        journal.commit(true, |state| {
            let candidate = &pending.candidate;
            let mut operations = state.pending_operations([(
                PendingObservation(candidate.path.clone(), candidate.size as i64,
                    candidate.mtime, candidate.observation.file_id.clone(),
                    candidate.observation.change_usn),
                current.path.to_string_lossy().into_owned(), Some(recovery.record()),
            )], pending.force, &recovery.password_scope.to_string_lossy(), true, None);
            operations.put_entry(Arc::clone(&entry));
            Ok(operations)
        }).unwrap();
    }
    {
        let journal = journal::Journal::open(&directory, 7).unwrap();
        let record = journal.state().pending(&pending.candidate.path).unwrap();
        assert_eq!(watch_path_key(&record.source_input_root), root_id);
        assert_eq!(record.change_usn, 9);
        assert_eq!(record.password_scope_dir, r"C:\passwords");
        let entry = journal.state().entry(&pending.candidate.path).unwrap();
        let (route, recovery) = route_blocker(&entry, &roots).unwrap();
        assert_eq!(route, root_id);
        assert!(recovery.unwrap().scope.contains(&pending.candidate.path));
    }
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn scan_diagnostics_do_not_override_watch_completion() {
    use crate::pipeline::{InputError, InputErrorKind};
    let root = Path::new(r"C:\watch\outer.zip");
    let nested = Path::new(r"C:\watch\outer\unreadable");
    let outputs = BTreeMap::from([
        (key(Path::new(r"C:\watch\outer")), root.to_string_lossy().into_owned()),
    ]);
    let mut errors = vec![InputError {
        path: nested.into(), message: "scan denied".into(),
        kind: InputErrorKind::FilesystemScan,
        failure: None,
        scan_operation: Some("read_dir".into()),
    }];
    // Scan diagnostics cannot override an archive result even when they
    // resolve to the same owner.
    assert!(completion_input_errors(&errors, &outputs, &HashMap::new(), &[]).is_empty());
    errors.push(InputError {
        path: nested.into(),
        message: "embedded read failed".into(),
        kind: InputErrorKind::EmbeddedDiscovery,
        failure: Some(Box::new(crate::pipeline::Failure::new(FailureKind::FilesystemError, "embedded read failed"))),
        scan_operation: None,
    });
    let paths = completion_input_errors(&errors, &outputs, &HashMap::new(), &[]);
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[&key(root)].failure.as_ref().unwrap().kind, FailureKind::FilesystemError);
    assert_eq!(paths[&key(nested)].message, "embedded read failed");
    // The projection borrows; CLI and diagnostics retain the original data.
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].message, "scan denied");

    let inputs = [r"C:\watch\first\series.001", r"C:\watch\second\series.001"]
        .map(|path| WatchCandidateRow {
            path: path.into(), size: 0, mtime: 0.0,
            observation: crate::filesystem::WatchFileObservation {
                file_id: String::new(), change_usn: 0, change_reasons: None,
            },
        });
    let errors = [
        InputError {
            path: inputs[1].path.as_str().into(), message: "admitted source".into(),
            kind: InputErrorKind::EmbeddedDiscovery, failure: None,
            scan_operation: None,
        },
        InputError {
            path: r"C:\watch\series.002".into(), message: "residual peer".into(),
            kind: InputErrorKind::EmbeddedDiscovery, failure: None,
            scan_operation: None,
        },
    ];
    let paths = completion_input_errors(&errors, &BTreeMap::new(), &HashMap::new(), &inputs);
    assert_eq!(paths[&watch_path_key(&inputs[0].path)].message, "residual peer");
    assert_eq!(paths[&watch_path_key(&inputs[1].path)].message, "admitted source");
}

pub(super) fn completion_archive(path: &str, depth: usize, kind: Option<FailureKind>) -> ArchiveResult {
    ArchiveResult {
        path: path.into(), format: "zip".into(), output: None,
        failure: kind.map(|kind| crate::pipeline::Failure::new(kind, format!("{kind:?}"))),
        files: 0, bytes: 0, encrypted: None, depth, offset: 0, end_offset: None,
        volume_completeness: None, volume_attempts: None, source_paths: vec![path.into()],
        password: None, discovery_source: crate::pipeline::DiscoverySource::Embedded,
        partial: false, retained: false, recovered_complete_files: 0,
          scan_layout: Default::default(),
    }
}

#[test]
fn completion_routes_nested_terminal_failures_to_the_canonical_top_level_group() {
    let head = Path::new(r"C:\watch\outer.part1.zip");
    let alias = Path::new(r"C:\watch\outer.part2.zip");
    let other = Path::new(r"C:\watch\other.zip");
    let group = Arc::new(SourceGroup {
        path: head.into(),
        members: vec![head.to_string_lossy().into(), alias.to_string_lossy().into()],
    });
    let groups = HashMap::from([(key(head), Arc::clone(&group)), (key(alias), group)]);
    let outputs = BTreeMap::from([
        (key(Path::new(r"C:\watch\outer")), alias.to_string_lossy().into_owned()),
        (key(Path::new(r"C:\watch\other")), other.to_string_lossy().into_owned()),
    ]);
    let mut outer = completion_archive(head.to_str().unwrap(), 1, None);
    outer.source_paths.push(alias.into());
    let mut outcome = Outcome::default();
    outcome.archives = vec![outer, completion_archive(other.to_str().unwrap(), 1, None),
        completion_archive(r"C:\watch\outer\inner.zip", 2, Some(FailureKind::Damaged))];
    let failures = outcome.input_failures();
    let (projected, _) = completion_archives(&outcome, &outputs, &groups, &failures);
    assert_eq!(projected[&key(head)].len(), 2);
    assert_eq!(projected[&key(alias)].len(), 1);
    assert_eq!(completion_failed_archive(&projected[&key(head)], &failures).unwrap().failure.as_ref().unwrap().kind, FailureKind::Damaged);
    assert!(completion_failed_archive(&projected[&key(other)], &failures).is_none());
    assert!(output_owner(&outputs, &key(Path::new(r"C:\watch\outer-other\inner.zip"))).is_none());
    // Error projection uses this same durable owner even after its nested
    // source disappears. No new filesystem observation is involved.
    assert_eq!(output_owner(&outputs, &key(Path::new(r"C:\watch\outer\gone.zip"))), alias.to_str());
}

#[test]
fn admitted_password_scope_survives_family_head_retry_and_retained_recovery() {
    use crate::watch_store::{NativeWatchState, NativeWatchOperations, PendingObservation};
    let state = NativeWatchState::new();
    let a = Path::new(r"C:\watch\A");
    let b = Path::new(r"C:\watch\B");
    // The admitted path, not the eventual family head, fixes all Watch
    // input forms. Different directories cannot share the dispatch key.
    for filename in ["single.zip", "family.part2.rar", "family.7z.002", "family.z01", "wrapped.enc"] {
        let tail = b.join(filename);
        let head = a.join(filename);
        assert_eq!(candidate_password_scope(&state, tail.to_str().unwrap(), None), b);
        assert_eq!(candidate_password_scope(&state, head.to_str().unwrap(), None), a);
    }
    let path = r"C:\watch\A\family.part1.rar";
    let candidate = WatchCandidateRow {
        path: path.into(), size: 42, mtime: 1.0,
        observation: crate::filesystem::WatchFileObservation {
            file_id: String::new(), change_usn: 0, change_reasons: None,
        },
    };
    let passwords = crate::core::passwords::PasswordSnapshot::default();
    let user_signature = user_password_signature(&[]);
    for kind in [FailureKind::PasswordRequired, FailureKind::MissingVolume] {
        let mut outcome = Outcome::default();
        outcome.archives.push(completion_archive(path, 1, Some(kind)));
        let failures = outcome.input_failures();
        let failure = &failures[&crate::path_keys::path_key(path)];
        let entry = make_blocker(&candidate, "blocked", failure, None,
            &passwords, &user_signature, None, None, b);
        assert_eq!(entry.failure_payload["password_scope_dir"], json!(b));
        if failure.password.is_some() {
            assert_eq!(entry.failure_payload["password_signature"],
                json!(password_source_signature(&user_signature, &passwords.scope_signature(b))));
        }
        let mut operations = NativeWatchOperations::empty();
        operations.put_entry(entry);
        state.apply(&operations);
        // A directory-password update must compare B's signature, and
        // the subsequent retry must retain B even though its path is A.
        assert_eq!(candidate_password_scope(&state, path, None), b);
    }
    let retained = Recovery {
        max_depth: None,
        scope: NativeDiscoveryScope::new(r"C:\output\nested".into(), Some(0), Vec::new()),
        password_scope: b.to_owned(),
    };
    assert_eq!(candidate_password_scope(&state, r"C:\output\nested\inner.zip", Some(&retained)), b);
    let pending_path = r"C:\watch\A\pending.zip";
    let operations = state.pending_operations([(
        PendingObservation(pending_path.into(), 42, 1.0, String::new(), 0),
        r"C:\watch".into(), None,
    )], false, b.to_str().unwrap(), false, None);
    state.apply(&operations);
    assert_eq!(candidate_password_scope(&state, pending_path, None), b);
    // An existing retry entry takes precedence over pending, as in main.
    let mut entry = observed_entry(&candidate, "failed_password", None);
    entry.path = pending_path.into();
    entry.failure_payload.insert("password_scope_dir".into(), json!(a));
    let mut operations = NativeWatchOperations::empty();
    operations.put_entry(Arc::new(entry));
    state.apply(&operations);
    assert_eq!(candidate_password_scope(&state, pending_path, None), a);
}

#[test]
fn retained_carrier_segments_share_blockers_without_hiding_independent_terminal_children() {
    let owner = Path::new(r"C:\Watch\outer.zip");
    let retained_path = r"C:\Watch\carrier.bin";
    let mut partial = completion_archive(retained_path, 2, Some(FailureKind::MissingVolume));
    partial.partial = true;
    let terminal = completion_archive(retained_path, 2, Some(FailureKind::Damaged));
    let blocked = completion_archive(retained_path, 2, Some(FailureKind::PasswordRequired));
    let mut outcome = Outcome::default();
    outcome.archives = vec![completion_archive(owner.to_str().unwrap(), 1, None), partial, terminal, blocked];
    let outputs = BTreeMap::from([
        (key(Path::new(retained_path)), owner.to_string_lossy().into_owned()),
        (key(Path::new(r"C:\Watch\outer")), owner.to_string_lossy().into_owned()),
    ]);
    let failures = outcome.input_failures();
    let carrier = &failures[&crate::path_keys::path_key(retained_path)];
    assert!(carrier.retryable());
    assert!(carrier.password.is_some() && carrier.missing.is_some());
    assert_eq!(carrier.failure().unwrap().kind, FailureKind::MissingVolume);
    let candidate = WatchCandidateRow {
        path: retained_path.into(), size: 42, mtime: 1.0,
        observation: crate::filesystem::WatchFileObservation {
            file_id: String::new(), change_usn: 0, change_reasons: None,
        },
    };
    let passwords = crate::core::passwords::PasswordSnapshot::default();
    let entry = make_blocker(&candidate, "carrier blocked", carrier, None,
        &passwords, &user_password_signature(&[]), None, None, Path::new(retained_path).parent().unwrap());
    assert_eq!(entry.status, "suspended_missing_volume");
    assert_eq!(entry.failure_payload["blockers"], json!(["missing_volume", "password"]));
    assert_eq!(entry.failure_payload["password_signature"],
        json!(password_source_signature(&user_password_signature(&[]), &passwords.scope_signature(Path::new(retained_path).parent().unwrap()))));
    let retry_paths = outcome.archives.iter().filter(|archive| nested_retry(archive, &failures))
        .map(|archive| key(&archive.path)).collect::<HashSet<_>>();
    assert_eq!(retry_paths.len(), 1, "one physical retry retains all logical receipts");
    let (projected, _) = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
    assert!(completion_failed_archive(&projected[&key(owner)], &failures).is_none());
    // A terminal failure in another physical child still fails the owner.
    outcome.archives.push(completion_archive(r"C:\Watch\outer\broken.zip", 2, Some(FailureKind::Unsupported)));
    let failures = outcome.input_failures();
    let (projected, _) = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
    assert_eq!(completion_failed_archive(&projected[&key(owner)], &failures).unwrap().failure.as_ref().unwrap().kind, FailureKind::Unsupported);
    outcome.archives.pop();
    // All-accepted partial evidence is successful, not a new blocker.
    outcome.archives.truncate(2);
    let failures = outcome.input_failures();
    let (projected, _) = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
    assert!(completion_failed_archive(&projected[&key(owner)], &failures).is_none());
    assert!(!failures[&crate::path_keys::path_key(retained_path)].retryable());
}

#[test]
fn nested_retry_handoff_keeps_descendant_checkpoints_after_owner_retirement() {
    // The carrier receipt alone cannot prevent a nested accepted partial
    // from being extracted again. Exercise durable handoff and reopen,
    // while ensuring an unrelated output is not kept under this blocker.
    let owner = crate::test_support::temp_file("watch_recovery_handoff", b"outer archive");
    let root = owner.with_extension("state");
    let segment = root.join("retained");
    let child_output = segment.join("nested");
    let unrelated = root.join("unrelated");
    fs::create_dir_all(&child_output).unwrap();
    fs::create_dir_all(&unrelated).unwrap();
    let carrier = root.join("carrier.bin");
    let nested = segment.join("nested.zip");
    fs::write(&carrier, b"carrier archive").unwrap();
    fs::write(&nested, b"nested archive").unwrap();
    let receipt = |source: &Path, output: &Path, partial: bool| {
        let input = crate::io::archive_state::ArchiveInput::file(
            source.to_string_lossy().into_owned(), "zip".into(), "nested".into(),
        );
        serde_json::from_value::<crate::pipeline::InputCheckpoint>(json!({
            "schema_version":1,"carrier":source,
            "input":input,
            "sources":[{"path":source,"generation":capture_file_generation(source).unwrap()}],
            "output":output,
            "container":null,"files":1,"bytes":4,"encrypted":false,"discovery_source":"embedded",
            "failure":partial.then(|| json!({
                "partial":true,"password_signature":null,
                "failure":{"kind":"damaged","message":"accepted recovery"},
                "complete_files":1})),
        })).unwrap()
    };
    let checkpoints = vec![receipt(&carrier, &segment, false), receipt(&nested, &child_output, true),
        receipt(&owner, &unrelated, false)];
    let owner_text = owner.to_str().unwrap();
    let carrier_text = carrier.to_str().unwrap();
    {
        let journal = journal::Journal::open(&root, 7).unwrap();
        journal.commit(true, |state| {
            Ok(state.pending_operations(
                [(PendingObservation(owner_text.into(), 13, 1.0, String::new(), 0), String::new(), None)],
                false, "", false, None,
            ))
        }).unwrap();
        let mut blocker = crate::watch_store::EntryRecord {
            path: carrier_text.into(), size: 15, mtime: 1.0, file_id: String::new(),
            change_usn: 0, status: "failed_password".into(), last_error: "blocked".into(),
            attempt_count: 1, failure_kind: "password_required".into(),
            failure_stage: "extraction".into(),
            failure_payload: json!({"blockers":["password"]}).as_object().unwrap().clone(),
            last_attempt_at: 1.0,
        };
        blocker.failure_payload.insert("input_checkpoints".into(), serde_json::to_value(
            recovery_checkpoints(&checkpoints, &[carrier.clone()])).unwrap());
        journal.commit(true, |_| {
            let mut operations = NativeWatchOperations::empty();
            operations.put_entry(Arc::new(blocker));
            operations.extend(NativeWatchOperations::finish_pending(owner_text, None));
            Ok(operations)
        }).unwrap();
        journal.flush().unwrap();
    }
    {
        let journal = journal::Journal::open(&root, 7).unwrap();
        assert!(input_checkpoints(journal.state().entry(owner_text).as_deref()).next().is_none());
        let retained = input_checkpoints(journal.state().entry(carrier_text).as_deref()).collect::<io::Result<Vec<_>>>().unwrap();
        assert_eq!(retained.len(), 2);
        let nested_receipt = retained.iter()
            .find(|checkpoint| checkpoint.carrier() == nested)
            .unwrap();
        let nested_receipt = serde_json::to_value(nested_receipt).unwrap();
        assert_eq!(nested_receipt["failure"]["failure"]["kind"], "damaged");
        assert_eq!(nested_receipt["failure"]["partial"], true);
        assert_eq!(nested_receipt["failure"]["complete_files"], 1);
        assert!(!retained.iter().any(|checkpoint| checkpoint.output() == unrelated));
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(owner).unwrap();
}

#[test]
fn configured_passwords_participate_in_watch_blocker_signatures() {
    let builtin = "a55be77812b08557859dab8291a7ac45";
    assert_eq!(password_source_signature(&user_password_signature(&[]), builtin), "1dc1efb66b9a5c864c8abd4d5e769223");
    assert_ne!(password_source_signature(&user_password_signature(&["new password".into()]), builtin),
        password_source_signature(&user_password_signature(&[]), builtin));
    assert_ne!(password_source_signature(&user_password_signature(&["new password".into()]), builtin),
        password_source_signature(&user_password_signature(&["new password".into()]), "changed builtin"));
}

#[test]
fn admission_round_is_bounded_ordered_and_leaves_backlog_untouched() {
    let now = Instant::now();
    let old = now - std::time::Duration::from_secs(1);
    let mut due = (0..8).map(|index| ((old, format!("input-{index}")), ()))
        .collect::<BTreeMap<_, _>>();
    due.insert((now + std::time::Duration::from_secs(1), "future".into()), ());
    let original = due.clone();
    let selected = due_admissions(&due, now, 2, |path| path != "input-0" && path != "input-2");
    assert_eq!(selected.iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>(),
        ["input-1", "input-3"]);
    assert_eq!(due, original, "selection must not remove durable backlog or change its order");
    assert!(due_admissions(&due, now, 0, |_| panic!("full window probed an input")).is_empty());
    for entry in selected { due.remove(&entry); }
    assert_eq!(due_admissions(&due, now, 2, |path| path != "input-0" && path != "input-2")
        .iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>(), ["input-4", "input-5"]);
    assert_eq!(due_admissions(&due, now, usize::MAX, |_| true).len(), 6);
}

#[test]
fn drain_wakes_after_stop_and_panicking_batch_completion() {
    let hub = Arc::new(Hub::new());
    hub.stop();
    let worker_hub = Arc::clone(&hub);
    let waiter = thread::spawn(move || {
        let completed = worker_hub.wait_drain();
        assert_eq!(completed.completed, ["panicking-batch"]);
    });
    // Exercise the actual owned-request boundary, not an OS-thread mock:
    // a blocked final report must not block another request, and unwinding
    // its callback must still wake Watch drain after stop.
    struct Silent;
    impl Observer for Silent { fn notify(&self, _: Event) {} }
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let cancelled_request = || {
        let mut request = Request::new(Vec::new(), Mode::Extract);
        request.origin = Origin::Watch;
        request.cancel.cancel();
        request
    };
    let completion = BatchCompletion { hub: Arc::clone(&hub), batch: Some("panicking-batch".into()) };
    let (entered, entering) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let failed = engine.submit(cancelled_request(), Arc::new(Silent), move |result| {
        assert!(crate::io::cancellation::is_cancellation(&result.unwrap_err()));
        entered.send(()).unwrap();
        released.recv().unwrap();
        panic!("a batch failed before returning its result");
    });
    failed.on_ready(move || drop(completion));
    entering.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(!failed.is_finished());
    let (progress, progressed) = mpsc::channel();
    let independent = engine.submit(cancelled_request(), Arc::new(Silent), move |_| {
        progress.send(()).unwrap();
    });
    let responsive = progressed.recv_timeout(std::time::Duration::from_secs(5));
    release.send(()).unwrap();
    assert!(failed.join().is_err());
    independent.join().unwrap();
    responsive.expect("a blocked completion report held the shared request driver");
    waiter.join().unwrap();
}

#[test]
fn empty_watch_defers_rules_until_first_root_activation() {
    let mut raw: Value = serde_json::from_str(include_str!("../../../../../../sunpack_advanced_config.json")).unwrap();
    raw["filesystem"]["scan_filters_enabled"] = json!(true);
    raw["filesystem"]["scan_filters"] = json!([{
        "name": "blacklist", "enabled": true,
        "full_names": [{"value": "[", "regex": true}]
    }]);
    let config = Config::parse(&raw).unwrap();
    assert!(watch_scan_options(&config, false).unwrap().is_none());
    // Root activation compiles the same ordinary rules for normal and
    // all-deep configurations; removing the last root disables compilation.
    assert!(watch_scan_options(&config, true).is_err());
    assert!(watch_scan_options(&config, false).unwrap().is_none());
    raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = json!("valid");
    assert!(watch_scan_options(&Config::parse(&raw).unwrap(), true).unwrap().is_some());
}

#[test]
fn policy_drain_preserves_next_generation_notifications_without_applying_passwords() {
    use std::future::Future;

    let hub = Hub::new();
    let (reload, reload_result) = command_reply();
    hub.queue_reload(Some(reload));
    hub.update(|signals| {
        signals.changes.root_changed("old-root", [(PathBuf::from("archive.zip"), PathChange::default())]);
        signals.password_changed = true;
    });
    hub.batch_completed("old-request".into());
    let drained = hub.wait_drain();
    assert_eq!(drained.completed, ["old-request"]);
    assert!(!drained.password_changed);
    assert!(!hub.stopped.load(Ordering::Acquire));
    let pending = hub.wait(None);
    assert!(pending.reload);
    assert!(pending.password_changed);
    assert!(pending.changes.changed_roots.contains_key("old-root"));
    let mut context = std::task::Context::from_waker(Waker::noop());
    let mut reload_result = std::pin::pin!(reload_result.wait());
    assert!(reload_result.as_mut().poll(&mut context).is_pending());
    pending.reload_waiters.into_iter().next().unwrap().send(Ok(true));
    assert!(block_on(reload_result).unwrap());
}

#[test]
fn concurrent_stop_keeps_the_draining_generation_visible_to_start() {
    use std::future::Future;
    use std::task::Context;
    let watch = Watch::new(Arc::new(|| {}));
    let hub = Arc::new(Hub::new());
    let completion = Arc::new(RunCompletion::default());
    let finished = FinishRun(Arc::clone(&completion));
    let worker_hub = Arc::clone(&hub);
    let (release, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        worker_hub.wait(None);
        released.recv().unwrap();
        finished.0.complete(&Ok(()));
        Ok(())
    });
    watch.generation.store(4, Ordering::Relaxed);
    *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, completion });
    let mut first = Box::pin(watch.stop_async());
    let mut second = Box::pin(watch.stop_async());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    // A missing worker path also proves start never tries to spawn/handshake.
    let start = block_on(watch.start_async(Path::new("."),
        Arc::new(Engine::new(PathBuf::from("unused-worker"))), false)).unwrap();
    assert_eq!(start, json!({"running":true,"started":false,"generation":4}));
    release.send(()).unwrap();
    for response in [block_on(first).unwrap(), block_on(second).unwrap()] {
        assert_eq!(response, json!({"running":false,"stopped":true,"generation":4}));
    }
    assert!(!watch.is_running());
}

#[test]
fn asynchronous_reload_and_stop_release_the_shared_control_driver() {
    let watch = Arc::new(Watch::new(Arc::new(|| {})));
    let hub = Arc::new(Hub::new());
    let completion = Arc::new(RunCompletion::default());
    let finished = FinishRun(Arc::clone(&completion));
    let worker_hub = Arc::clone(&hub);
    let (entered, entering) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        let pending = worker_hub.wait(None);
        entered.send(()).unwrap();
        released.recv().unwrap();
        // A disappearing service must wake an async reply even without send.
        drop(pending);
        worker_hub.wait(None);
        finished.0.complete(&Ok(()));
        Ok(())
    });
    *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, completion });
    let engine = Engine::new(PathBuf::from("unused-worker"));
    let caller = Arc::clone(&watch);
    let reload = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move { caller.reload_async().await }).unwrap();
    entering.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    let caller = Arc::clone(&watch);
    let stop = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move { caller.stop_async().await }).unwrap();
    let (progress, progressed) = mpsc::channel();
    let independent = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move { progress.send(()).unwrap(); }).unwrap();
    let responsive = progressed.recv_timeout(std::time::Duration::from_secs(5));
    release.send(()).unwrap();
    independent.join().unwrap();
    assert_eq!(reload.join().unwrap().unwrap()["reloaded"], false);
    assert_eq!(stop.join().unwrap().unwrap()["stopped"], true);
    responsive.expect("Watch lifecycle wait blocked another control request");
}

#[test]
fn root_apply_ack_accepts_observer_first_noop_but_not_apply_failure() {
    let watch = Watch::new(Arc::new(|| {}));
    let hub = Arc::new(Hub::new());
    let worker_hub = Arc::clone(&hub);
    let completion = Arc::new(RunCompletion::default());
    let finished = FinishRun(Arc::clone(&completion));
    let worker = thread::spawn(move || {
        let finished = finished;
        for result in [Ok(false), Ok(false), Err(io::Error::other("apply failed")), Err(io::Error::other("apply failed"))] {
            let signals = worker_hub.wait(None);
            assert_eq!(signals.reload_waiters.len(), 1);
            signals.reload_waiters.into_iter().next().unwrap().send(result);
        }
        worker_hub.wait(None);
        finished.0.complete(&Ok(()));
        Ok(())
    });
    *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, completion });
    // FileObserver already applied the write: explicit reload is a
    // successful no-op, but the changed root command was still applied.
    assert_eq!(block_on(watch.root_change_status(true, true)).unwrap(), Some((true, 0)));
    assert_eq!(watch.reload().unwrap()["reloaded"], false);
    assert_eq!(block_on(watch.root_change_status(true, true)).unwrap_err().to_string(), "apply failed");
    assert_eq!(watch.reload().unwrap()["reloaded"], false);
    assert_eq!(block_on(watch.root_change_status(true, false)).unwrap(), Some((false, 0)));
    watch.stop().unwrap();
}

#[test]
fn stopping_watch_allows_worker_foreground_callbacks() {
    let watch = Arc::new(Watch::new(Arc::new(|| {})));
    let hub = Arc::new(Hub::new());
    let worker_hub = Arc::clone(&hub);
    let worker_watch = Arc::clone(&watch);
    let completion = Arc::new(RunCompletion::default());
    let finished = FinishRun(Arc::clone(&completion));
    let worker = thread::spawn(move || {
        let finished = finished;
        worker_hub.wait(None);
        worker_watch.foreground_finished(|| {});
        finished.0.complete(&Ok(()));
        Ok(())
    });
    *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, completion });
    let (send, receive) = mpsc::channel();
    let stop = thread::spawn(move || {
        let _ = send.send(watch.stop());
    });
    receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap();
    stop.join().unwrap();
}

#[test]
fn physical_completion_consumes_claimed_siblings_before_release_reobservation() {
    let group = Arc::new(SourceGroup { path: "split.001".into(),
        members: vec!["split.001".into(), "split.002".into(), "split.003".into()] });
    let groups: HashMap<_, _> = group.members.iter()
        .map(|path| (watch_path_key(path), Arc::clone(&group))).collect();
    let now = Instant::now();
    let mut pending = HashMap::new();
    let mut due = BTreeMap::new();
    let mut unpublished = HashSet::new();
    for (index, path) in group.members.iter().enumerate().skip(1) {
        let id = watch_path_key(path);
        let deadline = now + std::time::Duration::from_secs(index as u64);
        pending.insert(id.clone(), Pending { root: "root".into(),
            candidate: WatchCandidateRow { path: path.clone(), size: 42, mtime: 1.0,
                observation: crate::filesystem::WatchFileObservation {
                    file_id: String::new(), change_usn: index as i64, change_reasons: None,
                } },
            quiet: quiet::Activity::default(), due: deadline, force: false, recovery: None,
        });
        due.insert((deadline, id.clone()), ());
        unpublished.insert(id);
    }
    for pending in pending.values_mut() {
        for at in [0.0, 5.0, 10.0, 15.0, 20.0] {
            pending.quiet.observe(at, false, false, true);
        }
        pending.quiet.end_phase();
    }
    let changed = watch_path_key("split.003");
    let claims = groups.keys().map(|path| (path.clone(), Arc::<str>::from("owner"))).collect();
    park_claimed_deadlines(&pending, &mut due, &claims, groups.keys().cloned().collect());
    assert!(due.is_empty());
    assert_eq!(pending.len(), 2); // observations survive until generation-safe completion
    // A probe may publish just before the worker claims its captured
    // generation. Completion must not consume that newer pending value.
    let mut captured: HashMap<_, _> = pending.iter()
        .map(|(id, pending)| (id.clone(), Some(pending.candidate.clone()))).collect();
    pending.get_mut(&changed).unwrap().candidate.observation.change_usn += 1;
    pending.get_mut(&changed).unwrap().candidate.size += 1;
    let mut inputs = Vec::new();
    let mut trackers = HashMap::new();
    consume_claimed_pending(&mut pending, &mut due, &mut unpublished, &groups, &captured, &mut inputs, &mut trackers);
    let tracker = trackers.remove(&watch_path_key("split.002")).unwrap();
    let learned = tracker.summary().0;
    tracker.observe(23.5, false, false, true);
    tracker.observe(24.5, false, false, true);
    assert_eq!(tracker.summary().2, 5.0);
    assert_eq!(tracker.summary().0, learned);
    assert!(trackers.is_empty());
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].path, "split.002");
    assert_eq!(pending.len(), 1);
    assert_eq!(unpublished, HashSet::from([changed.clone()]));
    assert!(due.is_empty());
    let queued = pending.get(&changed).unwrap();
    // The same sealed observation is also the baseline for dirty siblings
    // with no catalog/pending history. Same generation is not new work.
    let sealed = captured.remove(&changed).unwrap().unwrap();
    assert!(!quiet::changed(&sealed, &sealed));
    assert!(quiet::changed(&sealed, &queued.candidate));
    due.insert((queued.due, changed.clone()), ());
    // A late claim wake cannot remove the now-released new generation.
    park_claimed_deadlines(&pending, &mut due, &HashMap::new(), HashSet::from([changed.clone()]));
    assert_eq!(due.len(), 1);
    assert_eq!(due.keys().next().unwrap().1, changed);
}

#[test]
fn admission_counts_unfinished_candidates_not_batches_or_claimed_members() {
    let marker = crate::test_support::temp_file("watch_candidate_budget", b"");
    let base = marker.with_extension("dir");
    fs::create_dir_all(&base).unwrap();
    let journal = Arc::new(journal::Journal::open(&base.join("state"), 7).unwrap());
    let settings = Arc::new(Config::default());
    let mut scheduler = Scheduler {
        candidate_diagnostics: CandidateDiagnostics::default(), admission_checkpoint: None,
        cwd: base.clone(), root_file: base.join(ROOTS_FILE),
        roots: BTreeMap::new(), available_roots: HashSet::new(),
        user_password_signature: user_password_signature(&settings.user_passwords), settings,
        engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
        catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), recovery_ids: HashMap::new(), journal,
        options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
        deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
        passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
        root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
        parent_observers: HashMap::new(),
        dependency_observers: HashMap::new(), config_observers: Vec::new(),
        volume_checks: HashMap::new(),
        pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
        active: HashMap::new(), active_paths: HashMap::new(), tray_enabled: false,
        tray: None, monitor: None, toast: None, cache_deadline: None,
        external: Arc::default(), broker_lease: None,
    };
    let limit = scheduler.admission_available();
    let driver = crate::pipeline::Scheduler::new();
    let batch = |id, names: Vec<String>, failed: bool| {
        let cancel = Cancellation::new();
        let request = driver.submit(id, Origin::Watch, &cancel, move |_| Box::pin(async move {
            Completed { cancelled: !failed,
                result: Err(io::Error::other("test request settled")),
                 outputs: BTreeMap::new() }
        }));
        Active {
            max_depth: usize::MAX,
            deep: false, root: String::new(), recovery: None, password_scope: base.clone(),
            passwords: Arc::default(),
            inputs: names.into_iter().map(|path| (watch_path_key(&path), WatchCandidateRow {
                path, size: 1, mtime: 1.0,
                observation: crate::filesystem::WatchFileObservation {
                    file_id: String::new(), change_usn: 0, change_reasons: None,
                },
            })).collect(),
            quiet: HashMap::new(), dirty: HashSet::new(), cancel,
            groups: Arc::default(), claimed: Arc::default(), toast: None, request,
        }
    };
    let names = (0..limit).map(|index| base.join(format!("{index}.zip")).to_string_lossy().into_owned()).collect::<Vec<_>>();
    let reserved: Vec<_> = names[..3].iter().map(PathBuf::from).collect();
    for path in &reserved { fs::write(path, b"archive").unwrap(); }
    let cancel = Cancellation::new();
    let reservation = block_on(scheduler.engine.reserve_watch_inputs_for_test(1, &reserved, &cancel)).unwrap();
    let blocked = |engine: &Engine, path: &Path| {
        block_on(engine.reserve_foreground_async(&[path.to_owned()], &cancel))
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    };
    assert!(blocked(&scheduler.engine, &reserved[0]));
    scheduler.active_paths.extend(names.iter().map(|path| (watch_path_key(path), Arc::from("first"))));
    scheduler.active.insert("first".into(), batch(1, names.clone(), false));
    assert_eq!(scheduler.admission_available(), 0, "one full batch occupies the whole candidate window");
    assert!(scheduler.next_admission().is_none());
    // A completed head owns two admitted aliases; a third discovered
    // member never consumed an admission slot. Remaining siblings stay live.
    let head = Path::new(&names[0]);
    let discovered = base.join("not-admitted.002");
    scheduler.hub.claims.lock().unwrap().insert(key(&discovered), Arc::from("first"));
    assert_eq!(scheduler.admission_available(), 0, "discovered physical claims do not consume candidate slots");
    let group = Arc::new(SourceGroup { path: head.into(),
        members: vec![names[0].clone(), names[1].clone(), discovered.to_string_lossy().into_owned()] });
    let root = || RootCompleted {
        request: 1,
        reply: Arc::default(), batch: "first".into(), id: 1, path: head.into(),
        groups: group.members.iter().map(|member| (watch_path_key(member), Arc::clone(&group))).collect(),
        completed: Completed { cancelled: false, result: Ok(Outcome::default()),
             outputs: BTreeMap::new() },
    };
    scheduler.complete_root(root()).unwrap();
    assert_eq!(scheduler.admission_available(), 2);
    assert_eq!(scheduler.active["first"].inputs.len(), limit - 2);
    drop(block_on(scheduler.engine.reserve_foreground_async(&reserved[..2], &cancel))
        .expect("the completed root and its final alias must be immediately available to the foreground"));
    assert!(blocked(&scheduler.engine, &reserved[2]), "the other root is still active");
    scheduler.complete_root(root()).unwrap();
    assert_eq!(scheduler.admission_available(), 2, "repeated root notification cannot refund twice");
    scheduler.active_paths.extend(names[..2].iter().map(|path| (watch_path_key(path), Arc::from("second"))));
    scheduler.active.insert("second".into(), batch(2, vec![names[0].clone(), names[1].clone()], true));
    assert_eq!(scheduler.admission_available(), 0, "second batch consumes only the freed candidate slots");
    scheduler.complete_requests(vec!["first".into()]).unwrap();
    assert_eq!(scheduler.admission_available(), limit - 2, "cancellation returns only unfinished siblings");
    scheduler.complete_requests(vec!["second".into()]).unwrap();
    assert_eq!(scheduler.admission_available(), limit, "failed batch returns all remaining owners");
    scheduler.complete_requests(vec!["second".into()]).unwrap();
    assert_eq!(scheduler.admission_available(), limit);
    // A persistence error in the first completion must not abandon the
    // following cancellation projection (which releases its physical claims).
    scheduler.active_paths.insert(watch_path_key(&names[0]), Arc::from("faulted"));
    scheduler.active_paths.insert(watch_path_key(&names[1]), Arc::from("cancelled"));
    scheduler.active.insert("faulted".into(), batch(3, vec![names[0].clone()], true));
    scheduler.active.insert("cancelled".into(), batch(4, vec![names[1].clone()], false));
    scheduler.journal.fail_for_test();
    assert!(scheduler.complete_requests(vec!["faulted".into(), "cancelled".into()]).is_err());
    assert!(scheduler.active_paths.is_empty(), "failed sibling suppressed cancellation projection");
    scheduler.options = None;
    assert_eq!(scheduler.admission_available(), 0);
    drop(reservation);
    drop(scheduler);
    fs::remove_dir_all(base).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn root_completion_wakes_watch_and_drain_before_batch_exit() {
    // A batch completion test cannot detect a root-only wake being ignored
    // while another native task is still running.
    fn root() -> RootCompleted {
        RootCompleted { request: 1, reply: Arc::default(), batch: "batch".into(), id: 1, path: "a.zip".into(), groups: HashMap::new(),
            completed: Completed { cancelled: false, result: Ok(Outcome::default()),
                 outputs: BTreeMap::new() } }
    }
    let hub = Arc::new(Hub::new());
    let waiting = Arc::clone(&hub);
    let (send, receive) = mpsc::channel();
    let thread = thread::spawn(move || { send.send(waiting.wait(None)).unwrap(); });
    hub.root_completed(root());
    let signals = receive.recv_timeout(std::time::Duration::from_secs(5)).expect("root did not wake Watch");
    assert_eq!(signals.roots.len(), 1);
    assert!(signals.completed.is_empty());
    thread.join().unwrap();
    hub.stop();
    hub.root_completed(root());
    hub.batch_completed("batch".into());
    let signals = hub.wait_drain();
    assert_eq!(signals.roots.len(), 1);
    assert_eq!(signals.completed, ["batch"]);
}

#[test]
fn shared_tail_completion_preserves_other_logical_and_not_yet_claimed_owners() {
    let a = Path::new(r"C:\watch\a.001");
    let b = Path::new(r"C:\watch\b.001");
    let tail = Path::new(r"C:\watch\shared.002");
    let group = |head: &Path| Arc::new(SourceGroup { path: head.into(),
        members: vec![head.to_string_lossy().into_owned(), tail.to_string_lossy().into_owned()] });
    let mut groups = SourceGroups::default();
    groups.insert(group(a));
    groups.plan(key(b), vec![key(b), key(tail)]);
    groups.plan(key(tail), vec![]);
    let completed = groups.take(&key(a));
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[&key(a)].path, a);
    assert!(groups.planned.contains_key(&key(b)));
    assert_eq!(groups.members[&key(tail)], 1);

    groups.insert(group(b));
    // The independently admitted tail hasn't reached discovery yet. B
    // cannot retire its pending owner either, despite being last consumer.
    let completed = groups.take(&key(b));
    assert_eq!(completed.len(), 1);
    assert!(!completed.contains_key(&key(tail)));
    assert!(groups.members.is_empty());
    // An unadmitted physical sibling is transferred only by the final
    // consumer; it is never projected through the other head's group.
    groups.release_plan(&key(tail));
    groups.insert(group(a)); groups.insert(group(b));
    assert!(!groups.take(&key(a)).contains_key(&key(tail)));
    assert_eq!(groups.take(&key(b))[&key(tail)].path, b);
    assert!(groups.roots.is_empty());
    assert!(groups.members.is_empty());
    groups.insert(group(a)); groups.insert(group(b));
    let aliases = groups.into_aliases();
    assert!(!aliases.contains_key(&key(tail)));
    assert_eq!(aliases[&key(a)].path, a);
    assert_eq!(aliases[&key(b)].path, b);
    let claimed = ClaimedSources {
        candidates: [(key(a), None), (key(b), None), (key(tail), None)].into_iter().collect(),
        ..Default::default()
    };
    // The shared tail is absent from logical projection, but final
    // retirement must release its claim and rearm any parked generation.
    assert!(completion_claims(None, &aliases, &claimed).any(|path| path == &key(tail)));
    assert!(!completion_claims(Some(1), &aliases, &claimed).any(|path| path == &key(tail)));
}

#[test]
fn root_handoff_preserves_alias_aggregates_and_live_shared_tail_owners() {
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};
    struct NoWake;
    impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
    let marker = crate::test_support::temp_file("root_handoff", b"");
    let directory = marker.with_extension("journal");
    let head = Path::new(r"C:\watch\a.001");
    let alias = Path::new(r"C:\watch\a.002");
    let other = Path::new(r"C:\watch\b.zip");
    let output = Path::new(r"C:\watch\a");
    let other_output = Path::new(r"C:\watch\b");
    let retained = Path::new(r"C:\watch\nested.zip");
    let group = Arc::new(SourceGroup { path: head.into(),
        members: vec![head.to_string_lossy().into_owned(), alias.to_string_lossy().into_owned()] });
    let hub = Arc::new(Hub::new());
    let mut observer = WatchObserver {
        deep: false,
        catalog: Arc::new(NativeWatchCatalog::new(&crate::watch_store::NativeWatchState::new(), None)),
        journal: Arc::new(journal::Journal::open(&directory, 7).unwrap()),
        owners: HashMap::from([(key(alias), alias.to_string_lossy().into_owned())]),
        outputs: Mutex::new(ObservedOutputs::from(BTreeMap::from([(key(output), alias.to_string_lossy().into_owned()),
            (key(other_output), other.to_string_lossy().into_owned())]))),
        batch: Arc::from("batch"), toast: None, hub: Arc::clone(&hub),
        groups: Arc::new(Mutex::new({ let mut groups = SourceGroups::default(); groups.insert(Arc::clone(&group)); groups })),
        claimed: Arc::default(),
    };
    // Cancellation winning the mutex first must not turn an already
    // durable root into an interrupted root when its report comes back.
    observer.claimed.lock().unwrap().cancelled = true;
    let mut outcome = Outcome::default();
    outcome.archives.push(completion_archive(head.to_str().unwrap(), 1, None));
    let child = completion_archive(retained.to_str().unwrap(), 2, Some(FailureKind::WrongPassword));
    outcome.archives.push(child);
    let allocation = outcome.archives.as_ptr();
    let waker = Waker::from(Arc::new(NoWake));
    // Register two heads using the same admitted tail. Finishing one
    // leaves the tail's WAL and output receipts available to aggregate.
    let other_group = Arc::new(SourceGroup {
        path: other.into(),
        members: vec![other.to_string_lossy().into_owned(), alias.to_string_lossy().into_owned()],
    });
    observer.roots_planned([
        (head.to_str().unwrap(), group.members.as_slice()),
        (other.to_str().unwrap(), other_group.members.as_slice()),
    ].into_iter());
    {
        let mut groups = observer.groups.lock().unwrap();
        groups.insert(Arc::clone(&group));
        groups.insert(Arc::clone(&other_group));
    }
    let mut deferred = Box::pin(observer.root_finished(1, head, outcome, 1));
    let Poll::Ready(Ok(outcome)) = deferred.as_mut().poll(&mut Context::from_waker(&waker)) else {
        panic!("alias-owned roots must return their aggregate without a handoff");
    };
    assert_eq!(outcome.archives.as_ptr(), allocation);
    drop(deferred);
    assert_eq!(observer.outputs.lock().unwrap().paths.len(), 2);
    assert!(observer.claimed.lock().unwrap().finished.is_empty());

    // A single head can finish independently when only the tail was
    // admitted and the unrelated root remains active.
    let mut unique = SourceGroups::default();
    unique.insert(Arc::clone(&group));
    *observer.groups.lock().unwrap() = unique;
    let mut early = Box::pin(observer.root_finished(2, head, outcome, 1));
    assert!(early.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    let root = hub.wait(None).roots.into_iter().next().unwrap();
    assert_eq!(root.groups[&key(alias)].path, head);
    assert_eq!(root.completed.outputs.len(), 1);
    assert!(observer.claimed.lock().unwrap().finished.contains(&key(alias)));
    let outcome = root.completed.result.unwrap();
    root.reply.complete(Ok(Outcome::default()));
    assert!(matches!(early.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Ok(_))));
    drop(early);
    observer.claimed.lock().unwrap().finished.clear();
    observer.groups.lock().unwrap().insert(group);

    // Directly admitted roots still settle independently of their peers.
    observer.owners.insert(key(head), head.to_string_lossy().into_owned());
    observer.owners.insert(key(other), other.to_string_lossy().into_owned());
    observer.roots_planned([
        (head.to_str().unwrap(), &[][..]),
        (other.to_str().unwrap(), &[][..]),
    ].into_iter());
    observer.groups.lock().unwrap().insert(other_group);
    *observer.outputs.lock().unwrap() = ObservedOutputs::from(BTreeMap::from([
        (key(output), head.to_string_lossy().into_owned()),
        (key(other_output), other.to_string_lossy().into_owned()),
    ]));
    let mut future = Box::pin(observer.root_finished(1, head, outcome, 1));
    assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    let signals = hub.wait(None);
    let root = signals.roots.into_iter().next().unwrap();
    assert_eq!(root.completed.result.as_ref().unwrap().archives.as_ptr(), allocation);
    assert_eq!(root.groups.len(), 1);
    assert_eq!(root.groups[&key(head)].path, head);
    assert_eq!(root.completed.outputs.len(), 1);
    assert_eq!(observer.groups.lock().unwrap().roots[&key(other)].path, other);
    assert_eq!(observer.outputs.lock().unwrap().paths.len(), 1);
    assert!(!observer.claimed.lock().unwrap().finished.contains(&key(alias)));
    assert!(observer.claimed.lock().unwrap().finished.contains(&key(head)));
    root.reply.complete(root.completed.result);
    let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
        panic!("disabled notifications must not enqueue a report wait");
    };
    assert!(result.unwrap().archives.is_empty());
    drop(future);
    drop(observer);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn cancelling_claimed_volumes_preserves_a_replaced_sibling_generation() {
    let head = crate::test_support::temp_file("cancel_head", b"first volume");
    let sibling = crate::test_support::temp_file("cancel_sibling", b"old volume");
    let late = sibling.with_extension("late");
    let unreadable = format!("{}\0", head.display());
    let members = vec![
        head.to_string_lossy().into_owned(),
        sibling.to_string_lossy().into_owned(),
        late.to_string_lossy().into_owned(),
        unreadable.clone(),
    ];
    let mut claimed = ClaimedSources::default();
    claimed.capture(&members).unwrap();
    fs::write(&sibling, b"a newer independently queued volume").unwrap();
    fs::write(&late, b"a volume arriving after the original claim").unwrap();
    // Repeated claims and cancellation must retain the generation the
    // request started with, rather than consuming the replacement.
    claimed.capture(&members).unwrap();
    let current = watch_candidate_for_path(&sibling, None).unwrap().unwrap();
    assert!(quiet::changed(claimed.candidates[&key(&sibling)].as_ref().unwrap(), &current));
    assert!(claimed.candidates[&key(&late)].is_none());
    assert!(claimed.candidates[&watch_path_key(&unreadable)].is_none());
    claimed.cancelled = true;
    assert!(crate::io::cancellation::is_cancellation(&claimed.capture(&members).unwrap_err()));
    fs::remove_file(head).unwrap();
    fs::remove_file(sibling).unwrap();
    fs::remove_file(late).unwrap();
}

#[test]
fn configuration_candidates_remain_subscribed_after_deletion() {
    let marker = crate::test_support::temp_file("config_recreation", b"");
    let directory = marker.with_extension("dir");
    fs::create_dir(&directory).unwrap();
    let config = directory.join("sunpack_advanced_config.json");
    fs::write(&config, b"{}").unwrap();
    let sources = config::ConfigSources::default();
    assert!(config::watch_paths(&directory, &sources).contains(&config));
    fs::remove_file(&config).unwrap();
    let paths = config::watch_paths(&directory, &sources);
    assert!(paths.contains(&config));
    // Arm before recreating: verifies actual notification delivery, with
    // a bounded receive only as a test failure guard, never idle polling.
    let (send, receive) = mpsc::channel();
    let observer = FileObserver::start(&directory, false, move |names| {
        let _ = send.send(names);
    }).unwrap();
    fs::write(&config, b"{}").unwrap();
    let names = receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap();
    assert!(names.iter().any(|name| name.eq_ignore_ascii_case("sunpack_advanced_config.json")));
    drop(observer);
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn restored_checkpoint_routes_nested_outputs_to_the_durable_owner() {
    let source = crate::test_support::temp_file("watch_checkpoint_owner", b"outer archive");
    let directory = source.with_extension("state");
    let container = directory.join("output");
    let output = container.join("logical-input");
    fs::create_dir_all(&output).unwrap();
    let owner = source.to_str().unwrap();
    {
        let journal = journal::Journal::open(&directory, 7).unwrap();
        journal.commit(true, |state| {
            Ok(state.pending_operations(
                [(PendingObservation(owner.to_owned(), 13, 1.0, String::new(), 0),
                    String::new(), None)],
                false, "", false, None,
            ))
        }).unwrap();
        journal.commit(true, |state| {
            Ok(state.output_operation(owner, owner.to_owned(),
                container.to_str().unwrap().to_owned(), None, false)?.unwrap())
        }).unwrap();
        journal.commit(true, |state| {
            let mut operations = state.output_operation(owner, owner.to_owned(),
                container.to_str().unwrap().to_owned(), Some(true), false)?.unwrap();
            let candidate = watch_candidate_for_path(&source, None)?.unwrap();
            let mut blocker = observed_entry(&candidate, "failed_password", None);
            blocker.failure_payload.insert("input_checkpoints".into(), json!([{
                "schema_version":1,"carrier":source,
                "input":crate::io::archive_state::ArchiveInput::file(
                    source.to_string_lossy().into_owned(), "zip".into(), "logical-input".into(),
                ),
                "sources":[{"path":source,"generation":capture_file_generation(&source)?}],
                "output":output,
                "container":container,
                "files":1,"bytes":9,"encrypted":false,"discovery_source":"embedded",
            }]));
            operations.put_entry(Arc::new(blocker));
            Ok(operations)
        }).unwrap();
        journal.flush().unwrap();
    }
    {
        let journal = Arc::new(journal::Journal::open(&directory, 7).unwrap());
        let mut outputs = BTreeMap::new();
        let checkpoints = restore_checkpoints(journal.state(), owner, &mut outputs).unwrap();
        assert_eq!(checkpoints.len(), 1);
        let observer = WatchObserver {
            deep: false,
            catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)),
            journal: Arc::clone(&journal),
            owners: HashMap::from([(key(&source), owner.to_owned())]),
            outputs: Mutex::new(outputs.into()),
            batch: Arc::from("restored"),
            toast: None,
            hub: Arc::new(Hub::new()),
            groups: Arc::default(),
            claimed: Arc::default(),
            };
        assert_eq!(observer.owner_for_path(&output.join("nested.zip")).as_deref(), Some(owner));
        // A carrier's enclosing output need not be a logical receipt's
        // output. Restoring it must not attempt an exclusive re-create.
        let nested = container.join("nested.zip");
        let nested_output = container.join("nested");
        fs::write(&nested, b"nested archive").unwrap();
        let archive = ArchiveResult {
            path: nested.clone(), format: "zip".into(), output: None, failure: None,
            files: 0, bytes: 0, encrypted: None, depth: 2, offset: 0,
            end_offset: None, volume_completeness: None, volume_attempts: None,
            source_paths: vec![nested.clone()], password: None,
            discovery_source: crate::pipeline::DiscoverySource::Embedded,             partial: false, retained: false, recovered_complete_files: 0,
              scan_layout: Default::default(),
        };
        observer.register_output(&archive, &nested_output).unwrap();
        assert!(nested_output.is_dir());
        assert_eq!(observer.owner_for_path(&nested_output).as_deref(), Some(owner));
        assert!(journal.state().pending(owner).unwrap().active_outputs
            .values().any(|path| key(Path::new(path)) == key(&nested_output)));

        // main retains zero-verified-file payload on disk but retires its
        // Watch registration with keep=false. It is not a committed tree
        // for legacy crash recovery to recursively discover.
        let failed_output = directory.join("failed-output");
        let mut failed = completion_archive(owner, 1, Some(FailureKind::Damaged));
        observer.register_output(&failed, &failed_output).unwrap();
        fs::write(failed_output.join("unverified.zip"), b"damaged bytes").unwrap();
        failed.output = Some(failed_output.clone());
        observer.after_output(&failed).unwrap();
        assert!(failed_output.join("unverified.zip").is_file());
        let pending = journal.state().pending(owner).unwrap();
        assert!(!pending.active_outputs.values().any(|path| key(Path::new(path)) == key(&failed_output)));
        assert!(!pending.committed_roots.contains(failed_output.to_str().unwrap()));
    }
    {
        let journal = journal::Journal::open(&directory, 7).unwrap();
        let failed_output = directory.join("failed-output");
        let pending = journal.state().pending(owner).unwrap();
        assert!(!pending.committed_roots.contains(failed_output.to_str().unwrap()));
        assert!(failed_output.join("unverified.zip").is_file());
    }
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(source).unwrap();
}

#[test]
fn flatten_recovery_rebases_durable_output_identities() {
    let owner_file = crate::test_support::temp_file("flatten_watch_owner", b"outer archive");
    let directory = owner_file.with_extension("state");
    let real = directory.join("real");
    let alias = directory.join("junction");
    fs::create_dir_all(&real).unwrap();
    let junction = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"]).arg(&alias).arg(&real).output().unwrap();
    assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stderr));
    let root = alias.join("output");
    let work = alias.join("work");
    let leaf = root.join("wrapper").join("inner");
    let owner = owner_file.to_str().unwrap();
    let root_text = root.to_str().unwrap();
    fs::create_dir_all(&leaf).unwrap();
    fs::write(leaf.join("nested.zip"), b"inner archive").unwrap();
    fs::create_dir(leaf.join("nested")).unwrap();
    fs::write(leaf.join("nested/payload"), b"extracted").unwrap();

    {
        let journal = journal::Journal::open(&directory, 7).unwrap();
        journal
            .commit(true, |state| {
                Ok(state.pending_operations(
                    [(
                        PendingObservation(owner.to_owned(), 13, 1.0, String::new(), 0),
                        String::new(),
                        None,
                    )],
                    false,
                    "",
                    false,
                    None,
                ))
            })
            .unwrap();
        journal
            .commit(true, |state| {
                Ok(state
                    .output_operation(
                        owner,
                        owner.to_owned(),
                        root_text.to_owned(),
                        None, false)?
                    .unwrap())
            })
            .unwrap();
        prepare_flatten(&journal, owner, &root, &work, &leaf).unwrap();
        assert_eq!(journal.state().active_output_keys().len(), 4);
        fs::rename(&root, &work).unwrap();
        journal.flush().unwrap();
    }

    {
        let journal = journal::Journal::open(&directory, 7).unwrap();
        recover_flattens(&journal, |_| true).unwrap();
        assert_eq!(fs::read(root.join("nested/payload")).unwrap(), b"extracted");
        assert!(!work.exists());
        assert!(journal.state().runtime_keys("flatten|").is_empty());
        assert_eq!(journal.state().active_output_keys().len(), 2);
        let catalog = NativeWatchCatalog::new(journal.state(), None);
        for output in [&root, &real.join("output")] {
            assert!(catalog.is_owned(output.join("nested.zip").to_str().unwrap()));
        }
        for output in [&work, &real.join("work")] {
            assert!(journal.state().owned_root(output.to_str().unwrap()).is_none());
        }
        let pending = journal.state().pending(owner).unwrap();
        assert_eq!(
            pending
                .committed_roots
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [root_text]
        );
        assert!(recovery_output_matches(&pending, root_text));
    }
    fs::remove_dir(alias).unwrap();
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(owner_file).unwrap();
}

#[test]
fn flatten_keeps_physical_work_when_its_literal_junction_disappears() {
    let marker = crate::test_support::temp_file("flatten_detached_work", b"");
    let base = marker.with_extension("outputs");
    let real = base.join("real");
    let alias = base.join("junction");
    let root = real.join("output");
    let leaf = root.join("leaf");
    let work = alias.join("work");
    let physical_work = real.join("work");
    fs::create_dir_all(&leaf).unwrap();
    let junction = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"]).arg(&alias).arg(&real).output().unwrap();
    assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stderr));
    let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
    prepare_flatten(&journal, "", &root, &work, &leaf).unwrap();
    fs::rename(&root, &work).unwrap();
    fs::rename(physical_work.join("leaf"), &root).unwrap();
    fs::remove_dir(alias).unwrap();
    finish_flatten(&journal, root.to_str().unwrap()).unwrap();
    assert_eq!(journal.state().runtime_keys("flatten|").len(), 1);
    assert!(journal.state().owned_root(physical_work.to_str().unwrap()).is_some());
    fs::remove_dir(&physical_work).unwrap();
    finish_flatten(&journal, root.to_str().unwrap()).unwrap();
    assert!(journal.state().runtime_keys("flatten|").is_empty());
    assert_eq!(journal.state().active_output_keys().len(), 1);
    drop(journal);
    fs::remove_dir_all(base).unwrap();
    fs::remove_file(marker).unwrap();
}
