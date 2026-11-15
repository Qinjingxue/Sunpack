use super::*;
use crate::pipeline::CleanupStatus;
use crate::pipeline::{ArchiveResult, CleanupResult, Segment};

fn one_root(_: &Path) -> Option<String> { Some("root".into()) }

fn queued(id: TaskId, path: &str, parent: Option<TaskId>, index: usize) -> Event {
    Event::Queued {
        id,
        parent,
        path: PathBuf::from(path),
        segment: parent.map(|_| Segment {
            format: "zip".into(),
            index,
            offset: 0,
            end_offset: None,
        }),
    }
}

fn progress(
    activity: &Activity,
    id: TaskId,
    completed_bytes: u64,
    total_bytes: u64,
) {
    activity.event(Event::Progress {
        id,
        completed_bytes,
        total_bytes,
    });
}

fn current(publisher: &Publisher) -> Snapshot {
    let state = publisher.shared.state.lock().unwrap();
    Snapshot::progress(state.group.as_ref().unwrap())
}

#[test]
fn failed_native_snapshot_is_consumed_and_next_snapshot_recreates_presenter() {
    use std::cell::{Cell, RefCell};
    struct Presenter<'a>(&'a Cell<usize>);
    impl Drop for Presenter<'_> {
        fn drop(&mut self) { self.0.set(self.0.get() + 1); }
    }
    let drops = Cell::new(0);
    let created = Cell::new(0);
    let events = RefCell::new(Vec::new());
    let mut log = |event, _: io::Error| events.borrow_mut().push(event);
    let mut presenter = Some(Presenter(&drops));
    assert!(show_snapshot(&mut presenter,
        || panic!("existing presenter must be reused"),
        |_| Err(io::Error::other("native Show failure")), &mut log));
    assert!(presenter.is_none());
    assert_eq!(drops.get(), 1);
    assert_eq!(events.borrow().as_slice(), ["toast_error"]);
    // No eager retry or replay: only this next snapshot creates a presenter.
    assert!(show_snapshot(&mut presenter,
        || { created.set(created.get() + 1); Ok(Presenter(&drops)) },
        |_| Ok(()), &mut log));
    assert_eq!(created.get(), 1);
    assert!(presenter.is_some());
    presenter.take();
    assert!(!show_snapshot(&mut presenter,
        || Err(io::Error::other("component initialization failure")),
        |_| panic!("unavailable component cannot show"), &mut log));
    assert_eq!(events.borrow().as_slice(), ["toast_error", "toast_unavailable"]);
}

#[test]
fn terminal_progress_and_rollback_failure_keep_main_presentation() {
    let mut group = Group::new("00000000000000000000000000000001", Language::En);
    group.requests.insert(Arc::from("request"), RequestProgress::default());
    group.summary.succeeded = 1;
    let snapshot = Snapshot::progress(&group);
    assert_eq!(snapshot.progress, Some(1.0));
    assert_eq!(snapshot.value, "100% · 0 B / 0 B");
    group.active_roots = 1;
    assert_eq!(Snapshot::progress(&group).progress, None);
    group.totals.planned = 100;
    group.totals.written = 50;
    group.totals.unknown = 1;
    let snapshot = Snapshot::progress(&group);
    assert_eq!(snapshot.progress, None);
    assert_eq!(snapshot.value, Language::En.text("toast.progress.indeterminate"));
    // Stopping extraction keeps this batch valid: earlier failures still
    // need their final report. Only reset/disable invalidates report I/O.
    for request in group.requests.values_mut() { request.stopping = true; }
    let snapshot = Snapshot::progress(&group);
    assert_eq!(snapshot.body, Language::En.text("interrupt.stopping"));
    assert_eq!(snapshot.status, snapshot.body);
    assert!(snapshot.value.is_empty());
    for request in group.requests.values_mut() { request.stopping = false; }
    group.totals.unknown = 0;
    for (disk, memory, key) in [
        (0, 1, "report.status.memory_paused"),
        (1, 0, "report.status.disk_paused"),
        (1, 1, "report.status.resources_paused"),
    ] {
        group.totals.disk = disk;
        group.totals.memory = memory;
        let snapshot = Snapshot::progress(&group);
        assert_eq!(snapshot.progress, None);
        assert_eq!(snapshot.value, Language::En.text(key));
    }
    let mut completed = Completed {
        generation: 0, id: Arc::from("presentation"), language: Language::En,
        elapsed: Duration::ZERO, report: Arc::default(), cancellation: Cancellation::new(),
        summary: Summary { succeeded: 1, interrupted: 1, rollback_failed: true,
            ..Summary::default() },
    };
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let report = publisher.reports.publish(&completed, &publisher.shared).unwrap().unwrap();
    let text = fs::read_to_string(&report).unwrap();
    assert!(text.contains(&Language::En.translate("toast.report.summary", &[("failed", "1")])));
    assert_eq!(text.lines().count(), 4);
    let snapshot = Snapshot::completed(&completed, Some(report));
    assert_eq!(snapshot.kind, 4);
    assert!(snapshot.report_action.is_some());
    assert_eq!(snapshot.title, Language::En.text("toast.final.mixed.title"));
    let duration = Language::En.translate("duration.seconds", &[("seconds", "0")]);
    assert!(snapshot.body.starts_with(&Language::En.translate("toast.final.mixed.body",
        &[("succeeded", "1"), ("failed", "1"), ("duration", &duration)])));
    // Ordinary source cleanup is only a warning, not a rollback failure.
    completed.summary.interrupted = 0;
    completed.summary.rollback_failed = false;
    completed.summary.cleanup_failed = 1;
    let snapshot = Snapshot::completed(&completed, None);
    assert_eq!(snapshot.kind, 2);
    assert_eq!(snapshot.title, Language::En.text("toast.final.success.title"));
    assert!(snapshot.body.ends_with(&Language::En.translate("cleanup.incomplete", &[("count", "1")])));
    for _ in 0..128 {
        completed.summary.merge(Summary { cleanup_failed: 2, ..Summary::default() });
    }
    let snapshot = Snapshot::completed(&completed, None);
    assert!(snapshot.body.ends_with(&Language::En.translate("cleanup.incomplete", &[("count", "257")])));

    // An output moved away during recursive cleanup must not widen the
    // Open output target beyond the directory the user can still open.
    let live = directory.0.join("live");
    fs::create_dir_all(&live).unwrap();
    let mut result = Outcome::default();
    for path in [directory.0.join("departed"), live.clone()] {
        let mut output = archive("a.zip", None);
        output.output = Some(path);
        result.archives.push(output);
    }
    let summary = Summary::for_outcome(&result, false, true, &one_root, None);
    assert_eq!(summary.output, Some(live));

    let mut snapshot = Snapshot::stop_failed("batch", Language::En);
    assert_eq!(snapshot.kind, 3);
    assert_eq!(snapshot.title, "SunPack could not confirm stop");
    assert_eq!(snapshot.body, "Stop unconfirmed. Check the current processing status.");
    let target = format!("C:\\{}", "路径".repeat(1500));
    snapshot.action = Some((1, "Open".into(), target.clone()));
    assert!(snapshot.encode().unwrap().ends_with(target.as_bytes()));
    let report_path = format!("C:\\{}failure.txt", ("路径".repeat(126) + "\\").repeat(92));
    snapshot.report_action = Some((2, "Report".into(), report_path.clone()));
    assert!(snapshot.encode().unwrap().ends_with(report_path.as_bytes()));
}

#[test]
fn overlapping_requests_share_progress_stop_and_cleanup_result() {
    // Exercise the same state consumed by the presenter, without opening
    // Windows notifications or depending on update timing.
    let publisher = publisher(PathBuf::new());
    let first = Arc::<str>::from("00000000000000000000000000000001");
    let second = Arc::<str>::from("00000000000000000000000000000002");
    let a = publisher.register(Arc::clone(&first), Language::En);
    let b = publisher.register(Arc::clone(&second), Language::En);
    a.event(queued(1, "carrier", None, 0));
    a.event(queued(2, "carrier", Some(1), 1));
    a.event(queued(3, "carrier", Some(1), 2));
    b.event(queued(4, "ordinary.7z", None, 0));
    progress(&a, 2, 20, 100);
    progress(&a, 3, 80, 200);
    progress(&b, 4, 100, 200);
    let initial = current(&publisher);
    assert_eq!(initial.progress, Some(0.4));
    assert_eq!(initial.label, "2 archives");
    assert_eq!(initial.value, "40% · 200 B / 500 B");

    a.event(Event::ResourceWait {
        id: 2,
        path: "carrier".into(),
        state: ResourceWait {
            memory: true,
            ..ResourceWait::default()
        },
    });
    b.event(Event::ResourceWait {
        id: 4,
        path: "ordinary.7z".into(),
        state: ResourceWait {
            disk: true,
            ..ResourceWait::default()
        },
    });
    assert_eq!(
        current(&publisher).status,
        Language::En.text("report.status.resources_resume_hint")
    );
    b.event(Event::Finalizing { id: 4 });
    assert_eq!(
        current(&publisher).status,
        Language::En.text("toast.progress.memory_paused")
    );
    a.event(Event::Finalizing { id: 2 });
    a.event(Event::Finished {
        id: 2,
        result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None },
    });
    let snapshot = current(&publisher);
    assert_eq!(snapshot.status, "0/2 finished");
    assert_eq!(snapshot.progress, Some(0.56));

    let mut stopped = publisher.stop_group(&snapshot.action.unwrap().2);
    stopped.sort_unstable();
    assert_eq!(stopped, [first, second]);
    let later = publisher.register(Arc::from("00000000000000000000000000000003"), Language::En);
    later.event(queued(5, "later.zip", None, 0));
    progress(&later, 5, 5, 10);
    assert_eq!(current(&publisher).title, Language::En.text("toast.progress.title"));
    // Earlier requests remain in cancellation cleanup; new work is visible
    // immediately and another Stop captures it in the same batch.
    let stopped_again = publisher.stop_group(&initial.batch);
    assert!(stopped_again.contains(&later.request));
    assert_eq!(stopped_again.len(), 3);
    a.finish(&Err(io::Error::other("output deletion failed")), true, true, one_root);
    b.finish(&Ok(Outcome::default()), true, false, one_root);
    assert!(publisher.shared.state.lock().unwrap().completed.is_empty());

    let mut outcome = Outcome::default();
    outcome.archives.push(archive("later.zip", None));
    outcome.cleanup_results.push(CleanupResult {
        path: "later.zip".into(),
        mode: "delete",
        status: CleanupStatus::Failed,
        error_code: 5,
        message: "Access denied".to_owned(),
    });
    let finish = later.prepare_finish(&Ok(outcome), false, false, one_root).unwrap();
    // Watch may prepare a whole completion batch before any WAL wait.
    // Preparation cannot make its terminal notification visible.
    {
        let state = publisher.shared.state.lock().unwrap();
        assert!(state.group.as_ref().unwrap().finalize_at.is_none());
        assert!(state.completed.is_empty());
    }
    finish.publish();
    finish_debounce(&publisher);
    let completed = Snapshot::completed(&take_completed(&publisher), None);
    let state = publisher.shared.state.lock().unwrap();
    assert!(completed.body.contains(&Language::En.translate("cleanup.incomplete", &[("count", "1")])));
    assert!(state.group.is_none());
}
fn publisher(directory: PathBuf) -> Publisher {
    Publisher {
        shared: Arc::default(),
        reports: Arc::new(Reports {
            cancellation: Cancellation::new(),
            directory,
            retention: AtomicU64::new(30),
        }),
    }
}

fn archive(name: &str, failure: Option<FailureKind>) -> ArchiveResult {
    ArchiveResult {
        path: name.into(), format: "zip".into(), output: Some(name.into()),
        failure: failure.map(|kind| crate::pipeline::Failure::new(kind, name)),
        files: 1, bytes: 42, encrypted: None, depth: 1,
        offset: 0, end_offset: None, volume_completeness: None,
        volume_attempts: None, source_paths: Vec::new(), password: None,
        discovery_source: crate::pipeline::DiscoverySource::Embedded,         partial: false, retained: false, recovered_complete_files: 0,
          scan_layout: Default::default(),
    }
}

fn success() -> io::Result<Outcome> {
    let mut outcome = Outcome::default();
    outcome.archives.push(archive("outer.zip", None));
    outcome.archives.push(archive("nested.zip", None));
    Ok(outcome)
}

fn finish_debounce(publisher: &Publisher) {
    let mut state = publisher.shared.state.lock().unwrap();
    let deadline = state.group.as_ref().unwrap().finalize_at.unwrap();
    state.settle(deadline);
}

fn take_completed(publisher: &Publisher) -> Completed {
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    assert!(publisher.shared.present_completed(&completed, || {}));
    completed
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "sunpack-toast-{}-{}-{}", std::process::id(),
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn failed_report_service_releases_completion_gate_without_publishing_partial_report() {
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let activity = publisher.register(Arc::from("42"), Language::En);
    activity.event(queued(1, "a.zip", None, 0));
    progress(&activity, 1, 1, 2);
    activity.event(Event::Finished { id: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Failed, failure: None, output: None } });
    let mut outcome = Outcome::default();
    outcome.archives.push(archive("a.zip", Some(FailureKind::Damaged)));
    activity.root_finished(1, &outcome);
    assert!(publisher.shared.state.lock().unwrap().group.as_ref().unwrap().pending());
    activity.report_finished(1, true);
    assert!(!publisher.shared.state.lock().unwrap().group.as_ref().unwrap().pending());
    activity.finish(&Ok(Outcome::default()), false, false, |_| Some("a.zip".into()));
    finish_debounce(&publisher);
    let completed = take_completed(&publisher);
    assert!(completed.summary.report_failed);
    assert!(publisher.reports.publish(&completed, &publisher.shared).unwrap().is_none());
}

#[test]
fn later_root_uses_its_own_name_after_an_earlier_completion_is_published() {
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let activity = publisher.register(Arc::from("41"), Language::En);
    activity.event(queued(1, "a.zip", None, 0));
    activity.event(queued(2, "b.zip", None, 0));
    progress(&activity, 1, 1, 2);
    let mut outcome = Outcome::default();
    outcome.archives.push(archive("a.zip", None));
    activity.event(Event::Finished { id: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None } });
    activity.root_finished(1, &outcome);
    activity.report_finished(1, false);
    finish_debounce(&publisher);
    take_completed(&publisher);
    progress(&activity, 2, 1, 2);
    assert_eq!(current(&publisher).label, "b.zip");
}

#[test]
fn settled_roots_survive_sibling_cancel_or_request_error_without_duplicate_reports() {
    // Unlike projection-only tests, this exercises real incremental root
    // publication followed by both batch termination paths.
    for cancelled in [false, true] {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let activity = publisher.register(Arc::from("40"), Language::En);
        for (id, path) in [(1, "a.zip"), (2, "b.zip"), (3, "c.zip")] {
            activity.event(queued(id, path, None, 0));
            progress(&activity, id, 1, 2);
        }
        activity.event(Event::Finished { id: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None } });
        assert_eq!(current(&publisher).status, "0/3 finished");
        let mut done = Outcome::default();
        done.archives.push(archive("a.zip", None));
        done.archives.push(archive("a/nested.zip", None));
        done.cleanup_results.push(crate::pipeline::CleanupResult {
            path: "a.zip".into(), mode: "delete", status: CleanupStatus::Failed,
            error_code: 5, message: "source busy".into(),
        });
        activity.root_finished(1, &done);
        assert!(!activity.needs_root_report(1));
        activity.record_root(1, Path::new("a.zip"), &done);
        activity.report_finished(1, false);
        {
            let state = publisher.shared.state.lock().unwrap();
            let request = &state.group.as_ref().unwrap().requests[&activity.request];
            assert!(!request.roots.contains_key(&1));
            assert!(!request.task_roots.values().any(|root| *root == 1));
            assert!(!request.started.contains_key(&1));
            assert!(!request.visible_roots.contains(&1));
            let report = state.group.as_ref().unwrap().report.lock().unwrap();
            assert_eq!(report.failures, 0);
            assert!(report.path.as_ref().is_none_or(|path| !path.exists()));
        }
        assert_eq!(current(&publisher).status, "1/3 finished");
        let mut failed = Outcome::default();
        failed.archives.push(archive("c.zip", Some(FailureKind::Damaged)));
        activity.event(Event::Finished { id: 3, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Failed, failure: None, output: None } });
        activity.root_finished(3, &failed);
        assert!(activity.needs_root_report(3));
        activity.record_root(3, Path::new("c.zip"), &failed);
        activity.report_finished(3, false);
        assert!(!activity.needs_root_report(3));
        assert_eq!(current(&publisher).status, "2/3 finished");
        let owner = |path: &Path| {
            let path = path.to_string_lossy();
            Some(if path.starts_with("a") { "a.zip" } else if path.starts_with("c") {
                "c.zip"
            } else { "b.zip" }.to_owned())
        };
        let result = if cancelled { Ok(Outcome::default()) } else { Err(io::Error::other("sibling failed")) };
        activity.record(Path::new("b.zip"), &result, cancelled, &owner);
        activity.finish(&result, cancelled, false, &owner);
        let state = publisher.shared.state.lock().unwrap();
        let group = state.group.as_ref().unwrap();
        assert_eq!(group.summary.succeeded, 1);
        assert_eq!(group.summary.failed, if cancelled { 1 } else { 2 });
        assert_eq!(group.summary.interrupted, usize::from(cancelled));
        assert_eq!(group.summary.cleanup_failed, 1);
        // Only failed roots belong in the report; A's source cleanup
        // remains a warning and must not add a failure entry.
        assert_eq!(group.report.lock().unwrap().failures, if cancelled { 1 } else { 2 });
    }
}

#[test]
fn batched_top_level_tasks_keep_independent_completion_and_reports() {
    // Covers batched scheduling, nested/carrier ownership, invisible
    // failures, recovery and report admission in one production flow.
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let activity = publisher.register(Arc::from("30"), Language::En);
    for (id, path) in [(1, "a.zip"), (2, "b.zip"), (3, "c.zip"), (4, "d.zip")] {
        activity.event(queued(id, path, None, 0));
        if id != 4 { progress(&activity, id, 1, 2); }
    }
    assert_eq!(current(&publisher).status, "0/3 finished");
    assert_eq!(current(&publisher).label, "3 archives");
    // A root can finish before later descendants are queued. Retain its
    // scalar ancestry until the native request itself has completed.
    activity.event(Event::Finished { id: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None } });
    activity.event(queued(5, "a/nested.zip", Some(1), 1));
    progress(&activity, 5, 1, 2);
    assert_eq!(current(&publisher).status, "0/3 finished");
    let owner = |path: &Path| {
        let path = path.to_string_lossy().to_ascii_lowercase();
        if path.starts_with("a") { Some("a".into()) }
        else if path.starts_with("b") { Some("b".into()) }
        else if path.starts_with("c") { Some("c".into()) }
        else if path.starts_with("d") { Some("d".into()) }
        else { None }
    };
    let mut outcome = Outcome::default();
    outcome.archives.push(archive("a.zip", None));
    outcome.archives.push(archive("a/nested.zip", None));
    outcome.archives.push(archive("b.zip", None));
    let retained = archive("b/nested.zip", Some(FailureKind::WrongPassword));
    outcome.archives.push(retained);
    outcome.archives.push(archive("c.zip", None));
    outcome.archives.push(archive("c/nested.zip", Some(FailureKind::Damaged)));
    let mut segment = archive("c/nested.zip", Some(FailureKind::Damaged));
    segment.offset = 100;
    outcome.archives.push(segment);
    outcome.archives.push(archive("c/another.zip", Some(FailureKind::Damaged)));
    outcome.archives.push(archive("d.zip", Some(FailureKind::Damaged)));
    let result = Ok(outcome);
    activity.record(Path::new("a.zip"), &result, false, &owner);
    activity.finish(&result, false, false, &owner);
    finish_debounce(&publisher);
    let completed = take_completed(&publisher);
    assert_eq!((completed.summary.succeeded, completed.summary.failed), (1, 1));
    let draft = completed.report.lock().unwrap();
    assert_eq!(draft.failures, 1);
    let text = fs::read_to_string(draft.path.as_ref().unwrap()).unwrap();
    assert!(text.lines().any(|line| line == "[1] c.zip"));
    assert!(!text.lines().any(|line| line.starts_with("[2] ")));
    let prefix = Language::En.translate("toast.report.details", &[("details", "")]);
    let details: serde_json::Value = serde_json::from_str(
        text.lines().find_map(|line| line.strip_prefix(&prefix)).unwrap()).unwrap();
    assert_eq!(details.as_array().unwrap().len(), 2);
    assert_eq!(details[0]["kind"], "inputs_failed");
    assert_eq!(details[0]["causes"].as_array().unwrap().len(), 2);
    assert_eq!(details[1]["kind"], "damaged");
    assert!(!text.lines().any(|line| line.ends_with("] d.zip")));

    // No owner metadata: independent paths stay independent, while
    // case-folded segments of one physical carrier remain one task.
    let mut outcome = Outcome::default();
    outcome.archives.push(archive("a.zip", None));
    outcome.archives.push(archive("A.ZIP", None));
    outcome.archives.push(archive("b.zip", None));
    let summary = Summary::for_result(&Ok(outcome), false, false, true, &|_| None, None);
    assert_eq!((summary.succeeded, summary.failed), (2, 0));

    // Cancellation can precede receipts or Working events entirely.
    let activity = publisher.register(Arc::from("31"), Language::En);
    activity.event(queued(1, "a.zip", None, 0));
    activity.event(queued(2, "b.zip", None, 0));
    activity.finish(&Ok(Outcome::default()), true, false, &owner);
    finish_debounce(&publisher);
    assert_eq!(take_completed(&publisher).summary.interrupted, 2);
}

#[test]
fn request_projection_suppresses_invisible_retry_and_partial_diagnostics() {
    // Unlike aggregate-count tests this exercises report admission: a
    // retry or pre-extraction error must not create a diagnostic file.
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let invisible = publisher.register(Arc::from("01"), Language::En);
    invisible.event(queued(1, "invisible.zip", None, 0));
    let error = Err(io::Error::other("pre-extraction failure"));
    invisible.record(Path::new("invisible.zip"), &error, false, one_root);
    invisible.finish(&error, false, false, one_root);
    assert!(!directory.0.exists());
    assert!(publisher.shared.state.lock().unwrap().completed.is_empty());

    for (index, kind) in [FailureKind::PasswordRequired, FailureKind::WrongPassword,
        FailureKind::MissingVolume].into_iter().enumerate()
    {
        let activity = publisher.register(Arc::from(format!("1{index}")), Language::En);
        activity.event(queued(1, "retry.zip", None, 0));
        progress(&activity, 1, 1, 2);
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("successful-sibling.zip", None));
        outcome.archives.push(archive("retry.zip", Some(kind)));
        let result = Ok(outcome);
        activity.record(Path::new("retry.zip"), &result, false, one_root);
        activity.finish(&result, false, false, one_root);
        let mut state = publisher.shared.state.lock().unwrap();
        assert!(state.group.is_none());
        assert!(state.completed.is_empty());
        assert!(std::mem::take(&mut state.clear));
        assert!(!directory.0.exists());
    }

    // Retry evidence from an accepted segment still owns a failed
    // physical carrier, but an entirely accepted carrier stays successful.
    for (index, kind) in [FailureKind::MissingVolume, FailureKind::WrongPassword]
        .into_iter().enumerate()
    {
        let activity = publisher.register(Arc::from(format!("3{index}")), Language::En);
        activity.event(queued(1, "carrier.bin", None, 0));
        progress(&activity, 1, 1, 2);
        let mut outcome = Outcome::default();
        let mut partial = archive("carrier.bin", Some(kind));
        partial.partial = true;
        outcome.archives.push(partial);
        outcome.archives.push(archive("CARRIER.bin", Some(FailureKind::Damaged)));
        let result = Ok(outcome);
        activity.record(Path::new("carrier.bin"), &result, false, one_root);
        activity.finish(&result, false, false, one_root);
        assert!(publisher.shared.state.lock().unwrap().group.is_none());
        assert!(publisher.shared.state.lock().unwrap().completed.is_empty());
        assert!(!directory.0.exists());

        let mut accepted = archive("carrier.bin", Some(kind));
        accepted.partial = true;
        let mut outcome = Outcome::default();
        outcome.archives.push(accepted);
        let summary = Summary::for_result(&Ok(outcome), false, false, true, &one_root, None);
        assert_eq!((summary.succeeded, summary.failed), (1, 0));
    }

    let activity = publisher.register(Arc::from("20"), Language::En);
    activity.event(queued(1, "terminal.zip", None, 0));
    progress(&activity, 1, 1, 2);
    let mut outcome = Outcome::default();
    outcome.archives.push(archive("successful-sibling.zip", None));
    outcome.archives.push(archive("terminal.zip", Some(FailureKind::Damaged)));
    outcome.archives.push(archive("password-only.zip", Some(FailureKind::WrongPassword)));
    let mut carrier = archive("blocked-carrier.bin", Some(FailureKind::MissingVolume));
    carrier.partial = true;
    outcome.archives.push(carrier);
    outcome.archives.push(archive("blocked-carrier.bin", Some(FailureKind::Damaged)));
    let mut partial = archive("accepted-recovery.zip", Some(FailureKind::Damaged));
    partial.partial = true;
    outcome.archives.push(partial);
    outcome.errors.push(crate::pipeline::InputError {
        path: "log-only-scan".into(), message: "log-only-scan".into(),
        kind: InputErrorKind::FilesystemScan, scan_operation: Some("read".into()),
        failure: None,
    });
    let result = Ok(outcome);
    activity.record(Path::new("terminal.zip"), &result, false, one_root);
    activity.finish(&result, false, false, one_root);
    finish_debounce(&publisher);
    let completed = take_completed(&publisher);
    assert_eq!((completed.summary.succeeded, completed.summary.failed), (0, 1));
    let draft = completed.report.lock().unwrap();
    assert_eq!(draft.failures, 1);
    let text = fs::read_to_string(draft.path.as_ref().unwrap()).unwrap();
    assert!(text.contains("terminal.zip"));
    assert!(!text.contains("password-only.zip"));
    assert!(!text.contains("blocked-carrier.bin"));
    assert!(!text.contains("accepted-recovery.zip"));
    assert!(!text.contains("log-only-scan"));
}

#[test]
fn debounce_coalesces_requests_without_waiting_for_invisible_scans() {
    // Drive the production deadline directly. This catches early final
    // notifications, recursive archive counts, and orphaned activities
    // after an invisible scan moves to the next batch, without sleeping.
    let publisher = publisher(PathBuf::new());
    // This first request seeds the original batch but outlives it. Its
    // next batch must have a new notification tag and spool filename.
    let c = publisher.register(Arc::from("03"), Language::En);
    c.event(queued(3, "slow-scan.zip", None, 0));
    let a = publisher.register(Arc::from("01"), Language::En);
    a.event(queued(1, "outer.zip", None, 0));
    progress(&a, 1, 2, 2);
    a.finish(&success(), false, false, one_root);
    let first_deadline = publisher.shared.state.lock().unwrap()
        .group.as_ref().unwrap().finalize_at.unwrap();
    let b = publisher.register(Arc::from("02"), Language::En);
    b.event(queued(2, "next.zip", None, 0));
    {
        let mut state = publisher.shared.state.lock().unwrap();
        assert_eq!(state.group.as_ref().unwrap().finalize_at, Some(first_deadline));
        state.settle(first_deadline - Duration::from_millis(1));
        assert!(state.completed.is_empty());
    }
    progress(&b, 2, 1, 2);
    assert!(publisher.shared.state.lock().unwrap().group.as_ref().unwrap().finalize_at.is_none());
    assert_eq!(current(&publisher).status, "1/2 finished");
    b.finish(&success(), false, false, one_root);
    finish_debounce(&publisher);
    {
        let completed = take_completed(&publisher);
        let state = publisher.shared.state.lock().unwrap();
        assert_eq!(completed.summary.succeeded, 2);
        assert_eq!(state.group.as_ref().unwrap().requests.len(), 1);
        assert_ne!(state.group.as_ref().unwrap().id, completed.id);
    }
    progress(&c, 3, 1, 2);
    assert_eq!(current(&publisher).label, "slow-scan.zip");
    assert_eq!(current(&publisher).status, "0/1 finished");
    c.finish(&success(), false, false, one_root);
    finish_debounce(&publisher);
    assert_eq!(take_completed(&publisher).summary.succeeded, 1);
    assert!(publisher.shared.state.lock().unwrap().group.is_none());
}

#[test]
fn a_failed_append_poisons_previously_written_report_records() {
    // A single failed record must invalidate the whole report, including
    // earlier successful appends. Low-level append rollback tests cannot
    // detect publication of that otherwise well-formed incomplete file.
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let draft = Arc::new(Mutex::new(ReportDraft::default()));
    let error = Err(io::Error::other("terminal failure"));
    publisher.reports.append("81", Language::En, &draft, Path::new("a.zip"), &error, &one_root, None).unwrap();
    let path = draft.lock().unwrap().path.clone().unwrap();
    let original = fs::read(&path).unwrap();
    // Point the next append at a directory, an actual deterministic IO
    // failure on Windows and Unix, then restore the valid first record.
    draft.lock().unwrap().path = Some(directory.0.clone());
    assert!(publisher.reports.append("81", Language::En, &draft, Path::new("b.zip"), &error, &one_root, None).is_err());
    draft.lock().unwrap().path = Some(path.clone());
    publisher.reports.append("81", Language::En, &draft, Path::new("c.zip"), &error, &one_root, None).unwrap();
    assert!(draft.lock().unwrap().poisoned);
    assert_eq!(fs::read(&path).unwrap(), original);
    let completed = Completed {
        generation: 0,
        id: Arc::from("81"), language: Language::En, elapsed: Duration::ZERO,
        summary: Summary { failed: 3, ..Summary::default() }, report: draft, cancellation: Cancellation::new(),
    };
    assert!(publisher.reports.publish(&completed, &publisher.shared).unwrap().is_none());
    drop(completed);
    assert!(!path.exists());
}

#[test]
fn idle_toast_start_stop_does_not_require_a_native_presenter() {
    let directory = TestDirectory::new();
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let engine = Arc::new(crate::pipeline::Engine::new(directory.0.join("unused-worker.exe")));
    for _ in 0..3 {
        let reported = Arc::clone(&errors);
        let host = Toast::start(&directory.0, Arc::clone(&engine), directory.0.join("failures"), 7,
            move |_, _| { reported.fetch_add(1, Ordering::Relaxed); }).unwrap();
        drop(host);
    }
    assert_eq!(errors.load(Ordering::Relaxed), 0);
}

#[test]
fn disabling_toasts_cancels_then_joins_an_active_report_writer() {
    // Hold a writer on a channel rather than timing large disk writes.
    // Cancellation is immediate; stop must still await owner teardown.
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let draft = Arc::new(Mutex::new(ReportDraft::default()));
    let result = Err(io::Error::other("failure"));
    publisher.reports.append("81", Language::En, &draft, Path::new("a.zip"), &result, &one_root, None).unwrap();
    let path = draft.lock().unwrap().path.clone().unwrap();
    let completed = Completed {
        generation: 0,
        id: Arc::from("81"), language: Language::En, elapsed: Duration::ZERO,
        summary: Summary { failed: 1, ..Summary::default() }, report: draft, cancellation: Cancellation::new(),
    };
    let (entered, ready) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let worker = publisher.clone();
    let thread = thread::spawn(move || {
        let draft = completed.report.lock().unwrap();
        entered.send(()).unwrap();
        released.recv().unwrap();
        drop(draft);
        assert!(worker.reports.cancellation.cancelled());
        assert!(worker.reports.append("81", Language::En, &completed.report,
            Path::new("b.zip"), &result, &one_root, None).is_err());
        assert!(worker.reports.publish(&completed, &worker.shared).is_err());
        assert!(!worker.shared.present("81", || panic!("stale toast after disable")));
        drop(completed);
        done.send(()).unwrap();
    });
    ready.recv().unwrap();
    let toast = Toast { publisher: publisher.clone(), thread: Some(thread) };
    let (stopped, stop_complete) = mpsc::channel();
    let stop = thread::spawn(move || {
        drop(toast);
        stopped.send(()).unwrap();
    });
    let mut state = publisher.shared.state.lock().unwrap();
    while !state.stopping { state = publisher.shared.changed.wait(state).unwrap(); }
    drop(state);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !publisher.reports.cancellation.cancelled() && Instant::now() < deadline { thread::yield_now(); }
    assert!(publisher.reports.cancellation.cancelled());
    let returned = stop_complete.try_recv();
    // Always release before asserting, so a regression cannot leak a
    // blocked test thread or leave the temporary report locked.
    release.send(()).unwrap();
    stop.join().unwrap();
    assert!(matches!(returned, Err(mpsc::TryRecvError::Empty)), "disable returned before owner exit");
    stop_complete.recv_timeout(Duration::from_secs(5)).unwrap();
    finished.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!path.exists());
    assert!(!fs::read_dir(&directory.0).unwrap().any(|entry| {
        entry.unwrap().path().extension().is_some_and(|ext| ext == "txt")
    }));
}
#[test]
fn semantic_reload_retires_debouncing_and_in_flight_batches() {
    for in_flight in [false, true] {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let old = publisher.register(Arc::from("01"), Language::En);
        old.event(queued(1, "old.zip", None, 0));
        progress(&old, 1, 1, 2);
        let stale_progress = current(&publisher);
        let failure = Err(io::Error::other("old failure"));
        old.record(Path::new("old.zip"), &failure, false, one_root);
        old.finish(&failure, false, false, one_root);
        let completed = if in_flight {
            finish_debounce(&publisher);
            publisher.shared.state.lock().unwrap().completed.pop_front()
        } else { None };
        publisher.reset_batches();
        assert!(publisher.shared.state.lock().unwrap().clear);
        let new = publisher.register(Arc::from("02"), Language::Zh);
        new.event(queued(2, "new.zip", None, 0));
        progress(&new, 2, 1, 2);
        assert!(!publisher.shared.present(&stale_progress.batch, || panic!("stale progress")));
        if let Some(completed) = completed {
            assert!(!publisher.shared.present_completed(&completed, || panic!("stale completion")));
        }
        let state = publisher.shared.state.lock().unwrap();
        assert_eq!(state.group.iter().count(), 1);
        assert!(state.completed.is_empty());
        let group = state.group.as_ref().unwrap();
        assert!(group.requests.contains_key("02"));
        assert_ne!(group.id.as_ref(), stale_progress.batch);
        assert_eq!(group.language, Language::Zh);
        assert_eq!(group.summary.failed, 0);
        assert!(group.report.lock().unwrap().path.is_none());
    }
}

#[test]
fn presenter_shutdown_discards_queued_report_and_draft_with_live_activity() {
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let activity = publisher.register(Arc::from("01"), Language::En);
    activity.event(queued(1, "failed.zip", None, 0));
    progress(&activity, 1, 1, 2);
    let failure = Err(io::Error::other("failure"));
    activity.record(Path::new("failed.zip"), &failure, false, one_root);
    activity.finish(&failure, false, false, one_root);
    finish_debounce(&publisher);
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    let draft_path = completed.report.lock().unwrap().path.clone().unwrap();
    let engine = crate::pipeline::Engine::new(PathBuf::new());
    publisher.publish(&engine, completed).join().unwrap();
    let report_path = publisher.shared.state.lock().unwrap().published.front()
        .unwrap().1.clone().unwrap();
    assert!(report_path.exists());
    assert!(draft_path.exists());
    // Both disable and unrecoverable presenter failure exit through this
    // cleanup, while extraction observers may still retain the Activity.
    publisher.shared.state.lock().unwrap().stopping = true;
    publisher.shared.discard_batches();
    assert!(!report_path.exists());
    assert!(!draft_path.exists());
    let state = activity.publisher.shared.state.lock().unwrap();
    assert!(state.group.is_none());
    assert!(state.completed.is_empty());
    assert!(state.published.is_empty());
}

#[test]
fn stopping_remaining_work_preserves_the_batch_failure_report() {
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let failed = publisher.register(Arc::from("01"), Language::En);
    let running = publisher.register(Arc::from("02"), Language::En);
    failed.event(queued(1, "failed.zip", None, 0));
    progress(&failed, 1, 1, 2);
    running.event(queued(2, "running.zip", None, 0));
    progress(&running, 2, 1, 2);
    let failure = Err(io::Error::other("archive failure before user stop"));
    failed.record(Path::new("failed.zip"), &failure, false, one_root);
    failed.finish(&failure, false, false, one_root);
    let batch = current(&publisher).batch;
    assert_eq!(publisher.stop_group(&batch), vec![Arc::<str>::from("02")]);
    running.finish(&Ok(Outcome::default()), true, false, one_root);
    finish_debounce(&publisher);
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    assert_eq!(completed.summary.failed, 1);
    assert_eq!(completed.summary.interrupted, 1);
    assert!(!completed.cancellation.cancelled());
    let engine = crate::pipeline::Engine::new(PathBuf::new());
    publisher.publish(&engine, completed).join().unwrap();
    let (completed, report) = publisher.shared.state.lock().unwrap().published.pop_front().unwrap();
    let report = report.expect("stopping must retain previous failures");
    assert!(fs::read_to_string(&report).unwrap().contains("archive failure before user stop"));
    assert!(Snapshot::completed(&completed, Some(report)).report_action.is_some());
    assert!(publisher.shared.present_completed(&completed, || {}));

    let next = publisher.register(Arc::from("03"), Language::En);
    next.event(queued(3, "next.zip", None, 0));
    progress(&next, 3, 1, 2);
    let next_batch = current(&publisher).batch;
    assert_ne!(batch, next_batch);
    assert!(publisher.stop_group(&batch).is_empty());
    assert_eq!(publisher.stop_group(&next_batch), vec![Arc::<str>::from("03")]);
}

#[test]
fn report_publication_does_not_block_progress_and_reset_cancels_its_io() {
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let first = publisher.register(Arc::from("01"), Language::En);
    first.event(queued(1, "first.zip", None, 0));
    progress(&first, 1, 1, 2);
    let failure = Err(io::Error::other("first failure"));
    first.record(Path::new("first.zip"), &failure, false, one_root);
    first.finish(&failure, false, false, one_root);
    finish_debounce(&publisher);
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    let cancel = completed.cancellation.clone();
    let draft = Arc::clone(&completed.report);
    // Hold the actual report I/O gate, not a timed large-file simulation.
    // Dispatch and progress must remain usable until this gate is released.
    let held = draft.lock().unwrap();
    let engine = crate::pipeline::Engine::new(PathBuf::new());
    let publication = publisher.publish(&engine, completed);
    let next = publisher.register(Arc::from("02"), Language::En);
    next.event(queued(2, "next.zip", None, 0));
    progress(&next, 2, 1, 2);
    progress(&next, 2, 1, 2);
    let snapshot = current(&publisher);
    assert!(publisher.shared.present(&snapshot.batch, || {}));
    assert!(!cancel.cancelled());
    publisher.reset_batches();
    assert!(cancel.cancelled());
    assert!(publisher.shared.state.lock().unwrap().clear);
    drop(held);
    publication.join().unwrap();
    assert!(publisher.shared.state.lock().unwrap().published.is_empty());
    assert!(fs::read_dir(&directory.0).unwrap().flatten().all(|entry| {
        !entry.file_name().to_string_lossy().starts_with("failed-")
    }));
}

#[test]
fn native_presentation_releases_state_before_sending_progress_and_completion() {
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let first = publisher.register(Arc::from("01"), Language::En);
    first.event(queued(1, "first.zip", None, 0));
    progress(&first, 1, 1, 2);
    assert!(publisher.shared.present(&current(&publisher).batch, || {
        assert!(publisher.shared.state.try_lock().is_ok());
        progress(&first, 1, 1, 2);
    }));
    first.finish(&success(), false, false, one_root);
    finish_debounce(&publisher);
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    assert!(publisher.shared.present_completed(&completed, || {
        assert!(publisher.shared.state.try_lock().is_ok());
        let next = publisher.register(Arc::from("02"), Language::En);
        next.event(queued(2, "next.zip", None, 0));
        progress(&next, 2, 1, 2);
        progress(&next, 2, 1, 2);
        assert_ne!(current(&publisher).batch, completed.id.as_ref());
    }));
    assert_eq!(publisher.shared.state.lock().unwrap().group.iter().count(), 1);
}

#[test]
fn new_visible_work_invalidates_in_flight_completion_without_losing_report() {
    // Pause at the report/presentation boundary, where checking only
    // shutdown allowed an old final toast to overwrite fresh progress.
    let directory = TestDirectory::new();
    let publisher = publisher(directory.0.clone());
    let first = publisher.register(Arc::from("01"), Language::En);
    first.event(queued(1, "first.zip", None, 0));
    progress(&first, 1, 1, 2);
    let failure = Err(io::Error::other("first failure"));
    first.record(Path::new("first.zip"), &failure, false, one_root);
    first.finish(&failure, false, false, one_root);
    finish_debounce(&publisher);
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    let batch = Arc::clone(&completed.id);
    let (entered, ready) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let worker = publisher.clone();
    let thread = thread::spawn(move || {
        let report = worker.reports.publish(&completed, &worker.shared).unwrap().unwrap();
        entered.send(report.clone()).unwrap();
        released.recv().unwrap();
        assert!(!worker.shared.present_completed(&completed, || {
            panic!("old completion replaced active batch progress");
        }));
        fs::remove_file(report).unwrap();
    });
    let stale_report = ready.recv().unwrap();
    let next = publisher.register(Arc::from("02"), Language::En);
    next.event(queued(2, "next.zip", None, 0));
    progress(&next, 2, 1, 2);
    assert_eq!(current(&publisher).batch, batch.as_ref());
    assert_eq!(current(&publisher).status, "1/2 finished");
    let failure = Err(io::Error::other("second failure"));
    next.record(Path::new("next.zip"), &failure, false, one_root);
    next.finish(&failure, false, false, one_root);
    release.send(()).unwrap();
    thread.join().unwrap();
    assert!(!stale_report.exists());
    assert_eq!(publisher.shared.state.lock().unwrap().group.as_ref().unwrap().summary.failed, 2);
    finish_debounce(&publisher);
    let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
    let report = publisher.reports.publish(&completed, &publisher.shared).unwrap().unwrap();
    assert!(publisher.shared.present_completed(&completed, || {}));
    assert!(publisher.shared.state.lock().unwrap().group.is_none());
    let text = fs::read_to_string(report).unwrap();
    assert!(text.contains("first failure"));
    assert!(text.contains("second failure"));
    assert_eq!(completed.summary.failed, 2);
}
