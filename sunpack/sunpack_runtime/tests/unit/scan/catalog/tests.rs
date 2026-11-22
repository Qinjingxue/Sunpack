use super::*;

#[test]
fn only_ready_peer_set_or_content_changes_advance_the_layout_revision() {
    let mut table = ScopeCatalog::default();
    let file = |name: &str| DirectoryEntryRecord { path: name.to_owned(), ..Default::default() };
    let head = r"C:\in\beta.part1.bin";
    let middle = r"C:\in\beta.part02.bin";
    table.insert_key(head.into(), file(head));
    assert!(!table.admit_member(head, false));
    let started = current_revision();
    table.insert_key(middle.into(), file(middle));
    assert!(table.buckets["beta"].ready_revision <= started);
    assert!(table.admit_member(middle, true));
    let ready = table.buckets["beta"].ready_revision;
    assert!(ready > started);

    // Refreshing inventory or replaying admission is not a new generation.
    let mut metadata = file(middle);
    metadata.mtime_ns = Some(100);
    table.insert_key(middle.into(), metadata);
    assert!(!table.admit_member(middle, true));
    assert!(!table.admit_member(head, true));
    assert_eq!(table.buckets["beta"].ready_revision, ready);

    // A Watch content change does not wake peers until the member is ready.
    table.invalidate_member(middle);
    assert_eq!(table.buckets["beta"].ready_revision, ready);
    table.insert_key(middle.into(), file(middle));
    assert!(table.admit_member(middle, true));
    let updated = table.buckets["beta"].ready_revision;
    assert!(updated > ready);
    assert!(!table.admit_member(middle, true));
    table.remove(middle);
    assert!(table.buckets["beta"].ready_revision > updated);
}

#[test]
fn unchanged_close_still_ends_saved_phase_without_relearning_cadence() {
    let mut observation = NativeWatchObservation::new(42, 10.0, FileId::new("file"), 7);
    observation.quiet_seconds = 2.0;
    observation.cadence_seconds = 1.0;
    observation.pending_interval_seconds = 4.0;
    observation.last_content_event_at = Some(10.0);
    let mut row = CatalogRow {
        parent: Arc::from("C:\\watch"), name: "input.zip".into(),
        size: 42, mtime_ns: 0, flags: HAS_SIZE | HAS_MTIME,
        cheap_anchor: None, observation: Some(Box::new(observation)),
    };
    // Main skips activity learning for unchanged forced retries, but its
    // ordinary observation publication still honors an explicit CLOSE.
    row.remember_observation(42, 10.0, "file", 7, true);
    let saved = row.observation.as_ref().unwrap();
    assert_eq!((saved.quiet_seconds, saved.cadence_seconds), (2.0, 1.0));
    assert_eq!(saved.last_content_event_at, None);
    assert_eq!(saved.pending_interval_seconds, 0.0);
}
