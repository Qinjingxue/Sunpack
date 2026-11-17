use super::*;

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
