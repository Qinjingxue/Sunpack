use super::*;

#[test]
fn shared_samples_survive_coalescing_and_retire_with_the_last_owner() {
    use std::sync::Arc;
    let registry = Arc::new(Activities::default());
    let owner = registry.bind("path", Activity::default);
    let signal = registry.bind("path", Activity::default);
    let now = Instant::now();
    let mut candidate = WatchCandidateRow {
        path: "path".into(), size: 100, mtime: 0.0,
        observation: crate::filesystem::WatchFileObservation {
            file_id: "one".into(), change_usn: 1,
            change_reasons: Some(sunpack_usn_core::ChangeReasons { all: 1, without_close: 1 }),
        },
    };
    for index in 0..20 {
        candidate.size += 1;
        candidate.mtime = index as f64 * 0.2;
        candidate.observation.change_usn += 1;
        signal.0.state.lock().unwrap().record(&candidate,
            after(now, candidate.mtime), candidate.mtime, false, None);
    }
    let before = owner.summary();
    assert!((before.0 - 0.30950540136780874).abs() < 1e-9);
    assert_eq!(owner.sample_count(), WINDOW);
    let deadline = owner.deadline().unwrap();
    assert_eq!(owner.content_deadline(&candidate, after(now, 100.0), 100.0,
        false, false, None), deadline);
    assert_eq!(owner.summary(), before); // scheduler drain does not relearn
    // An older scheduler probe cannot overwrite a newer callback sample.
    candidate.size -= 1;
    candidate.observation.change_usn -= 1;
    owner.content_deadline(&candidate, now, 0.0, false, false, None);
    assert_eq!(owner.summary(), before);
    candidate.observation.change_reasons.as_mut().unwrap().all = CLOSE;
    owner.metadata(&candidate, now);
    owner.boundary_observation(&candidate, now, 0.0, 0.5);
    assert_eq!(owner.summary(), before); // delayed CLOSE/probe cannot reset newer samples
    // Metadata-only CLOSE may shorten an existing content deadline, but
    // cannot erase a later write observed while the readiness probe ran.
    owner.metadata(&candidate, after(now, 101.0));
    owner.accelerate(after(now, 101.0), after(now, 101.0));
    assert_eq!(owner.deadline(), Some(after(now, 101.0)));
    candidate.size += 2;
    candidate.observation.change_usn += 2;
    candidate.observation.change_reasons.as_mut().unwrap().all = 1;
    owner.content_deadline(&candidate, after(now, 102.0), 102.0, false, false, None);
    let latest = owner.deadline();
    owner.accelerate(after(now, 101.0), after(now, 101.0));
    assert_eq!(owner.deadline(), latest);
    let cadence = owner.summary();
    assert_eq!(owner.content_deadline(&candidate, after(now, 103.0), 103.0,
        false, true, Some(true)), after(now, 103.0));
    assert_eq!(owner.deadline(), Some(after(now, 103.0)));
    assert_eq!(owner.summary(), cadence);
    drop(signal);
    assert_eq!(registry.0.lock().unwrap().len(), 1);
    drop(owner);
    assert!(registry.0.lock().unwrap().is_empty());
}

#[test]
fn unchanged_retries_do_not_change_saved_or_future_cadence() {
    let now = Instant::now();
    let mut expected = Quiet::default();
    let mut actual = Quiet::default();
    for at in [0.0, 1.0, 2.0, 20.0] {
        expected.content_deadline(now, at, false, false, false);
        actual.content_deadline(now, at, false, false, false);
    }
    for boundary in [false, true] {
        assert_eq!(actual.content_deadline(now, 21.0, boundary, true, true), now);
        assert_eq!((actual.seconds, actual.cadence, actual.tentative, actual.last),
            (expected.seconds, expected.cadence, expected.tentative, expected.last));
    }
    for at in [22.0, 24.0, 26.0] {
        assert_eq!(actual.content_deadline(now, at, false, false, false),
            expected.content_deadline(now, at, false, false, false));
    }
}

#[test]
fn admission_boundary_preserves_zero_quiet_and_caps_learned_windows() {
    let mut quiet = Quiet::default();
    let now = Instant::now();
    // First activity and boundary-only/busy retries do not learn a delay.
    quiet.observe(1.0, false, false, true);
    assert_eq!(quiet.boundary_deadline(now, 0.5), now);
    quiet.observe(2.0, false, false, false);
    assert_eq!(quiet.boundary_deadline(now, 0.5), now);
    quiet.seconds = 2.0;
    assert_eq!(quiet.boundary_deadline(now, 0.5), after(now, 0.5));
    quiet.seconds = 0.2;
    assert_eq!(quiet.boundary_deadline(now, 0.5), after(now, 0.2));
    quiet.observe(3.0, true, true, false);
    assert_eq!(quiet.boundary_deadline(now, 0.5), now);
}

#[test]
fn content_close_preserves_learned_quiet_and_unchanged_retry_is_immediate() {
    let mut quiet = Quiet::default();
    let now = Instant::now();
    for at in [0.0, 1.0, 2.0] {
        quiet.content_deadline(now, at, false, false, false);
    }
    let learned = quiet.seconds;
    assert!(learned > 1.0);
    let due = quiet.content_deadline(now, 3.0, true, false, false);
    assert_eq!(due, after(now, learned));
    assert!(due > after(now, 0.8)); // the next write precedes admission
    assert!(quiet.last.is_none()); // CLOSE still ends cadence learning
    assert_eq!(quiet.content_deadline(now, 4.0, true, false, true), now);
    assert_eq!(quiet.content_deadline(now, 5.0, true, true, false), now);
    assert_eq!(quiet.seconds, 0.0); // a replaced/truncated file starts anew
}
