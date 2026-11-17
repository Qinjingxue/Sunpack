use super::*;
use std::sync::mpsc;

#[test]
fn replaced_password_snapshot_returns_typed_retirement() {
    let path = crate::test_support::temp_file("retired_password_snapshot", b"old");
    let reader = ManagedReader::open(&path).unwrap();
    let old = InputKey::file("rar", &reader).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let borrower = std::thread::spawn(move || {
        Preparation::default().verify(old, &[], move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Err(PreparedStatus::new("damaged", "obsolete verdict"))
        })
    });
    entered_rx.recv().unwrap();
    std::fs::write(&path, b"new physical generation").unwrap();
    let current = ManagedReader::open(&path).unwrap();
    let key = InputKey::file("rar", &current).unwrap();
    let new = Preparation::default().verify(key, &[], || {
        Err(PreparedStatus::new("not_required", "current verdict"))
    });
    release_tx.send(()).unwrap();
    let error = borrower.join().unwrap().unwrap_err();
    assert!(error.get_ref().is_some_and(|error| error.is::<InputChanged>()));
    assert!(!std::io::Error::other(error.to_string()).get_ref().is_some_and(|error| error.is::<InputChanged>()));
    assert_eq!(new.unwrap().status, "not_required");

    let canonical = current.file_identity().unwrap().path.to_path_buf();
    release_under_roots(&[canonical]);
    drop((reader, current));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn cancelled_initializer_does_not_publish_damage_to_shared_password_input() {
    use crate::io::cancellation::Cancellation;
    let path = crate::test_support::temp_file("cancel_prepare", b"physical generation");
    let reader = ManagedReader::open(&path).unwrap();
    let key = InputKey::file("rar", &reader).unwrap();
    let owner_key = key.clone();
    let borrower_key = key.clone();
    let signal = Cancellation::new();
    let owner_signal = signal.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let owner = std::thread::spawn(move || {
        owner_signal.run(|| {
            Preparation::default().verify(owner_key, &[], move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(PreparedStatus::new("damaged", "abandoned initializer"))
            })
            .unwrap_err()
            .to_string()
        })
    });
    entered_rx.recv().unwrap();
    // Acquire the owner's exact slot before revoking it. A waiter on
    // this generation must see an abandoned initialization even if
    // the slot is already removed from the map when it resumes.
    let mut borrowed = Preparation { slot: Some(borrow(&key)), rar5_key: None };
    let borrower = std::thread::spawn(move || {
        let result = borrowed.verify(borrower_key.clone(), &[], || {
            Err(PreparedStatus::new("not_required", "surviving initializer"))
        }).unwrap();
        assert_eq!(borrowed.verify(borrower_key, &[], || {
            panic!("successful preparation must be reused across batches")
        }).unwrap().status, "not_required");
        result.status
    });
    signal.cancel();
    release_tx.send(()).unwrap();
    assert_eq!(owner.join().unwrap(), "native operation cancelled");
    assert_eq!(borrower.join().unwrap(), "not_required");
    assert!(ACTIVE.lock().unwrap().iter().all(|slot| slot.key != key));
    drop(reader);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn concurrent_volume_snapshots_preserve_independent_password_facts() {
    // Arrival tests hit this overlap only by chance; cancellation tests use
    // one identical key. Block one initializer while a larger snapshot
    // completes, then check both cached verdicts without KDF/payload work.
    let root = std::env::temp_dir().join(format!(
        "sunpack_password_snapshots_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let readers: Vec<_> = (1..=4)
        .map(|number| {
            let path = root.join(format!("part{number}.bin"));
            std::fs::write(&path, b"unchanged physical generation").unwrap();
            ManagedReader::open(path).unwrap()
        })
        .collect();
    let members: Vec<_> = readers
        .iter()
        .enumerate()
        .map(|(index, reader)| InputMember::new(reader, 0, None, index as u32 + 1).unwrap())
        .collect();
    let partial = InputKey::new("rar", "volumes", members[..2].to_vec());
    let complete = InputKey::new("rar", "volumes", members);
    let owner_key = partial.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let owner = std::thread::spawn(move || {
        let mut plan = Preparation::default();
        let first = plan.verify(owner_key.clone(), &[], move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Err(PreparedStatus::new("missing_volume", "partial snapshot"))
        }).unwrap();
        assert_eq!(plan.verify(owner_key, &[], || panic!("preparation lost")).unwrap().status, first.status);
        first.status
    });
    entered_rx.recv().unwrap();
    let mut new_plan = Preparation::default();
    let newer = new_plan.verify(complete.clone(), &[], || {
        Err(PreparedStatus::new("not_required", "complete snapshot"))
    }).unwrap();
    release_tx.send(()).unwrap();
    let older = owner.join().unwrap();
    assert_eq!(new_plan.verify(complete.clone(), &[], || panic!("preparation lost")).unwrap().status, newer.status);
    drop(new_plan);
    assert!(ACTIVE.lock().unwrap().iter().all(|slot| slot.key != partial && slot.key != complete));
    drop(readers);
    std::fs::remove_dir_all(root).unwrap();

    assert_eq!(older, "missing_volume");
    assert_eq!(newer.status, "not_required");
}
