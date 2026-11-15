use super::{atomic_file, fs, io, publish, Document, IndexBuilder, PasswordSnapshot, Write};
use std::path::Path;

#[test]
fn builtin_password_documents_require_objects() {
    assert!(Document::parse(r#"[[{"value":"secret"}]]"#).is_err());
    assert!(Document::parse(r#"{"passwords":[["secret"]]}"#)
        .unwrap().read_passwords(None).is_err());
    assert!(Document::parse(r#"{"passwords":[{"value":"secret"}]}"#)
        .unwrap().read_passwords(None).is_ok());
}

#[test]
fn password_notification_overrides_an_unchanged_request_stamp() {
    use super::{physical_file_generation, BuiltinStore, StoreState, TrackedFile};
    let path = crate::test_support::temp_file("builtin_password_notify", br#"{"passwords":[{"value":"old"}]}"#);
    let store = BuiltinStore { path: path.clone(), state: std::sync::Mutex::new(StoreState::default()), dirty: Default::default() };
    assert_eq!(store.reload().unwrap().global()[0].as_ref(), "old");

    fs::write(&path, br#"{"passwords":[{"value":"new"}]}"#).unwrap();
    // Simulate an edit that leaves the cached generation unchanged.
    store.state.lock().unwrap().generation = physical_file_generation(&TrackedFile::open_reader(&path).unwrap()).ok();
    assert!(store.state.lock().unwrap().generation.is_some());
    store.invalidate();
    assert_eq!(store.snapshot_for_request().global()[0].as_ref(), "new");
    assert_eq!(store.observed_snapshot().global()[0].as_ref(), "new");
    fs::remove_file(path).unwrap();
}

#[test]
fn clipboard_save_reports_share_conflict_without_waiting_for_reader() {
    use std::{os::windows::fs::OpenOptionsExt, sync::{mpsc, Mutex}, time::Duration};
    let path = crate::test_support::temp_file("clipboard_share_conflict", br#"{"passwords":[],"clipboard_history":[]}"#);
    let reader = fs::OpenOptions::new().read(true).share_mode(3).open(&path).unwrap();
    let store = super::BuiltinStore { path: path.clone(), state: Mutex::default(), dirty: Default::default() };
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(store.merge_clipboard(&["new-password".into()], 30)).unwrap();
    });
    let result = receive.recv_timeout(Duration::from_secs(5));
    // Release before asserting so the former retry loop cannot leak a
    // worker or keep the test process alive on a regression.
    drop(reader);
    worker.join().unwrap();
    let error = result.expect("clipboard save waited for an external reader").unwrap_err();
    assert!(matches!(error.raw_os_error(), Some(32 | 33)));
    assert_eq!(fs::read(&path).unwrap(), br#"{"passwords":[],"clipboard_history":[]}"#);
    fs::remove_file(path).unwrap();
}

#[test]
fn clipboard_merge_moves_repeated_values_to_the_end_in_copy_order() {
    use super::BuiltinStore;
    let path = crate::test_support::temp_file("clipboard_merge_order", br#"{"passwords":[{"value":"configured"}],"clipboard_history":["old","copied","old","retained"]}"#);
    let store = BuiltinStore { path: path.clone(), state: Default::default(), dirty: Default::default() };
    let copied = ["copied".to_owned(), "new".to_owned(), "copied".to_owned()];
    assert!(store.merge_clipboard(&copied, 3).unwrap());
    assert!(!store.merge_clipboard(&copied, 3).unwrap());
    let snapshot = store.reload().unwrap();
    assert_eq!(snapshot.global().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
        ["configured", "retained", "copied", "new"]);
    fs::remove_file(path).unwrap();
}

#[test]
fn default_password_publication_preserves_concurrent_edit() {
    let path = crate::test_support::temp_file("builtin_password_creation", b"");
    fs::remove_file(&path).unwrap();
    let result = publish(&path, atomic_file::rename_no_replace, |file| {
        file.write_all(b"default")?;
        fs::write(&path, b"user edit")
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), b"user edit");
    fs::remove_file(path).unwrap();
}

#[test]
fn persisted_password_signatures_survive_runtime_migration() {
    let text = r##"{
        "passwords": [
            {"value":"世界"},
            {"value":"#literal"},
            {"value":" secret ","scopes":["C:\\Downloads"]},
            {"value":"child","scopes":["C:\\Downloads\\child"]}
        ]
    }"##;
    let mut index = IndexBuilder::default();
    Document::parse(text)
        .unwrap()
        .read_passwords(Some(&mut index))
        .unwrap();
    let snapshot = index.finish(&PasswordSnapshot::default()).unwrap();
    // Existing Watch records contain these fingerprints. A schema or
    // ordering change here would retry unchanged failed archives on upgrade.
    assert_eq!(snapshot.signature(), "0871aed6a34a4efb389027260eaaf30f");
    assert_eq!(
        snapshot.scope_signature(Path::new(r"C:\Downloads\child\deep")),
        "7fa575ff785f4d5a6e3e7afaa5e05bcb",
    );
    assert_eq!(
        snapshot.scope_signature(Path::new(r"C:\different")),
        "a55be77812b08557859dab8291a7ac45",
    );
    // A scoped edit changes only receipts that inherit that bucket, not
    // every password failure under an unrelated Watch root.
    let mut changed = IndexBuilder::default();
    Document::parse(&text.replace("\"value\":\"child\"", "\"value\":\"new child\""))
        .unwrap().read_passwords(Some(&mut changed)).unwrap();
    let changed = changed.finish(&snapshot).unwrap();
    assert_ne!(snapshot.scope_signature(Path::new(r"C:\Downloads\child\deep")),
        changed.scope_signature(Path::new(r"C:\Downloads\child\deep")));
    assert_eq!(snapshot.scope_signature(Path::new(r"C:\different")),
        changed.scope_signature(Path::new(r"C:\different")));

}
