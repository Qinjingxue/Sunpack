use super::*;

#[test]
fn unobservable_metadata_retires_candidate_without_retry() {
    // An invalid native path deterministically fails metadata even under
    // an elevated test account; it does not exercise the share-open path.
    let path = Path::new("invalid\0candidate.zip");
    assert!(fs::metadata(path).is_err());
    assert!(watch_candidate_for_path(path, None).unwrap().is_none());
}

use std::time::{SystemTime, UNIX_EPOCH};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sunpack-postprocess-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be created");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn flatten_stops_at_first_branching_level() {
    let output = TestDirectory::new("branching");
    let build = output.path().join("Build");
    fs::create_dir_all(build.join("Plugins/x86_64")).unwrap();
    fs::create_dir_all(build.join("StreamingAssets/aa")).unwrap();
    fs::write(build.join("Clicker.exe"), b"exe").unwrap();
    fs::write(build.join("Plugins/x86_64/plugin.dll"), b"dll").unwrap();
    fs::write(build.join("StreamingAssets/aa/catalog.bin"), b"catalog").unwrap();

    let mut stats = FlattenStats::default();
    flatten_single_branch_chain(output.path(), &mut stats);

    assert!(!output.path().join("Build").exists());
    assert!(output.path().join("Clicker.exe").is_file());
    assert!(output.path().join("Plugins/x86_64/plugin.dll").is_file());
    assert!(output
        .path()
        .join("StreamingAssets/aa/catalog.bin")
        .is_file());
    assert_eq!(stats.removed_dirs, 1);
    assert_eq!(stats.output_dir.as_deref(), Some(output.path()));
    assert_eq!(stats.source_dir.as_ref(), Some(&build));
    assert!(stats.errors.is_empty());
}

#[cfg(windows)]
#[test]
fn flatten_keeps_last_proven_level_when_deeper_enumeration_fails() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE};

    let output = TestDirectory::new("locked_leaf");
    let leaf = output.path().join("wrapper");
    fs::create_dir(&leaf).unwrap();
    fs::write(leaf.join("payload"), b"payload").unwrap();
    // Permit the directory entry to be inspected, but deny a new listing
    // handle. The lock is released before publishing the discovered leaf.
    let locked = fs::OpenOptions::new().read(true)
        .share_mode(FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&leaf).unwrap();
    assert!(fs::read_dir(&leaf).is_err());

    let discovered = discover_flatten_leaf(output.path()).unwrap();
    drop(locked);

    assert_eq!(discovered, leaf);
}

#[test]
fn flatten_continues_along_an_unbranched_directory_chain() {
    let output = TestDirectory::new("chain");
    let payload = output.path().join("outer/inner/payload.txt");
    fs::create_dir_all(payload.parent().unwrap()).unwrap();
    fs::write(&payload, b"payload").unwrap();

    let mut stats = FlattenStats::default();
    flatten_single_branch_chain(output.path(), &mut stats);

    assert!(output.path().join("payload.txt").is_file());
    assert!(!output.path().join("outer").exists());
    assert!(!output.path().join("inner").exists());
    assert_eq!(stats.removed_dirs, 2);
    assert_eq!(stats.output_dir.as_deref(), Some(output.path()));
    assert_eq!(stats.source_dir.as_deref(), payload.parent());
    assert!(stats.errors.is_empty());
}

#[cfg(windows)]
#[test]
fn flatten_moves_directories_beyond_win32_max_path() {
    let container = TestDirectory::new("long_path");
    let output = container.path().join("x".repeat(130)).join("y".repeat(130));
    assert!(output.as_os_str().len() > 260);
    fs::create_dir_all(output.join("wrapper/first")).unwrap();
    fs::create_dir_all(output.join("wrapper/second")).unwrap();

    let mut stats = FlattenStats::default();
    flatten_single_branch_chain(&output, &mut stats);

    assert!(stats.errors.is_empty(), "{:?}", stats.errors);
    assert!(output.join("first").is_dir() && output.join("second").is_dir());
    assert!(!output.join("wrapper").exists());
}

#[test]
fn flatten_publish_failure_reports_retained_payload_without_touching_collision() {
    let container = TestDirectory::new("publish_failure");
    let output = container.path().join("output");
    fs::create_dir_all(output.join("outer/inner")).unwrap();
    fs::write(output.join("outer/inner/payload.txt"), b"payload").unwrap();
    let mut stats = FlattenStats::default();
    flatten_single_branch_chain_with_publisher(
        &output,
        &mut stats,
        &container.path().join("flatten-work"),
        FlattenLeaf::Prepared(&output.join("outer/inner")),
        |leaf, root| {
            fs::create_dir(root)?;
            fs::write(root.join("unrelated.txt"), b"unrelated")?;
            rename_no_replace(leaf, root)
        },
        |_, _, _| Ok(()),
    );
    let retained = stats.output_dir.as_ref().unwrap();
    assert_ne!(retained, &output);
    assert_eq!(stats.source_dir.as_ref(), Some(&output));
    assert_eq!(
        fs::read(retained.join("outer/inner/payload.txt")).unwrap(),
        b"payload"
    );
    assert_eq!(
        fs::read(output.join("unrelated.txt")).unwrap(),
        b"unrelated"
    );
    assert_eq!(stats.moved, 0);
    assert_eq!(stats.removed_dirs, 0);
    assert_eq!(stats.errors.len(), 1);
}
