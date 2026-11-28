use super::*;

#[test]
fn unobservable_metadata_retires_candidate_without_retry() {
    // An invalid native path deterministically fails metadata even under
    // an elevated test account; it does not exercise the share-open path.
    let path = Path::new("invalid\0candidate.zip");
    assert!(fs::metadata(path).is_err());
    assert!(watch_candidate_for_path(path, None).unwrap().is_none());
}

#[test]
fn watch_observation_keeps_its_path_and_file_identity_during_rename() {
    let directory = TestDirectory::new("cross-root-observation");
    let left = directory.path().join("left");
    let right = directory.path().join("right");
    fs::create_dir(&left).unwrap();
    fs::create_dir(&right).unwrap();
    let path = left.join("delivery.zip");
    let destination = right.join("delivery.zip");
    let replacement = left.join("replacement.zip");
    fs::write(&path, b"original").unwrap();
    fs::write(&replacement, b"replacement bytes").unwrap();
    let original = watch_candidate_for_path(&path, None).unwrap().unwrap();

    *WATCH_OBSERVATION_HOOK.lock().unwrap() = Some((path.clone(), |path| {
        let left = path.parent().unwrap();
        let new_name = left.parent().unwrap().join("right").join(path.file_name().unwrap());
        fs::rename(path, new_name)?;
        fs::rename(left.join("replacement.zip"), path)
    }));
    let sampled = watch_candidate_with_generation(&path, None);
    *WATCH_OBSERVATION_HOOK.lock().unwrap() = None;
    let (sampled, generation) = sampled.unwrap().unwrap();
    let moved = watch_candidate_for_path(&destination, None).unwrap().unwrap();
    let reused = watch_candidate_for_path(&path, None).unwrap().unwrap();

    assert_eq!(Path::new(&sampled.path), path);
    assert_eq!(sampled.size, original.size);
    assert_eq!(sampled.observation.file_id, moved.observation.file_id);
    assert_ne!(sampled.observation.file_id, reused.observation.file_id);
    assert_eq!(generation, crate::io::reader::capture_file_generation(&destination).unwrap());
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

fn flatten(root: &Path) {
    let work = root.with_extension("flatten-work");
    let leaf = discover_flatten_leaf(root).unwrap();
    let outcome = flatten_single_branch_directories(root, &work, FlattenLeaf::Prepared(&leaf), root, || Ok(()));
    assert!(matches!(outcome, FlattenOutcome::Published { cleanup_error: None }), "{outcome:?}");
    assert!(!work.exists());
}

#[test]
fn flatten_follows_single_branch_chain_to_first_branching_level() {
    let output = TestDirectory::new("branching");
    let build = output.path().join("wrapper/Build");
    fs::create_dir_all(build.join("Plugins/x86_64")).unwrap();
    fs::create_dir_all(build.join("StreamingAssets/aa")).unwrap();
    fs::write(build.join("Clicker.exe"), b"exe").unwrap();
    fs::write(build.join("Plugins/x86_64/plugin.dll"), b"dll").unwrap();
    fs::write(build.join("StreamingAssets/aa/catalog.bin"), b"catalog").unwrap();

    flatten(output.path());

    assert!(!output.path().join("wrapper").exists());
    assert!(!output.path().join("Build").exists());
    assert!(output.path().join("Clicker.exe").is_file());
    assert!(output.path().join("Plugins/x86_64/plugin.dll").is_file());
    assert!(output
        .path()
        .join("StreamingAssets/aa/catalog.bin")
        .is_file());
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

#[cfg(windows)]
#[test]
fn flatten_moves_directories_beyond_win32_max_path() {
    let container = TestDirectory::new("long_path");
    let output = container.path().join("x".repeat(130)).join("y".repeat(130));
    assert!(output.as_os_str().len() > 260);
    fs::create_dir_all(output.join("wrapper/first")).unwrap();
    fs::create_dir_all(output.join("wrapper/second")).unwrap();

    flatten(&output);

    assert!(output.join("first").is_dir() && output.join("second").is_dir());
    assert!(!output.join("wrapper").exists());
}

#[test]
fn flatten_publish_failure_reports_retained_payload_without_touching_collision() {
    let container = TestDirectory::new("publish_failure");
    let output = container.path().join("output");
    let destination = container.path().join("inner");
    fs::create_dir_all(output.join("outer/inner")).unwrap();
    fs::write(output.join("outer/inner/payload.txt"), b"payload").unwrap();
    let work = container.path().join("flatten-work");
    let outcome = flatten_single_branch_directories(
        &output,
        &work,
        FlattenLeaf::Prepared(&output.join("outer/inner")),
        &destination,
        || {
            fs::create_dir(&destination)?;
            fs::write(destination.join("unrelated.txt"), b"unrelated")
        },
    );
    assert!(matches!(outcome, FlattenOutcome::Staged(_)), "{outcome:?}");
    assert!(!output.exists());
    assert_eq!(
        fs::read(work.join("outer/inner/payload.txt")).unwrap(),
        b"payload"
    );
    assert_eq!(
        fs::read(destination.join("unrelated.txt")).unwrap(),
        b"unrelated"
    );
}
