use crate::io::atomic_file::rename_no_replace;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::filesystem::{watch_file_observation_known_kind, WatchFileObservation};

#[derive(Clone)]
pub(crate) struct WatchCandidateRow {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) mtime: f64,
    pub(crate) observation: WatchFileObservation,
}

pub(crate) fn flatten_single_branch_directories(
    base: &Path,
    work_path: &Path,
    leaf: FlattenLeaf<'_>,
    before_move: impl FnOnce(&Path, &Path, &Path) -> io::Result<()>,
) -> FlattenStats {
    let mut stats = FlattenStats::default();
    flatten_single_branch_chain_with_publisher(
        base,
        &mut stats,
        work_path,
        leaf,
        rename_no_replace,
        before_move,
    );
    stats
}

pub(crate) fn remove_owned_file(path: &Path) -> io::Result<()> {
    remove_with_readonly(path, |path| fs::remove_file(path))
}

fn remove_with_readonly(path: &Path, remove: impl Fn(&Path) -> io::Result<()>) -> io::Result<()> {
    match remove(path) {
        #[cfg(windows)]
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            use std::os::windows::fs::MetadataExt;
            let metadata = fs::symlink_metadata(path)?;
            let permissions = metadata.permissions();
            // Never change a reparse target's attributes. Only deletion-owned
            // regular entries may have their read-only bit cleared.
            if !permissions.readonly() || metadata.file_attributes() & 0x400 != 0 {
                return Err(error);
            }
            let mut writable = permissions.clone();
            writable.set_readonly(false);
            fs::set_permissions(path, writable)?;
            let result = remove(path);
            if result.is_err() {
                let _ = fs::set_permissions(path, permissions);
            }
            result
        }
        result => result,
    }
}

pub(crate) fn remove_owned_tree(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let metadata = fs::symlink_metadata(path)?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(error);
                }
            }
            if !metadata.is_dir() {
                return Err(error);
            }
            // The normal path uses std's native tree removal. Walk only the
            // retained subtree after a read-only/permission failure, streaming
            // entries without following directory links.
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() && !kind.is_symlink() {
                    remove_owned_tree(&entry.path())?;
                } else {
                    remove_owned_file(&entry.path())?;
                }
            }
            remove_with_readonly(path, |path| fs::remove_dir(path))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
// Inject after successful metadata, at the identity/USN observation boundary.
pub(crate) static WATCH_OBSERVATION_FAILURE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

pub(crate) fn watch_candidate_for_path(
    path: &Path,
    since_usn: Option<i64>,
) -> io::Result<Option<WatchCandidateRow>> {
    // An unobservable candidate ends this admission attempt, as in main.
    // USN and readiness failures remain separately classified below.
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    watch_candidate_from_metadata(path, &metadata, since_usn)
}

fn watch_candidate_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    since_usn: Option<i64>,
) -> io::Result<Option<WatchCandidateRow>> {
    if metadata.len() == 0 {
        return Ok(None);
    }
    #[cfg(test)]
    if WATCH_OBSERVATION_FAILURE.lock().unwrap().as_deref() == Some(path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected identity observation failure"));
    }
    let observation = watch_file_observation_known_kind(path, since_usn, false)?;
    Ok(Some(WatchCandidateRow {
        path: normalize_path(path),
        size: metadata.len(),
        mtime: mtime_seconds(metadata),
        observation,
    }))
}

#[derive(Default)]
pub(crate) struct FlattenStats {
    pub(crate) moved: usize,
    pub(crate) removed_dirs: usize,
    pub(crate) errors: Vec<String>,
    pub(crate) output_dir: Option<PathBuf>,
    pub(crate) source_dir: Option<PathBuf>,
}

pub(crate) enum FlattenLeaf<'a> {
    Prepared(&'a Path),
    Resume(&'a Path),
}

#[cfg(test)]
fn flatten_single_branch_chain(root: &Path, stats: &mut FlattenStats) {
    let Some(leaf) = discover_flatten_leaf(root) else { return; };
    flatten_single_branch_chain_with_publisher(
        root,
        stats,
        &root.with_extension("flatten-work"),
        FlattenLeaf::Prepared(&leaf),
        rename_no_replace,
        |_, _, _| Ok(()),
    );
}

fn flatten_single_branch_chain_with_publisher(
    root: &Path,
    stats: &mut FlattenStats,
    work: &Path,
    leaf: FlattenLeaf<'_>,
    publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
    before_move: impl FnOnce(&Path, &Path, &Path) -> io::Result<()>,
) {
    let (leaf, resume) = match leaf {
        FlattenLeaf::Prepared(path) => (path, false),
        FlattenLeaf::Resume(path) => (path, true),
    };
    let leaf_relative = match leaf.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative,
        _ => {
            stats.errors.push(format!(
                "{}: flatten leaf is not below output root",
                normalize_path(root)
            ));
            return;
        }
    };

    if !resume {
        if let Err(error) = before_move(root, work, leaf).and_then(|_| rename_no_replace(root, work)) {
            stats
                .errors
                .push(format!("{}: {error}", normalize_path(work)));
            return;
        }
    }
    stats.output_dir = Some(work.to_path_buf());
    stats.source_dir = Some(root.to_path_buf());
    let leaf_in_work = work.join(leaf_relative);
    if let Err(error) = if resume && root.is_dir() {
        Ok(())
    } else {
        publish(&leaf_in_work, root)
    } {
        stats.errors.push(format!(
            "{} -> {}: {}",
            normalize_path(&leaf_in_work),
            normalize_path(root),
            error
        ));
        // Do not merge, overwrite, or clean up on failure.  The complete payload
        // remains under the visible work directory for straightforward inspection.
        return;
    }
    stats.moved += 1;
    stats.output_dir = Some(root.to_path_buf());
    stats.source_dir = Some(leaf.to_path_buf());

    match remove_empty_flatten_wrappers(work, leaf_relative) {
        Ok(removed) => stats.removed_dirs += removed,
        Err(error) => stats.errors.push(error),
    }
}

pub(crate) fn discover_flatten_leaf(root: &Path) -> Option<PathBuf> {
    let mut current = only_child_directory(root)?;
    while let Some(child) = only_child_directory(&current) {
        current = child;
    }
    Some(current)
}

fn only_child_directory(dir: &Path) -> Option<PathBuf> {
    let mut entries = fs::read_dir(dir).ok()?;
    let first = entries.next()?.ok()?;
    if entries.next().is_some() {
        return None;
    }
    first.metadata().ok()?.is_dir().then(|| first.path())
}


fn remove_empty_flatten_wrappers(work: &Path, leaf_relative: &Path) -> Result<usize, String> {
    let leaf = work.join(leaf_relative);
    let mut current = leaf.parent().map(Path::to_path_buf);
    let mut removed = 0usize;

    while let Some(directory) = current {
        if !directory.starts_with(work) {
            break;
        }
        match fs::remove_dir(&directory) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("{}: {}", normalize_path(&directory), error));
            }
        }
        if directory == work {
            break;
        }
        current = directory.parent().map(Path::to_path_buf);
    }

    Ok(removed)
}

fn normalize_path(path: &Path) -> String {
    let text = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();
    crate::path_keys::normalize_windows_extended_prefix(text)
}

fn mtime_seconds(metadata: &fs::Metadata) -> f64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
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
}

pub(crate) fn watch_content_changed(
    size: u64,
    mtime: f64,
    id: &str,
    usn: i64,
    current: &WatchCandidateRow,
) -> bool {
    if id != current.observation.file_id || size != current.size {
        return true;
    }
    if usn == current.observation.change_usn {
        return false;
    }
    if let Some(reasons) = current.observation.change_reasons {
        return reasons.without_close & 7 != 0;
    }
    current.mtime >= mtime - 2.0
}

/// Recovery permissions belong to the original location as well as its bytes.
pub(crate) fn watch_source_changed(size: u64, mtime: f64, id: &str, usn: i64, current: &WatchCandidateRow) -> bool {
    watch_content_changed(size, mtime, id, usn, current)
        || (usn != current.observation.change_usn && current.observation.change_reasons
            .is_some_and(|reasons| reasons.without_close & 0x3000 != 0))
}
