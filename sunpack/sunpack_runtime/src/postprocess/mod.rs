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
    destination: &Path,
    before_move: impl FnOnce() -> io::Result<()>,
) -> FlattenStats {
    let mut stats = FlattenStats::default();
    flatten_single_branch_chain_with_publisher(
        base,
        &mut stats,
        work_path,
        leaf,
        destination,
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
    watch_candidate(path, since_usn, false)
}

pub(crate) fn watch_candidate_for_observation(
    path: &Path,
    since_usn: Option<i64>,
) -> io::Result<Option<WatchCandidateRow>> {
    watch_candidate(path, since_usn, true)
}

fn watch_candidate(
    path: &Path,
    since_usn: Option<i64>,
    report_absent: bool,
) -> io::Result<Option<WatchCandidateRow>> {
    // An unobservable candidate ends this admission attempt, as in main.
    // USN and readiness failures remain separately classified below.
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if report_absent && matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => {
            return Err(error);
        }
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
    Resume { leaf: &'a Path, published: bool },
}

#[cfg(test)]
fn flatten_single_branch_chain(root: &Path, stats: &mut FlattenStats) {
    let Some(leaf) = discover_flatten_leaf(root) else { return; };
    flatten_single_branch_chain_with_publisher(
        root,
        stats,
        &root.with_extension("flatten-work"),
        FlattenLeaf::Prepared(&leaf),
        root,
        rename_no_replace,
        || Ok(()),
    );
}

fn flatten_single_branch_chain_with_publisher(
    root: &Path,
    stats: &mut FlattenStats,
    work: &Path,
    leaf: FlattenLeaf<'_>,
    destination: &Path,
    publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
    before_move: impl FnOnce() -> io::Result<()>,
) {
    let (leaf, resume, published) = match leaf {
        FlattenLeaf::Prepared(path) => (path, false, false),
        FlattenLeaf::Resume { leaf, published } => (leaf, true, published),
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
        if let Err(error) = before_move().and_then(|_| rename_no_replace(root, work)) {
            stats
                .errors
                .push(format!("{}: {error}", normalize_path(work)));
            return;
        }
    }
    stats.output_dir = Some(work.to_path_buf());
    stats.source_dir = Some(root.to_path_buf());
    let leaf_in_work = work.join(leaf_relative);
    if !published {
        if let Err(error) = publish(&leaf_in_work, destination) {
            stats.errors.push(format!(
                "{} -> {}: {}",
                normalize_path(&leaf_in_work),
                normalize_path(destination),
                error
            ));
            // Keep the complete payload under work if exclusive publication fails.
            return;
        }
    }
    stats.moved += 1;
    stats.output_dir = Some(destination.to_path_buf());
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

pub(crate) fn mtime_seconds(metadata: &fs::Metadata) -> f64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
#[path = "../../tests/unit/postprocess/tests.rs"]
mod tests;

pub(crate) fn watch_content_changed(
    size: u64,
    mtime: f64,
    id: &str,
    usn: i64,
    current: &WatchCandidateRow,
) -> bool {
    watch_observed_content_changed(size, mtime, id, usn, current.size, current.mtime, &current.observation)
}

pub(crate) fn watch_observed_content_changed(
    size: u64,
    mtime: f64,
    id: &str,
    usn: i64,
    current_size: u64,
    current_mtime: f64,
    observation: &WatchFileObservation,
) -> bool {
    if id != observation.file_id || size != current_size {
        return true;
    }
    if usn == observation.change_usn {
        return false;
    }
    if let Some(reasons) = observation.change_reasons {
        return reasons.without_close & 7 != 0;
    }
    current_mtime >= mtime - 2.0
}

/// Recovery permissions belong to the original location as well as its bytes.
pub(crate) fn watch_source_changed(size: u64, mtime: f64, id: &str, usn: i64, current: &WatchCandidateRow) -> bool {
    watch_content_changed(size, mtime, id, usn, current)
        || (usn != current.observation.change_usn && current.observation.change_reasons
            .is_some_and(|reasons| reasons.without_close & 0x3000 != 0))
}
