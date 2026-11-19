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

#[cfg_attr(test, derive(Debug))]
pub(crate) enum FlattenOutcome {
    Unmoved(String),
    Staged(String),
    Published { cleanup_error: Option<String> },
}

pub(crate) enum FlattenLeaf<'a> {
    Prepared(&'a Path),
    Resume { leaf: &'a Path, published: bool },
}

pub(crate) fn flatten_single_branch_directories(
    root: &Path,
    work: &Path,
    leaf: FlattenLeaf<'_>,
    destination: &Path,
    before_move: impl FnOnce() -> io::Result<()>,
) -> FlattenOutcome {
    let (leaf, resume, published) = match leaf {
        FlattenLeaf::Prepared(path) => (path, false, false),
        FlattenLeaf::Resume { leaf, published } => (leaf, true, published),
    };
    let leaf_relative = match leaf.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative,
        _ => {
            return FlattenOutcome::Unmoved(format!(
                "{}: flatten leaf is not below output root",
                normalize_path(root)
            ));
        }
    };

    if !resume {
        if let Err(error) = before_move().and_then(|_| rename_no_replace(root, work)) {
            return FlattenOutcome::Unmoved(format!("{}: {error}", normalize_path(work)));
        }
    }
    let leaf_in_work = work.join(leaf_relative);
    if !published {
        if let Err(error) = rename_no_replace(&leaf_in_work, destination) {
            // Keep the complete payload under work if exclusive publication fails.
            return FlattenOutcome::Staged(format!(
                "{} -> {}: {}",
                normalize_path(&leaf_in_work),
                normalize_path(destination),
                error
            ));
        }
    }
    FlattenOutcome::Published {
        cleanup_error: remove_empty_flatten_wrappers(work, &leaf_in_work).err(),
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


fn remove_empty_flatten_wrappers(work: &Path, leaf: &Path) -> Result<(), String> {
    for directory in leaf.ancestors().skip(1) {
        if !directory.starts_with(work) {
            break;
        }
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("{}: {}", normalize_path(directory), error));
            }
        }
        if directory == work {
            break;
        }
    }

    Ok(())
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
    id != current.observation.file_id || size != current.size || watch_usn_content_changed(
        mtime, usn, current.mtime, current.observation.change_usn, current.observation.change_reasons,
    )
}

pub(crate) fn watch_usn_content_changed(
    mtime: f64,
    usn: i64,
    current_mtime: f64,
    current_usn: i64,
    change_reasons: Option<sunpack_usn_core::ChangeReasons>,
) -> bool {
    if usn == current_usn {
        return false;
    }
    if let Some(reasons) = change_reasons {
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
