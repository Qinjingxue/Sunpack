use crate::io::directory_errors::{DirectoryReadError, DirectoryReadErrors};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

type PromotionResult = (
    HashMap<String, String>,
    Vec<String>,
    Vec<String>,
    String,
    bool,
);

#[pyclass(frozen)]
pub(crate) struct NativeBlockedInputPromotion {
    moves: Vec<(PathBuf, PathBuf)>,
    destination: PathBuf,
    // Shared with Python leases/WAL and the result; convert paths only once.
    #[pyo3(get)]
    path_map: Py<PyDict>,
}

#[pymethods]
impl NativeBlockedInputPromotion {
    #[new]
    fn new(py: Python<'_>, paths: Vec<String>, destination_dir: String) -> PyResult<Self> {
        let destination = PathBuf::from(destination_dir);
        let moves = py.detach(|| plan_promotion_moves(paths, &destination))?;
        let path_map = PyDict::new(py);
        for (source, target) in &moves {
            path_map.set_item(normalize_path(source), normalize_path(target))?;
        }
        Ok(Self {
            moves,
            destination,
            path_map: path_map.unbind(),
        })
    }

    #[pyo3(signature = (before_move=None))]
    fn execute(
        &self,
        py: Python<'_>,
        before_move: Option<Py<PyAny>>,
    ) -> PyResult<(Py<PyDict>, Vec<String>, Vec<String>, String, bool)> {
        let (mapping, removed, touched, error, collision) = py.detach(|| {
            promote_input_files_with_move(
                &self.moves,
                &self.destination,
                || {
                    if let Some(callback) = before_move {
                        Python::attach(|py| callback.call0(py))
                            .map_err(|error| io::Error::other(error.to_string()))?;
                    }
                    Ok(())
                },
                move_input_no_replace,
            )
        });
        let path_map = if error.is_empty() {
            self.path_map.clone_ref(py)
        } else {
            let partial = PyDict::new(py);
            for (source, target) in mapping {
                partial.set_item(source, target)?;
            }
            partial.unbind()
        };
        Ok((path_map, removed, touched, error, collision))
    }
}

fn plan_promotion_moves(
    paths: Vec<String>,
    destination: &Path,
) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    static NEXT_ALIAS: AtomicU64 = AtomicU64::new(0);
    let mut destinations = HashSet::new();
    let mut sources = HashSet::new();
    let mut moves = Vec::new();
    for raw in paths {
        let source = PathBuf::from(raw);
        if !sources.insert(crate::path_keys::path_key(&normalize_path(&source))) {
            continue;
        }
        let Some(name) = source.file_name() else {
            return Err(io::Error::other("input has no basename"));
        };
        if !source.metadata()?.is_file() {
            return Err(io::Error::other(format!(
                "not an input file: {}",
                source.display()
            )));
        }
        let mut target = destination.join(name);
        while target.try_exists()?
            || destinations.contains(&crate::path_keys::path_key(&normalize_path(&target)))
        {
            // Keep the first-dot bucket and every original numeric channel.
            // Alphabetic aliases introduce neither volume numbers nor format hints.
            let mut value = NEXT_ALIAS.fetch_add(1, Ordering::Relaxed);
            let mut suffix = String::from(".__sunpack_");
            loop {
                suffix.push((b'a' + (value & 15) as u8) as char);
                value >>= 4;
                if value == 0 {
                    break;
                }
            }
            let mut alias = name.to_os_string();
            alias.push(suffix);
            target = destination.join(alias);
        }
        destinations.insert(crate::path_keys::path_key(&normalize_path(&target)));
        moves.push((source, target));
    }
    Ok(moves)
}

fn promote_input_files_with_move(
    moves: &[(PathBuf, PathBuf)],
    destination: &Path,
    before_move: impl FnOnce() -> io::Result<()>,
    mut move_file: impl FnMut(&Path, &Path) -> io::Result<()>,
) -> PromotionResult {
    let mut mapping = HashMap::new();
    let mut removed = Vec::new();
    let mut parents = HashSet::new();
    // Recheck after acquiring publication leases, before the durable intent.
    for (source, target) in moves {
        match target.try_exists() {
            Ok(false) => {}
            Ok(true) => {
                return (
                    mapping,
                    removed,
                    Vec::new(),
                    "promotion destination exists".into(),
                    true,
                )
            }
            Err(error) => return (mapping, removed, Vec::new(), error.to_string(), false),
        }
        if let Some(parent) = source.parent() {
            parents.insert(parent.to_path_buf());
        }
    }
    if let Err(error) = before_move() {
        return (mapping, removed, Vec::new(), error.to_string(), false);
    }
    for (source, target) in moves {
        if let Err(error) = move_file(source, target) {
            let mut message = error.to_string();
            for (old, new) in moves.iter().rev() {
                let old_key = normalize_path(old);
                if mapping.contains_key(&old_key) {
                    match move_file(new, old) {
                        Ok(()) => {
                            mapping.remove(&old_key);
                        }
                        Err(rollback) => {
                            message.push_str(&format!(
                                "; rollback {}: {}",
                                new.display(),
                                rollback
                            ));
                        }
                    }
                }
            }
            let collision = is_name_collision(&error) && mapping.is_empty();
            return (mapping, removed, Vec::new(), message, collision);
        }
        mapping.insert(normalize_path(source), normalize_path(target));
    }
    for parent in &parents {
        // remove_dir itself atomically checks emptiness; never walk upwards.
        if fs::remove_dir(parent).is_ok() {
            removed.push(normalize_path(parent));
        }
    }
    let mut touched: Vec<_> = parents.iter().map(|p| normalize_path(p)).collect();
    touched.push(normalize_path(destination));
    (mapping, removed, touched, String::new(), false)
}

fn move_input_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    match rename_no_replace(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(17) => {
            // A create-new handle prevents a concurrent arrival from being overwritten.
            let mut input = fs::File::open(source)?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            let copied = io::copy(&mut input, &mut output);
            drop(output);
            drop(input);
            if let Err(error) = copied.and_then(|_| fs::remove_file(source)) {
                let _ = fs::remove_file(destination);
                return Err(error);
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

use crate::filesystem::{watch_file_observation_known_kind, WatchFileObservation};

struct WatchCandidateRow {
    path: String,
    size: u64,
    mtime: f64,
    observation: WatchFileObservation,
}

#[cfg(windows)]
#[link(name = "Kernel32")]
extern "system" {
    fn MoveFileExW(existing_file_name: *const u16, new_file_name: *const u16, flags: u32) -> i32;
}

#[pyfunction]
#[pyo3(signature = (roots, recursive=true))]
pub(crate) fn scan_watch_candidates(
    py: Python<'_>,
    roots: Vec<String>,
    recursive: bool,
) -> PyResult<(Py<PyList>, Vec<DirectoryReadError>)> {
    let (candidates, messages) = py.detach(|| scan_watch_candidate_rows(roots, recursive))?;
    let values = PyList::empty(py);
    for row in candidates {
        values.append(watch_candidate_to_python(py, row)?)?;
    }
    Ok((values.unbind(), messages))
}

fn scan_watch_candidate_rows(
    roots: Vec<String>,
    recursive: bool,
) -> PyResult<(Vec<WatchCandidateRow>, Vec<DirectoryReadError>)> {
    let mut candidates = Vec::new();
    let mut messages = DirectoryReadErrors::report();
    for root in roots {
        let scope = crate::scan::scope::NativeDiscoveryScope::new(
            root,
            if recursive { None } else { Some(0) },
            Vec::new(),
        );
        let (paths, errors) = crate::scan::directory::scope_file_paths(&scope)?;
        messages.extend(errors);
        for path in paths {
            if let Some(candidate) = watch_candidate_row(&path, None)? {
                candidates.push(candidate);
            }
        }
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((candidates, messages.into_messages()))
}

#[pyfunction]
#[pyo3(signature = (path, since_usn=None))]
pub(crate) fn watch_candidate_for_path(
    py: Python<'_>,
    path: &str,
    since_usn: Option<i64>,
) -> PyResult<Option<Py<PyDict>>> {
    py.detach(|| watch_candidate_row(Path::new(path), since_usn))?
        .map(|row| watch_candidate_to_python(py, row))
        .transpose()
}

#[pyfunction]
#[pyo3(signature = (base, work_path=None, before_move=None, resume_leaf=None))]
pub(crate) fn flatten_single_branch_directories(
    py: Python<'_>,
    base: &str,
    work_path: Option<&str>,
    before_move: Option<Py<PyAny>>,
    resume_leaf: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let base_path = PathBuf::from(base);
    let result = PyDict::new(py);
    result.set_item("moved", 0usize)?;
    result.set_item("removed_dirs", 0usize)?;
    result.set_item("errors", PyList::empty(py))?;
    result.set_item("output_dir", normalize_path(&base_path))?;
    result.set_item("source_dir", "")?;
    if !base_path.is_dir() && resume_leaf.is_none() {
        return Ok(result.unbind());
    }

    let mut stats = FlattenStats::default();
    // The rename chain is pure filesystem work, and every rename publishes a
    // directory change the watch scheduler has to consume.  Release the GIL for
    // the loop (as delete_files_batch already does) so those two can overlap
    // instead of serializing on the interpreter lock.
    py.detach(|| {
        flatten_single_branch_chain_with_publisher(
            &base_path,
            &mut stats,
            work_path.map(Path::new),
            rename_no_replace,
            |root, work, leaf| {
                if let Some(callback) = before_move {
                    Python::attach(|py| {
                        callback.call1(
                            py,
                            (
                                normalize_path(root),
                                normalize_path(work),
                                normalize_path(leaf),
                            ),
                        )
                    })
                    .map_err(|error| io::Error::other(error.to_string()))?;
                }
                Ok(())
            },
            resume_leaf.map(Path::new),
        )
    });
    result.set_item("moved", stats.moved)?;
    result.set_item("removed_dirs", stats.removed_dirs)?;
    result.set_item("errors", PyList::new(py, stats.errors)?)?;
    if let Some(output) = stats.output_dir {
        result.set_item("output_dir", normalize_path(&output))?;
    }
    if let Some(source) = stats.source_dir {
        result.set_item("source_dir", normalize_path(&source))?;
    }
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn remove_output_path(py: Python<'_>, path: String, recursive: bool) -> PyResult<()> {
    py.detach(|| {
        if recursive {
            remove_owned_tree(Path::new(&path))
        } else {
            remove_owned_file(Path::new(&path))
        }
    })?;
    Ok(())
}

fn remove_owned_file(path: &Path) -> io::Result<()> {
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

fn remove_owned_tree(path: &Path) -> io::Result<()> {
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

#[pyfunction]
pub(crate) fn delete_files_batch(py: Python<'_>, paths: Vec<String>) -> PyResult<Py<PyList>> {
    let rows = py.detach(|| {
        paths
            .into_iter()
            .map(|raw| {
                let result = remove_owned_file(Path::new(&raw));
                let (status, error, error_code) = match result {
                    Ok(()) => ("deleted", String::new(), 0),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        ("missing", String::new(), 0)
                    }
                    Err(error) => (
                        "error",
                        error.to_string(),
                        error.raw_os_error().unwrap_or(0),
                    ),
                };
                (raw, status, error, error_code)
            })
            .collect::<Vec<_>>()
    });
    let results = PyList::empty(py);
    for (raw, status, error, error_code) in rows {
        let item = PyDict::new(py);
        item.set_item("path", normalize_path(Path::new(&raw)))?;
        item.set_item("status", status)?;
        item.set_item("error", error)?;
        item.set_item("error_code", error_code)?;
        results.append(item)?;
    }
    Ok(results.unbind())
}

fn watch_candidate_row(path: &Path, since_usn: Option<i64>) -> PyResult<Option<WatchCandidateRow>> {
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
) -> PyResult<Option<WatchCandidateRow>> {
    if metadata.len() == 0 {
        return Ok(None);
    }
    let observation = watch_file_observation_known_kind(path, since_usn, false)?;
    Ok(Some(WatchCandidateRow {
        path: normalize_path(path),
        size: metadata.len(),
        mtime: mtime_seconds(metadata),
        observation,
    }))
}

fn watch_candidate_to_python(py: Python<'_>, row: WatchCandidateRow) -> PyResult<Py<PyDict>> {
    let observation = row.observation;
    let dict = PyDict::new(py);
    dict.set_item("path", row.path)?;
    dict.set_item("size", row.size)?;
    dict.set_item("mtime", row.mtime)?;
    dict.set_item("file_id", observation.file_id)?;
    dict.set_item("change_usn", observation.change_usn)?;
    dict.set_item("change_reasons", observation.change_reasons)?;
    dict.set_item(
        "change_reasons_without_close",
        observation.change_reasons_without_close,
    )?;
    dict.set_item("change_reasons_known", observation.change_reasons_known)?;
    dict.set_item("change_reason_error", observation.change_reason_error)?;
    Ok(dict.unbind())
}

#[derive(Default)]
struct FlattenStats {
    moved: usize,
    removed_dirs: usize,
    errors: Vec<String>,
    output_dir: Option<PathBuf>,
    source_dir: Option<PathBuf>,
}

#[cfg(test)]
fn flatten_single_branch_chain(root: &Path, stats: &mut FlattenStats) {
    flatten_single_branch_chain_with_publisher(
        root,
        stats,
        None,
        rename_no_replace,
        |_, _, _| Ok(()),
        None,
    );
}

fn flatten_single_branch_chain_with_publisher(
    root: &Path,
    stats: &mut FlattenStats,
    reserved_work: Option<&Path>,
    publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
    before_move: impl FnOnce(&Path, &Path, &Path) -> io::Result<()>,
    resume_leaf: Option<&Path>,
) {
    let leaf = resume_leaf
        .map(Path::to_path_buf)
        .or_else(|| discover_flatten_chain(root).pop());
    let Some(leaf) = leaf else {
        return;
    };
    let leaf_relative = match leaf.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.to_path_buf(),
        _ => {
            stats.errors.push(format!(
                "{}: flatten leaf is not below output root",
                normalize_path(root)
            ));
            return;
        }
    };

    let work = if let Some(work) = reserved_work {
        let prepared = if resume_leaf.is_none() {
            before_move(root, work, &leaf)
        } else {
            Ok(())
        };
        if let Err(error) = prepared.and_then(|_| {
            if resume_leaf.is_some() {
                Ok(())
            } else {
                rename_no_replace(root, work)
            }
        }) {
            stats
                .errors
                .push(format!("{}: {error}", normalize_path(work)));
            return;
        }
        work.to_path_buf()
    } else {
        let Some(work) = rename_root_to_visible_work(root, stats) else {
            return;
        };
        work
    };
    stats.output_dir = Some(work.clone());
    stats.source_dir = Some(root.to_path_buf());
    let leaf_in_work = work.join(&leaf_relative);
    if let Err(error) = if resume_leaf.is_some() && root.is_dir() {
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
    stats.source_dir = Some(leaf);

    match remove_empty_flatten_wrappers(&work, &leaf_relative) {
        Ok(removed) => stats.removed_dirs += removed,
        Err(error) => stats.errors.push(error),
    }
}

fn discover_flatten_chain(root: &Path) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut current = root.to_path_buf();
    while let Some(child) = only_child_directory(&current) {
        chain.push(child.clone());
        current = child;
    }
    chain
}

fn only_child_directory(dir: &Path) -> Option<PathBuf> {
    let mut entries = fs::read_dir(dir).ok()?;
    let first = entries.next()?.ok()?;
    if entries.next().is_some() {
        return None;
    }
    if first.metadata().ok()?.is_dir() {
        Some(first.path())
    } else {
        None
    }
}

fn rename_root_to_visible_work(root: &Path, stats: &mut FlattenStats) -> Option<PathBuf> {
    let Some(parent) = root.parent() else {
        stats.errors.push(format!(
            "{}: output root has no parent for flatten work directory",
            normalize_path(root)
        ));
        return None;
    };
    let Some(root_name) = root.file_name() else {
        stats.errors.push(format!(
            "{}: output root has no directory name",
            normalize_path(root)
        ));
        return None;
    };

    let mut attempt = 1usize;
    loop {
        let mut work_name = root_name.to_os_string();
        work_name.push(".__sunpack_flatten_work__");
        if attempt > 1 {
            work_name.push(attempt.to_string());
        }
        let work = parent.join(work_name);
        match rename_no_replace(root, &work) {
            Ok(()) => return Some(work),
            Err(error) if is_name_collision(&error) => {
                attempt = attempt.saturating_add(1);
            }
            Err(error) => {
                stats.errors.push(format!(
                    "{} -> {}: {}",
                    normalize_path(root),
                    normalize_path(&work),
                    error
                ));
                return None;
            }
        }
    }
}

fn is_name_collision(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists || matches!(error.raw_os_error(), Some(80 | 183))
}

#[cfg(windows)]
fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let source_wide: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { MoveFileExW(source_wide.as_ptr(), destination_wide.as_ptr(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::rename(source, destination)
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
    normalize_windows_extended_prefix(text)
}

fn normalize_windows_extended_prefix(path: String) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    path
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
    fn promotion_rolls_back_preceding_members_on_move_failure() {
        let root = TestDirectory::new("promotion-rollback");
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let first = source.join("game.001");
        let second = source.join("game.002");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let moves = plan_promotion_moves(
            vec![normalize_path(&first), normalize_path(&second)],
            &destination,
        )
        .unwrap();
        // Both a permanent failure and a concurrent collision must roll back
        // earlier members. Only a fully restored collision may replan.
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::AlreadyExists] {
            let result = promote_input_files_with_move(
                &moves,
                &destination,
                || Ok(()),
                |old, new| {
                    if old == second {
                        return Err(io::Error::new(kind, "injected"));
                    }
                    rename_no_replace(old, new)
                },
            );
            assert!(result.0.is_empty());
            assert!(result.3.contains("injected"));
            assert_eq!(result.4, kind == io::ErrorKind::AlreadyExists);
            assert!(first.is_file() && second.is_file());
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        }
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
            None,
            |leaf, root| {
                fs::create_dir(root)?;
                fs::write(root.join("unrelated.txt"), b"unrelated")?;
                rename_no_replace(leaf, root)
            },
            |_, _, _| Ok(()),
            None,
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
