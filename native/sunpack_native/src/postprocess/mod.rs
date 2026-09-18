use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::filesystem::watch_file_observation;

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
) -> PyResult<Py<PyList>> {
    let mut candidates: Vec<(String, Py<PyDict>)> = Vec::new();
    for root in roots {
        let path = PathBuf::from(root);
        if path.is_file() {
            if let Some(candidate) = watch_candidate_dict(py, &path, None)? {
                candidates.push((normalize_path(&path), candidate));
            }
            continue;
        }
        if !path.is_dir() {
            continue;
        }
        if recursive {
            scan_watch_dir_recursive(py, &path, &mut candidates)?;
        } else {
            scan_watch_dir_shallow(py, &path, &mut candidates)?;
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let values = candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect::<Vec<_>>();
    Ok(PyList::new(py, values)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, since_usn=None))]
pub(crate) fn watch_candidate_for_path(
    py: Python<'_>,
    path: &str,
    since_usn: Option<i64>,
) -> PyResult<Option<Py<PyDict>>> {
    watch_candidate_dict(py, Path::new(path), since_usn)
}

#[pyfunction]
#[pyo3(signature = (base, state_dir=None))]
pub(crate) fn flatten_single_branch_directories(
    py: Python<'_>,
    base: &str,
    state_dir: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let base_path = PathBuf::from(base);
    let result = PyDict::new(py);
    result.set_item("moved", 0usize)?;
    result.set_item("removed_dirs", 0usize)?;
    result.set_item("errors", PyList::empty(py))?;
    if !base_path.is_dir() {
        return Ok(result.unbind());
    }

    let mut stats = FlattenStats::default();
    // The rename chain is pure filesystem work, and every rename publishes a
    // directory change the watch scheduler has to consume.  Release the GIL for
    // the loop (as delete_files_batch already does) so those two can overlap
    // instead of serializing on the interpreter lock.
    py.detach(|| {
        flatten_single_branch_chain(&base_path, &mut stats, state_dir.map(Path::new));
    });
    result.set_item("moved", stats.moved)?;
    result.set_item("removed_dirs", stats.removed_dirs)?;
    result.set_item("errors", PyList::new(py, stats.errors)?)?;
    Ok(result.unbind())
}

/// Finish flatten transactions this process did not complete (startup recovery).
#[pyfunction]
pub(crate) fn recover_pending_flatten_transactions(
    py: Python<'_>,
    state_dir: &str,
) -> PyResult<usize> {
    let state_dir = PathBuf::from(state_dir);
    Ok(py.detach(|| recover_flatten_transactions(&state_dir)))
}

#[pyfunction]
pub(crate) fn delete_files_batch(py: Python<'_>, paths: Vec<String>) -> PyResult<Py<PyList>> {
    let rows = py.detach(|| {
        paths
            .into_iter()
            .map(|raw| {
                let result = fs::remove_file(&raw);
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

fn scan_watch_dir_recursive(
    py: Python<'_>,
    root: &Path,
    candidates: &mut Vec<(String, Py<PyDict>)>,
) -> PyResult<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            scan_watch_dir_recursive(py, &path, candidates)?;
        } else if metadata.is_file() {
            if let Some(candidate) = watch_candidate_from_metadata(py, &path, &metadata, None)? {
                candidates.push((normalize_path(&path), candidate));
            }
        }
    }
    Ok(())
}

fn scan_watch_dir_shallow(
    py: Python<'_>,
    root: &Path,
    candidates: &mut Vec<(String, Py<PyDict>)>,
) -> PyResult<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_file() {
            if let Some(candidate) = watch_candidate_from_metadata(py, &path, &metadata, None)? {
                candidates.push((normalize_path(&path), candidate));
            }
        }
    }
    Ok(())
}

fn watch_candidate_dict(
    py: Python<'_>,
    path: &Path,
    since_usn: Option<i64>,
) -> PyResult<Option<Py<PyDict>>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    watch_candidate_from_metadata(py, path, &metadata, since_usn)
}

fn watch_candidate_from_metadata(
    py: Python<'_>,
    path: &Path,
    metadata: &fs::Metadata,
    since_usn: Option<i64>,
) -> PyResult<Option<Py<PyDict>>> {
    if metadata.len() == 0 {
        return Ok(None);
    }
    let observation = watch_file_observation(path, since_usn)?;
    let dict = PyDict::new(py);
    dict.set_item("path", normalize_path(path))?;
    dict.set_item("size", metadata.len())?;
    dict.set_item("mtime", mtime_seconds(metadata))?;
    dict.set_item("file_id", observation.file_id)?;
    dict.set_item("change_usn", observation.change_usn)?;
    dict.set_item("change_reasons", observation.change_reasons)?;
    dict.set_item(
        "change_reasons_without_close",
        observation.change_reasons_without_close,
    )?;
    dict.set_item("change_reasons_known", observation.change_reasons_known)?;
    dict.set_item("change_reason_error", observation.change_reason_error)?;
    Ok(Some(dict.unbind()))
}

#[derive(Default)]
struct FlattenStats {
    moved: usize,
    removed_dirs: usize,
    errors: Vec<String>,
}

/// One flatten transaction: promote the direct entries of the deepest
/// single-child directory of `root` into `root` itself.
///
/// The outer wrapper is detached to a same-volume sibling first, so the output
/// root keeps its own directory identity.  `source` and `leaf_relative` are the
/// discovery-time facts a resumed transaction must never re-derive from a tree
/// that may already be half moved.
struct FlattenState {
    root: PathBuf,
    /// Discovery-time wrapper directory that the detach moves aside.
    source: PathBuf,
    work: PathBuf,
    leaf_relative: PathBuf,
}

const FLATTEN_STATE_VERSION: u32 = 2;

fn flatten_single_branch_chain(root: &Path, stats: &mut FlattenStats, state_dir: Option<&Path>) {
    if let Some(state_dir) = state_dir {
        if let Some((state_file, state)) = pending_flatten_state(state_dir, root) {
            if run_flatten_transaction(&state, stats) {
                let _ = fs::remove_file(state_file);
            }
            return;
        }
    }

    let chain = discover_flatten_chain(root);
    let Some(first) = chain.first().cloned() else {
        return;
    };
    let leaf_relative = chain[chain.len() - 1]
        .strip_prefix(&first)
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let Some(work) = flatten_work_path(root) else {
        stats.errors.push(format!(
            "{}: output root has no parent for a flatten work directory",
            normalize_path(root)
        ));
        return;
    };
    let state = FlattenState {
        root: root.to_path_buf(),
        source: first.clone(),
        work,
        leaf_relative,
    };
    // The durable record comes first: an interruption after the detach would
    // otherwise leave a detached tree with nothing describing how to finish it.
    let state_file = match state_dir {
        Some(state_dir) => match write_flatten_state(state_dir, &state) {
            Ok(path) => Some(path),
            Err(error) => {
                stats.errors.push(format!("flatten recovery state: {error}"));
                return;
            }
        },
        None => None,
    };
    if run_flatten_transaction(&state, stats) {
        if let Some(path) = state_file {
            let _ = fs::remove_file(path);
        }
    }
}

/// Forward recovery: the namespace itself records progress, so any interruption
/// resumes by looking at what is currently on disk.
fn run_flatten_transaction(state: &FlattenState, stats: &mut FlattenStats) -> bool {
    if !state.work.is_dir() {
        if state.source.parent() != Some(state.root.as_path()) {
            // A state file that does not describe one of our own transactions
            // must never move an unrelated path.
            stats.errors.push(format!(
                "{}: recorded flatten source is not a direct child of {}",
                normalize_path(&state.source),
                normalize_path(&state.root)
            ));
            return false;
        }
        if !state.source.is_dir() {
            // The recorded wrapper is gone while the work tree was never
            // created: do not guess another directory, keep the state.
            stats.errors.push(format!(
                "{}: recorded flatten source is missing; state kept for inspection",
                normalize_path(&state.source)
            ));
            return false;
        }
        if let Err(error) = fs::rename(&state.source, &state.work) {
            stats.errors.push(format!(
                "{} -> {}: {error}",
                normalize_path(&state.source),
                normalize_path(&state.work)
            ));
            return false;
        }
    }
    let leaf = state.work.join(&state.leaf_relative);
    promote_leaf_entries(&state.root, &leaf, stats);
    if !stats.errors.is_empty() {
        return false;
    }
    match remove_flatten_wrapper(&state.work, &state.leaf_relative) {
        Ok(removed) => {
            stats.removed_dirs += removed;
            true
        }
        Err(error) => {
            stats.errors.push(error);
            false
        }
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

/// At most two directory entries are read per level, so discovery stays O(depth)
/// even when the boundary directory holds a hundred thousand files.
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

fn promote_leaf_entries(root: &Path, leaf: &Path, stats: &mut FlattenStats) {
    let entries = match fs::read_dir(leaf) {
        Ok(entries) => entries,
        // A resumed transaction whose cleanup already removed the leaf levels
        // has nothing left to promote.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            stats.errors.push(format!("{}: {error}", normalize_path(leaf)));
            return;
        }
    };
    // The detach left the root empty, so the hot path needs no per-entry
    // existence probe.  A root that is not empty keeps the historical unique
    // naming fallback, and a concurrent writer still falls back on rename error.
    let root_is_empty = fs::read_dir(root)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false);
    for entry in entries.flatten() {
        let source = entry.path();
        let Some(name) = source.file_name() else {
            continue;
        };
        let mut destination = if root_is_empty {
            root.join(name)
        } else {
            unique_destination(root, name)
        };
        if fs::rename(&source, &destination).is_err() {
            destination = unique_destination(root, name);
            if let Err(error) = fs::rename(&source, &destination) {
                stats.errors.push(format!(
                    "{} -> {}: {error}",
                    normalize_path(&source),
                    normalize_path(&destination)
                ));
                return;
            }
        }
        stats.moved += 1;
    }
}

fn remove_flatten_wrapper(work: &Path, leaf_relative: &Path) -> Result<usize, String> {
    let mut directories = vec![work.to_path_buf()];
    let mut current = work.to_path_buf();
    for component in leaf_relative.components() {
        current = current.join(component);
        directories.push(current.clone());
    }
    directories.reverse();
    let mut removed = 0usize;
    for directory in directories {
        match fs::remove_dir(&directory) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", normalize_path(&directory))),
        }
    }
    Ok(removed)
}

fn flatten_work_path(root: &Path) -> Option<PathBuf> {
    Some(root.parent()?.join(format!(".sunpack-flatten-{}", transaction_id())))
}

const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

/// Name-level commit for the state file.  MOVEFILE_WRITE_THROUGH keeps the
/// rename from returning before NTFS has committed the metadata, which is the
/// only durability gap left after the content itself was synced.
#[cfg(windows)]
fn rename_write_through(source: &Path, destination: &Path) -> std::io::Result<()> {
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
    if unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn rename_write_through(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

fn transaction_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

fn flatten_state_file(state_dir: &Path, id: &str) -> PathBuf {
    state_dir.join(format!("{id}.state"))
}

fn write_flatten_state(state_dir: &Path, state: &FlattenState) -> std::io::Result<PathBuf> {
    fs::create_dir_all(state_dir)?;
    let id = transaction_id();
    let path = flatten_state_file(state_dir, &id);
    let temporary = state_dir.join(format!("{id}.state.tmp"));
    let text = format!(
        "version={FLATTEN_STATE_VERSION}\nroot={}\nsource={}\nwork={}\nleaf={}\n",
        state.root.display(),
        state.source.display(),
        state.work.display(),
        state.leaf_relative.display()
    );
    let mut file = fs::File::create(&temporary)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // Commit the state name write-through: only its success allows the detach.
    rename_write_through(&temporary, &path)?;
    Ok(path)
}

fn load_flatten_state(path: &Path) -> Option<FlattenState> {
    let text = fs::read_to_string(path).ok()?;
    let mut version = 0u32;
    let mut root: Option<PathBuf> = None;
    let mut source: Option<PathBuf> = None;
    let mut work: Option<PathBuf> = None;
    let mut leaf_relative = PathBuf::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "version" => version = value.parse().ok()?,
            "root" => root = Some(PathBuf::from(value)),
            "source" => source = Some(PathBuf::from(value)),
            "work" => work = Some(PathBuf::from(value)),
            "leaf" => leaf_relative = PathBuf::from(value),
            _ => {}
        }
    }
    // Anything that is not this exact schema is left untouched for a human or a
    // future version instead of being guessed at.
    if version != FLATTEN_STATE_VERSION {
        return None;
    }
    Some(FlattenState {
        root: root?,
        source: source?,
        work: work?,
        leaf_relative,
    })
}

fn pending_flatten_state(state_dir: &Path, root: &Path) -> Option<(PathBuf, FlattenState)> {
    for path in flatten_state_files(state_dir) {
        let Some(state) = load_flatten_state(&path) else {
            continue;
        };
        if same_path(&state.root, root) {
            return Some((path, state));
        }
    }
    None
}

fn recover_flatten_transactions(state_dir: &Path) -> usize {
    let mut finished = 0usize;
    for path in flatten_state_files(state_dir) {
        let Some(state) = load_flatten_state(&path) else {
            continue;
        };
        let mut stats = FlattenStats::default();
        if run_flatten_transaction(&state, &mut stats) {
            let _ = fs::remove_file(&path);
            finished += 1;
        }
    }
    finished
}

fn flatten_state_files(state_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(state_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("state"))
        .collect()
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy()),
    }
}

fn unique_destination(root: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let direct = root.join(name);
    if !direct.exists() {
        return direct;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("item");
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    for count in 1usize.. {
        let candidate_name = if extension.is_empty() {
            format!("{stem} ({count})")
        } else {
            format!("{stem} ({count}).{extension}")
        };
        let candidate = root.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    direct
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
        flatten_single_branch_chain(output.path(), &mut stats, None);

        assert!(!output.path().join("Build").exists());
        assert!(output.path().join("Clicker.exe").is_file());
        assert!(output.path().join("Plugins/x86_64/plugin.dll").is_file());
        assert!(output
            .path()
            .join("StreamingAssets/aa/catalog.bin")
            .is_file());
        assert_eq!(stats.removed_dirs, 1);
        assert!(stats.errors.is_empty());
    }

    #[test]
    fn flatten_continues_along_an_unbranched_directory_chain() {
        let output = TestDirectory::new("chain");
        let payload = output.path().join("outer/inner/payload.txt");
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::write(&payload, b"payload").unwrap();

        let mut stats = FlattenStats::default();
        flatten_single_branch_chain(output.path(), &mut stats, None);

        assert!(output.path().join("payload.txt").is_file());
        assert!(!output.path().join("outer").exists());
        assert!(!output.path().join("inner").exists());
        assert_eq!(stats.removed_dirs, 2);
        assert!(stats.errors.is_empty());
    }
}
