use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

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
pub(crate) fn flatten_single_branch_directories(
    py: Python<'_>,
    base: &str,
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
    py.detach(|| flatten_single_branch_chain(&base_path, &mut stats));
    result.set_item("moved", stats.moved)?;
    result.set_item("removed_dirs", stats.removed_dirs)?;
    result.set_item("errors", PyList::new(py, stats.errors)?)?;
    Ok(result.unbind())
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

fn flatten_single_branch_chain(root: &Path, stats: &mut FlattenStats) {
    let chain = discover_flatten_chain(root);
    let Some(leaf) = chain.last() else {
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

    let Some(work) = rename_root_to_visible_work(root, stats) else {
        return;
    };
    let leaf_in_work = work.join(&leaf_relative);
    if let Err(error) = rename_no_replace(&leaf_in_work, root) {
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
    error.kind() == io::ErrorKind::AlreadyExists
        || matches!(error.raw_os_error(), Some(80 | 183))
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
        assert!(stats.errors.is_empty());
    }
}
