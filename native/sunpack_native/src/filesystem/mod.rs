use pyo3::exceptions::{PyFileNotFoundError, PyOSError, PyRuntimeError};
use pyo3::prelude::*;
use std::path::Path;

#[derive(Debug)]
pub(crate) struct WatchFileObservation {
    pub(crate) file_id: String,
    pub(crate) change_usn: i64,
    pub(crate) change_reasons: u32,
    pub(crate) change_reasons_without_close: u32,
    pub(crate) change_reasons_known: bool,
    pub(crate) change_reason_error: String,
}

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub(crate) fn watch_file_observation(
    _path: &Path,
    _since_usn: Option<i64>,
) -> PyResult<WatchFileObservation> {
    Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
}

pub(crate) fn watch_file_observation_known_kind(
    path: &Path,
    since_usn: Option<i64>,
    is_directory: bool,
) -> PyResult<WatchFileObservation> {
    #[cfg(windows)]
    {
        windows::watch_file_observation_known_kind(path, since_usn, is_directory).map_err(os_error)
    }
    #[cfg(not(windows))]
    {
        let _ = is_directory;
        watch_file_observation(path, since_usn)
    }
}

#[pyfunction]
pub(crate) fn watch_filesystem_type(path: &str) -> PyResult<String> {
    #[cfg(windows)]
    {
        return windows::filesystem_type(Path::new(path)).map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn validate_ntfs_watch_root(path: &str) -> PyResult<()> {
    #[cfg(windows)]
    {
        let path = Path::new(path);
        let filesystem = windows::filesystem_type(path).map_err(os_error)?;
        if !filesystem.eq_ignore_ascii_case("NTFS") {
            return Err(PyRuntimeError::new_err(format!(
                "watch mode requires NTFS: '{}' is on {}",
                path.display(),
                filesystem
            )));
        }
        windows::watch_file_observation(path, None).map_err(|error| {
            PyRuntimeError::new_err(format!(
                "watch mode requires readable NTFS file identity for '{}': {}",
                path.display(),
                error
            ))
        })?;
        windows::validate_volume_journal(path).map_err(|error| {
            PyRuntimeError::new_err(format!(
                "watch mode requires volume-level NTFS USN journal access for '{}': {}",
                path.display(),
                error
            ))
        })?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn resolve_output_volume_key(path: &str) -> PyResult<Option<String>> {
    #[cfg(windows)]
    {
        return match windows::resolve_output_volume(Path::new(path)) {
            Ok(key) => Ok(Some(key)),
            // Unresolvable volume: the caller falls back to a synthetic per-job key.
            Err(_) => Ok(None),
        };
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(None)
    }
}

#[pyfunction]
pub(crate) fn watch_broker_acquire() -> PyResult<()> {
    #[cfg(windows)]
    {
        return sunpack_usn_core::broker_acquire().map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn watch_broker_release() -> PyResult<()> {
    #[cfg(windows)]
    {
        return sunpack_usn_core::broker_release().map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[pyfunction]
pub(crate) fn watch_broker_is_connected() -> bool {
    #[cfg(windows)]
    {
        return sunpack_usn_core::broker_is_connected();
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[pyfunction]
pub(crate) fn watch_broker_ping_seconds() -> PyResult<f64> {
    #[cfg(windows)]
    {
        return sunpack_usn_core::broker_ping()
            .map(|elapsed| elapsed.as_secs_f64())
            .map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn watch_path_identity(path: &str) -> PyResult<(String, String, i64)> {
    #[cfg(windows)]
    {
        return windows::watch_path_identity(Path::new(path)).map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn watch_identity_path(py: Python<'_>, volume: &str, identity: &str) -> PyResult<String> {
    #[cfg(windows)]
    { py.detach(|| windows::watch_identity_path(volume, identity)).map_err(os_error) }
    #[cfg(not(windows))]
    { let _=(py,volume,identity); Err(PyRuntimeError::new_err("watch mode requires Windows NTFS")) }
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchChangeBatch {
    #[pyo3(get)]
    journal_id: u64,
    #[pyo3(get)]
    next_usn: i64,
    #[pyo3(get)]
    dirty: bool,
    #[cfg(windows)]
    changes: Vec<sunpack_usn_core::protocol::JournalChange>,
}

#[pymethods]
impl NativeWatchChangeBatch {
    fn paths_for_scopes(&self, scopes: Vec<PyRef<'_, crate::scan::scope::NativeDiscoveryScope>>) -> Vec<(String, bool)> {
        #[cfg(windows)]
        {
            let mut paths = std::collections::BTreeMap::new();
            for change in &self.changes {
                if let Some(path) = change.path.as_ref().filter(|path| scopes.iter().any(|scope| scope.contains(path))) {
                    paths.entry(crate::path_keys::path_key(path))
                        .and_modify(|entry: &mut (String, bool)| entry.1 |= change.is_directory)
                        .or_insert_with(|| (path.clone(), change.is_directory));
                }
            }
            paths.into_values().collect()
        }
        #[cfg(not(windows))]
        { let _ = scopes; Vec::new() }
    }
}

#[pyfunction]
pub(crate) fn watch_volume_changes(py: Python<'_>, volume: &str, start_usn: i64, end_usn: i64) -> PyResult<NativeWatchChangeBatch> {
    #[cfg(windows)]
    {
        let batch = py.detach(|| sunpack_usn_core::broker_read_volume_changes(volume, start_usn, end_usn)).map_err(os_error)?;
        Ok(NativeWatchChangeBatch {journal_id: batch.journal_id, next_usn: batch.next_usn, dirty: batch.dirty, changes: batch.changes})
    }
    #[cfg(not(windows))]
    {
        let _ = (py, volume, start_usn, end_usn);
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn watch_volume_cursor(path: &str) -> PyResult<(String, u64, i64)> {
    #[cfg(windows)]
    {
        return windows::watch_volume_cursor(Path::new(path)).map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn watch_file_is_ready(path: &str) -> PyResult<bool> {
    #[cfg(windows)]
    {
        return windows::watch_file_is_ready(Path::new(path)).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PyFileNotFoundError::new_err(error.to_string())
            } else {
                os_error(error)
            }
        });
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

fn os_error(error: std::io::Error) -> PyErr {
    // Ownership recovery distinguishes a vanished identity from an unreadable
    // one. A string-only OSError loses that distinction at the Python boundary.
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
            PyFileNotFoundError::new_err(error.to_string())
        }
        _ => PyOSError::new_err(error.to_string()),
    }
}
