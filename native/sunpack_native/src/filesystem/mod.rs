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

#[pyfunction(name = "resolve_output_volume_key")]
pub(crate) fn resolve_output_volume_key_python(py: Python<'_>, path: &str) -> Option<String> {
    py.detach(|| resolve_output_volume_key(path))
}

pub(crate) fn resolve_output_volume_key(path: &str) -> Option<String> {
    #[cfg(windows)]
    {
        // Unresolvable volume: the caller falls back to a synthetic per-job key.
        windows::resolve_output_volume(Path::new(path)).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
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
pub(crate) fn watch_root_changes(
    path: &str,
    start_usn: i64,
    end_usn: i64,
) -> PyResult<Vec<String>> {
    #[cfg(windows)]
    {
        let path = Path::new(path);
        let (volume, file_id, _) = windows::watch_path_identity(path).map_err(os_error)?;
        return sunpack_usn_core::broker_read_root_changes(&volume, &file_id, start_usn, end_usn)
            .map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        let _ = (path, start_usn, end_usn);
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

/// Resolve directory identities once, then dispatch one journal pass using parent IDs.
#[pyfunction]
pub(crate) fn watch_directories_changes(
    py: Python<'_>,
    directories: Vec<String>,
    volume: String,
    journal: u64,
    start_usn: i64,
    end_usn: i64,
) -> PyResult<Vec<String>> {
    py.detach(|| {
        watch_directories_changes_impl(directories, &volume, journal, start_usn, end_usn)
            .map_err(os_error)
    })
}

pub(crate) fn watch_directories_changes_impl(
    directories: Vec<String>,
    volume: &str,
    journal: u64,
    start_usn: i64,
    end_usn: i64,
) -> std::io::Result<Vec<String>> {
    #[cfg(windows)]
    {
        if directories.len() > (sunpack_usn_core::protocol::MAX_DIRECTORY_QUERY_BYTES - 8) / 16 {
            return Err(std::io::Error::other(
                "directory recovery exceeds payload budget",
            ));
        }
        let mut live = Vec::with_capacity(directories.len());
        let mut ids = Vec::with_capacity(directories.len());
        let mut paths = std::collections::BTreeSet::new();
        for directory in directories {
            match windows::watch_path_identity(Path::new(&directory)) {
                Ok((actual, id, _)) if actual.eq_ignore_ascii_case(volume) => {
                    let (id, _) = sunpack_usn_core::protocol::parse_file_id(&id)?;
                    live.push(directory);
                    ids.push(id);
                }
                Ok(_) => return Err(std::io::Error::other("directory changed volume")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    paths.insert(directory);
                }
                Err(error) => return Err(error),
            }
        }
        if start_usn < end_usn && !ids.is_empty() {
            let changes = sunpack_usn_core::broker_read_directories_changes(
                volume, journal, &ids, start_usn, end_usn,
            )?;
            for (index, name) in changes {
                paths.insert(if name.is_empty() {
                    live[index as usize].clone()
                } else {
                    Path::new(&live[index as usize])
                        .join(name)
                        .to_string_lossy()
                        .into_owned()
                });
            }
        }
        Ok(paths.into_iter().collect())
    }
    #[cfg(not(windows))]
    {
        let _ = (directories, volume, journal, start_usn, end_usn);
        Err(std::io::Error::other("watch mode requires Windows NTFS"))
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
    PyOSError::new_err(error.to_string())
}
