//! Metadata-only physical file generation snapshots.
use super::reader::file_identity;
use super::resource_lifecycle::TrackedFile;
use pyo3::prelude::*;
use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

const READ_ATTRIBUTES: u32 = 0x80;
const SHARE_ALL: u32 = 7;

fn open_attributes(path: &Path) -> io::Result<TrackedFile> {
    TrackedFile::open_with(path, "file_generation", |options| {
        options
            .access_mode(READ_ATTRIBUTES)
            .share_mode(SHARE_ALL);
    })
}

fn token(path: &Path, file: &File) -> io::Result<String> {
    Ok(file_identity(path.to_path_buf(), file)?.generation_token())
}

#[pyfunction]
pub(crate) fn file_generation_tokens(py: Python<'_>, paths: Vec<String>) -> Vec<Option<String>> {
    py.detach(|| {
        paths
            .iter()
            .map(|path| {
                let path = Path::new(path);
                open_attributes(path)
                    .and_then(|file| token(path, &file))
                    .ok()
            })
            .collect()
    })
}
