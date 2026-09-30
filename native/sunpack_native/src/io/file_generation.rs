//! Metadata-only generation snapshots and cleanup of the exact opened file.
use super::reader::file_identity;
use super::resource_lifecycle::TrackedFile;
use pyo3::prelude::*;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const READ_ATTRIBUTES: u32 = 0x80;
const DELETE: u32 = 0x10000;
const SHARE_READ: u32 = 1;
const SHARE_ALL: u32 = 7;
pub(crate) const CLEANUP_PREFIX: &str = ".sunpack-cleanup-";

#[link(name = "kernel32")]
extern "system" {
    fn SetFileInformationByHandle(
        handle: *mut c_void,
        class: i32,
        information: *const c_void,
        size: u32,
    ) -> i32;
}

fn open_attributes(path: &Path, cleanup: bool) -> io::Result<TrackedFile> {
    // Cleanup denies concurrent writes/deletes until the handle operation.
    // This is exclusion enforced by Windows, not a check-then-use path race.
    let configure = |options: &mut std::fs::OpenOptions| {
        options
            .access_mode(READ_ATTRIBUTES | if cleanup { DELETE } else { 0 })
            .share_mode(if cleanup { SHARE_READ } else { SHARE_ALL });
    };
    if cleanup {
        TrackedFile::open_for_mutation(path, configure)
    } else {
        TrackedFile::open_with(path, "file_generation", configure)
    }
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
                open_attributes(path, false)
                    .and_then(|file| token(path, &file))
                    .ok()
            })
            .collect()
    })
}

fn set_information(file: &File, class: i32, data: &[usize]) -> io::Result<()> {
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            class,
            data.as_ptr().cast(),
            std::mem::size_of_val(data) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn rename_handle(file: &File, destination: &Path) -> io::Result<()> {
    #[repr(C)]
    struct RenameInfo {
        replace: u8,
        root: *mut c_void,
        name_bytes: u32,
        name: [u16; 1],
    }
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let name_offset = std::mem::offset_of!(RenameInfo, name);
    // SetFileInformationByHandle takes a NUL-terminated Win32 path, even
    // though FileNameLength itself excludes that terminator.
    let bytes = name_offset + (name.len() + 1) * 2;
    // Word-aligned storage satisfies FILE_RENAME_INFO's pointer alignment.
    let mut data = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
    let info = data.as_mut_ptr().cast::<RenameInfo>();
    unsafe {
        (*info).name_bytes = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            data.as_mut_ptr().cast::<u8>().add(name_offset).cast(),
            name.len(),
        );
    }
    set_information(file, 3, &data)
}

fn cleanup_opened(
    path: &Path,
    expected: Option<&str>,
    recycle: bool,
) -> io::Result<(String, String)> {
    let file = match open_attributes(path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(("missing".into(), String::new()))
        }
        Err(error) => return Err(error),
    };
    let Some(expected) = expected else {
        return Ok(("changed".into(), String::new()));
    };
    if token(path, &file)? != expected {
        return Ok(("changed".into(), String::new()));
    }
    if !recycle {
        // FILE_DISPOSITION_INFO.DeleteFile = TRUE. Deletion targets this handle,
        // even if an unrelated new file subsequently occupies the same path.
        set_information(&file, 4, &[1usize])?;
        return Ok(("deleted".into(), String::new()));
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    loop {
        let destination = path.with_file_name(format!(
            "{CLEANUP_PREFIX}{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match rename_handle(&file, &destination) {
            Ok(()) => return Ok(("staged".into(), destination.to_string_lossy().into_owned())),
            Err(error) if matches!(error.raw_os_error(), Some(80 | 183)) => continue,
            Err(error) => return Err(error),
        }
    }
}

#[pyfunction]
pub(crate) fn prepare_file_cleanup(
    py: Python<'_>,
    files: Vec<(String, Option<String>)>,
    recycle: bool,
) -> Vec<(String, String, i32, String)> {
    // A batch detaches once. Each file's handle is dropped before the next
    // item, including mismatch, missing-file and syscall-failure paths.
    py.detach(|| prepare_cleanup_files(files, recycle))
}

fn prepare_cleanup_files(
    files: Vec<(String, Option<String>)>,
    recycle: bool,
) -> Vec<(String, String, i32, String)> {
    files
        .into_iter()
        .map(|(path, expected)| {
            match cleanup_opened(Path::new(&path), expected.as_deref(), recycle) {
                Ok((status, staged)) => (status, staged, 0, String::new()),
                Err(error) => (
                    "failed".into(),
                    String::new(),
                    error.raw_os_error().unwrap_or(0),
                    error.to_string(),
                ),
            }
        })
        .collect()
}

#[pyfunction]
pub(crate) fn restore_staged_cleanup(
    py: Python<'_>,
    staged: String,
    original: String,
) -> PyResult<()> {
    // Never overwrite a new arrival while restoring a failed recycle.
    py.detach(|| {
        let file = open_attributes(Path::new(&staged), true)?;
        rename_handle(&file, &PathBuf::from(original))
    })
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;

    fn snapshot(path: &Path) -> String {
        token(path, &open_attributes(path, false).unwrap()).unwrap()
    }

    #[test]
    fn cleanup_delete_targets_only_the_snapshot_generation() {
        let path = temp_file("guarded_delete", b"old!");
        let generation = snapshot(&path);
        assert_eq!(
            cleanup_opened(&path, Some(&generation), false).unwrap().0,
            "deleted"
        );
        assert!(!path.exists());
        std::fs::write(&path, b"new!").unwrap();
        assert_eq!(
            cleanup_opened(&path, Some(&generation), false).unwrap().0,
            "changed"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new!");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cleanup_handle_excludes_writes_and_rename_after_validation() {
        let path = temp_file("guarded_exclusion", b"old!");
        let file = open_attributes(&path, true).unwrap();
        assert_eq!(token(&path, &file).unwrap(), snapshot(&path));
        assert!(std::fs::write(&path, b"new!").is_err());
        assert!(std::fs::rename(&path, path.with_extension("renamed")).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn staged_recycle_restore_never_overwrites_new_arrival() {
        let path = temp_file("guarded_restore", b"old!");
        let generation = snapshot(&path);
        let (status, staged) = cleanup_opened(&path, Some(&generation), true).unwrap();
        assert_eq!(status, "staged");
        assert!(!path.exists());
        std::fs::write(&path, b"new!").unwrap();
        let staged = PathBuf::from(staged);
        let file = open_attributes(&staged, true).unwrap();
        assert!(rename_handle(&file, &path).is_err());
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"new!");
        assert_eq!(std::fs::read(&staged).unwrap(), b"old!");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(staged).unwrap();
    }

    #[test]
    fn handle_rename_terminates_paths_at_every_buffer_alignment() {
        let path = temp_file("guarded_rename_alignment", b"old!");
        for length in 1..=16 {
            let destination = path.with_file_name(format!(
                "sunpack_{}_{}.bin",
                "测🧪".repeat(length),
                std::process::id()
            ));
            let file = open_attributes(&path, true).unwrap();
            rename_handle(&file, &destination).unwrap();
            drop(file);
            assert!(!path.exists());
            assert_eq!(std::fs::read(&destination).unwrap(), b"old!");
            let file = open_attributes(&destination, true).unwrap();
            rename_handle(&file, &path).unwrap();
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cleanup_batch_continues_after_failure_and_releases_every_handle() {
        let busy = temp_file("cleanup_batch_busy", b"busy");
        let good = temp_file("cleanup_batch_good", b"good");
        let changed = temp_file("cleanup_batch_changed", b"new!");
        let generation = snapshot(&busy);
        let good_generation = snapshot(&good);
        let guard = open_attributes(&busy, true).unwrap();
        let rows = prepare_cleanup_files(
            vec![
                (busy.to_string_lossy().into_owned(), Some(generation)),
                (good.to_string_lossy().into_owned(), Some(good_generation)),
                (changed.to_string_lossy().into_owned(), Some("stale".into())),
                (
                    good.with_extension("missing")
                        .to_string_lossy()
                        .into_owned(),
                    None,
                ),
                (changed.to_string_lossy().into_owned(), None),
            ],
            false,
        );
        assert_eq!(
            rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            ["failed", "deleted", "changed", "missing", "changed"]
        );
        assert_eq!(rows[0].2, 32);
        assert!(!good.exists());
        assert_eq!(std::fs::read(&changed).unwrap(), b"new!");
        assert_eq!(
            crate::io::resource_lifecycle::snapshot_under(&busy).len(),
            1
        );
        assert!(crate::io::resource_lifecycle::snapshot_under(&good).is_empty());
        assert!(crate::io::resource_lifecycle::snapshot_under(&changed).is_empty());
        drop(guard);
        assert!(crate::io::resource_lifecycle::snapshot_under(&busy).is_empty());
        std::fs::remove_file(busy).unwrap();
        std::fs::remove_file(changed).unwrap();
    }
}
