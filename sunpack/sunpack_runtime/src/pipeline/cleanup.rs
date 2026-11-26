use std::{io, path::{Path, PathBuf}};

use crate::io::reader::PhysicalFileGeneration;

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct CleanupSource {
    pub(crate) path: PathBuf,
    pub(crate) generation: PhysicalFileGeneration,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) recycle: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct CleanupReceipt<'a> {
    pub(crate) id: super::TaskId,
    pub(crate) sources: &'a [CleanupSource],
}

// Ok(false) settles an absent or replaced source without touching its namespace.
// Open without write sharing, then validate and unlink the very same handle.
#[cfg(windows)]
pub(crate) fn clean_source(source: &CleanupSource, durable: bool) -> io::Result<bool> {
    use std::os::windows::{fs::{MetadataExt, OpenOptionsExt}, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_DELETE, FileDispositionInfoEx, SetFileInformationByHandle,
    };
    let file = match std::fs::OpenOptions::new()
        .access_mode(if source.recycle { FILE_READ_ATTRIBUTES } else { DELETE | FILE_READ_ATTRIBUTES })
        .share_mode(if source.recycle { FILE_SHARE_READ | FILE_SHARE_DELETE } else { FILE_SHARE_READ })
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(&source.path)
    {
        Ok(file) => file,
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0
        || crate::io::reader::physical_file_generation_from_metadata(&file, &metadata)? != source.generation
    {
        return Ok(false);
    }
    if source.recycle {
        recycle(&source.path)?;
        if durable {
            // Shell creates the restore metadata separately from the NTFS rename.
            // Flush this small file before acknowledging a recoverable transfer.
            let payload = crate::io::resource_lifecycle::resolved_reader_path(&file)?;
            let suffix = payload.file_name().and_then(|name| name.to_str()).and_then(|name| name.strip_prefix("$R"))
                .filter(|_| payload.parent().and_then(Path::parent).and_then(Path::file_name)
                    .is_some_and(|name| name.eq_ignore_ascii_case("$Recycle.Bin")))
                .ok_or_else(|| io::Error::other("Windows did not return a recycled file"))?;
            std::fs::OpenOptions::new().write(true).open(payload.with_file_name(format!("$I{suffix}")))?.sync_all()?;
        }
        return Ok(true);
    }
    let info = FILE_DISPOSITION_INFO_EX { Flags: FILE_DISPOSITION_FLAG_DELETE
        | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE };
    if unsafe { SetFileInformationByHandle(file.as_raw_handle(), FileDispositionInfoEx,
        (&raw const info).cast(), std::mem::size_of_val(&info) as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(not(windows))]
pub(crate) fn clean_source(_: &CleanupSource, _: bool) -> io::Result<bool> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "generation-checked deletion requires Windows"))
}

#[cfg(windows)]
pub(super) fn recycle(path: &Path) -> io::Result<()> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::core::GUID;

    const FILE_OPERATION: GUID = GUID::from_u128(0x3ad05575_8857_4850_9277_11b85bdb8e09);
    const IFILE_OPERATION: GUID = GUID::from_u128(0x947aab5f_0a5c_4c13_b4d6_4bf7836fc9f8);
    const ISHELL_ITEM: GUID = GUID::from_u128(0x43826d1e_e718_42ee_bc55_a1e261c37bfe);
    const RECYCLE_ON_DELETE: u32 = 0x00080000;
    const ADD_UNDO_RECORD: u32 = 0x20000000;
    const EARLY_FAILURE: u32 = 0x00100000;
    const SILENT: u32 = 0x0004;
    const NO_CONFIRMATION: u32 = 0x0010;
    const NO_ERROR_UI: u32 = 0x0400;

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
        fn CoUninitialize();
        fn CoCreateInstance(
            class: *const GUID,
            outer: *mut c_void,
            context: u32,
            interface: *const GUID,
            object: *mut *mut c_void,
        ) -> i32;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHCreateItemFromParsingName(
            path: *const u16,
            bind_context: *mut c_void,
            interface: *const GUID,
            item: *mut *mut c_void,
        ) -> i32;
    }

    #[repr(C)]
    struct Unknown {
        query_interface: *const c_void,
        add_ref: *const c_void,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
    }

    // Windows SDK ShObjIdl_core.h, IFileOperationVtbl. Include only the
    // method signatures used here while preserving unused ABI slots.
    #[repr(C)]
    struct FileOperation {
        unknown: Unknown,
        advise: *const c_void,
        unadvise: *const c_void,
        set_operation_flags: unsafe extern "system" fn(*mut c_void, u32) -> i32,
        before_delete: [*const c_void; 12],
        delete_item: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> i32,
        after_delete: [*const c_void; 2],
        perform_operations: unsafe extern "system" fn(*mut c_void) -> i32,
        operations_aborted: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
    }

    struct ComObject(*mut c_void);
    impl Drop for ComObject {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    ((**self.0.cast::<*const Unknown>()).release)(self.0);
                }
            }
        }
    }

    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    fn check(result: i32) -> io::Result<()> {
        if result < 0 {
            Err(io::Error::from_raw_os_error(result & 0xffff))
        } else {
            Ok(())
        }
    }

    unsafe {
        check(CoInitializeEx(null_mut(), 2))?; // COINIT_APARTMENTTHREADED
        let _apartment = Apartment;
        let mut operation = ComObject(null_mut());
        check(CoCreateInstance(
            &FILE_OPERATION,
            null_mut(),
            23,
            &IFILE_OPERATION,
            &mut operation.0,
        ))?;
        let methods = &**operation.0.cast::<*const FileOperation>();
        let flags = RECYCLE_ON_DELETE
            | ADD_UNDO_RECORD
            | EARLY_FAILURE
            | SILENT
            | NO_CONFIRMATION
            | NO_ERROR_UI;
        check((methods.set_operation_flags)(operation.0, flags))?;
        {
            let path: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
            let mut item = ComObject(null_mut());
            check(SHCreateItemFromParsingName(
                path.as_ptr(),
                null_mut(),
                &ISHELL_ITEM,
                &mut item.0,
            ))?;
            check((methods.delete_item)(operation.0, item.0, null_mut()))?;
        }
        check((methods.perform_operations)(operation.0))?;
        let mut aborted = 0;
        check((methods.operations_aborted)(operation.0, &mut aborted))?;
        if aborted != 0 {
            return Err(io::Error::other("Windows cancelled recycling"));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn recycle(_: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recycling requires Windows",
    ))
}
