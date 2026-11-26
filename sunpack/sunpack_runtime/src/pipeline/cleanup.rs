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
    let departed = || {
        if durable && source.recycle { repair_recycle_info(source)?; }
        Ok(false)
    };
    let file = match std::fs::OpenOptions::new()
        .access_mode(if source.recycle { FILE_READ_ATTRIBUTES } else { DELETE | FILE_READ_ATTRIBUTES })
        .share_mode(if source.recycle { FILE_SHARE_READ | FILE_SHARE_DELETE } else { FILE_SHARE_READ })
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(&source.path)
    {
        Ok(file) => file,
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => return departed(),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0
        || crate::io::reader::physical_file_generation_from_metadata(&file, &metadata)? != source.generation
    {
        return departed();
    }
    if source.recycle {
        recycle(&source.path)?;
        if durable {
            // Shell creates the restore metadata separately from the NTFS rename.
            // Flush this small file before acknowledging a recoverable transfer.
            let payload = crate::io::resource_lifecycle::resolved_reader_path(&file)?;
            let info = recycle_info_path(&payload)
                .ok_or_else(|| io::Error::other("Windows did not return a recycled file"))?;
            std::fs::OpenOptions::new().write(true).open(info)?.sync_all()?;
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

#[cfg(windows)]
fn recycle_info_path(payload: &Path) -> Option<PathBuf> {
    let bin = payload.parent()?.parent()?;
    if !bin.file_name()?.eq_ignore_ascii_case("$Recycle.Bin") {
        return None;
    }
    let suffix = payload.file_name()?.to_str()?.strip_prefix("$R")?;
    Some(payload.with_file_name(format!("$I{suffix}")))
}

// The Shell rename can survive power loss while its separate restore record is
// still zero-filled. The outstanding cleanup receipt already identifies both
// the payload and its original name. Look up that object only on a departed path.
#[cfg(windows)]
fn repair_recycle_info(source: &CleanupSource) -> io::Result<()> {
    use std::{fs::{File, OpenOptions}, io::{Read, Seek, Write},
        os::windows::{ffi::{OsStrExt, OsStringExt}, fs::{MetadataExt, OpenOptionsExt}, io::{AsRawHandle, FromRawHandle}}};
    use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, Storage::FileSystem::*};

    let (_, id) = source.generation.object_id().unwrap();
    let descriptor = if id[8..] == [0; 8] {
        FILE_ID_DESCRIPTOR { dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32, Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 { FileId: i64::from_le_bytes(id[..8].try_into().unwrap()) } }
    } else {
        FILE_ID_DESCRIPTOR { dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32, Type: ExtendedFileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 { ExtendedFileId: FILE_ID_128 { Identifier: id } } }
    };
    // The source's parent may have been removed by the same cleanup.
    let mut parents = source.path.ancestors().skip(1);
    let volume = loop {
        let Some(path) = parents.next() else { return Ok(()); };
        match OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path) {
            Ok(dir) => break dir,
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => continue,
            Err(e) => return Err(e),
        }
    };
    let handle = unsafe { OpenFileById(volume.as_raw_handle(), &descriptor, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, std::ptr::null(), FILE_FLAG_OPEN_REPARSE_POINT) };
    if handle == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(e) };
    }
    let file = unsafe { File::from_raw_handle(handle) };
    if !source.generation.matches_input(&crate::io::reader::physical_file_generation(&file)?) { return Ok(()); }
    // A directory named $Recycle.Bin under an ordinary Watch root is user data.
    // The GUID form anchors this check to the real root even on a mounted volume.
    let path = crate::io::resource_lifecycle::with_handle_path(&file, VOLUME_NAME_GUID,
        |wide| PathBuf::from(std::ffi::OsString::from_wide(wide)))?;
    if !path.ancestors().nth(3).is_some_and(|root| root.parent().is_none()) { return Ok(()); }
    let Some(info) = recycle_info_path(&path) else { return Ok(()); };
    let sid = crate::runtime::current_user_sid()?;
    if path.parent().and_then(Path::file_name) != Some(std::ffi::OsStr::new(&sid)) { return Ok(()); }

    let mut payload = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut payload) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut record = match options.open(&info) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && payload.nNumberOfLinks == 1 =>
            options.create_new(true).open(&info)?,
        result => result?,
    };
    let mut attributes = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(record.as_raw_handle(), &mut attributes) } == 0 { return Err(io::Error::last_os_error()); }
    if attributes.nNumberOfLinks != 1 || attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("Unexpected recycle metadata identity"));
    }

    // Windows 10+ $I v2 is four little-endian fields followed by the
    // NUL-terminated UTF-16 original path. Use the record creation time as
    // deletion time so an interrupted repair produces identical bytes on replay.
    let path = std::path::absolute(&source.path)?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let metadata = record.metadata()?;
    let mut expected = Vec::with_capacity(28 + wide.len() * 2);
    expected.extend(2u64.to_le_bytes());
    expected.extend(source.generation.len.to_le_bytes());
    expected.extend(metadata.creation_time().to_le_bytes());
    expected.extend((wide.len() as u32).to_le_bytes());
    for c in wide { expected.extend(c.to_le_bytes()); }
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Unrecognized recycle metadata");
    if metadata.len() > expected.len() as u64 { return Err(invalid()); }
    let mut actual = Vec::with_capacity(metadata.len() as usize);
    record.read_to_end(&mut actual)?;
    if actual.len() >= 24 && actual[16..24].iter().any(|&byte| byte != 0) {
        expected[16..24].copy_from_slice(&actual[16..24]);
    }
    if actual == expected {
        return record.sync_all();
    }
    if actual.iter().zip(&expected).any(|(&a,&b)| a != 0 && a != b) {
        return Err(invalid());
    }
    if payload.nNumberOfLinks != 1 { return Err(io::Error::other("Ambiguous recycled hard link")); }
    record.rewind()?;
    record.write_all(&expected)?;
    record.sync_all()
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
