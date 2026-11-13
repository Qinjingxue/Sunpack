use std::{io, path::Path};

#[cfg(windows)]
pub(super) fn recycle<'a>(paths: impl Iterator<Item = &'a Path>) -> io::Result<()> {
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

    let mut paths = paths.peekable();
    if paths.peek().is_none() {
        return Ok(());
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
        for path in paths {
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
pub(super) fn recycle<'a>(_: impl Iterator<Item = &'a Path>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recycling requires Windows",
    ))
}
