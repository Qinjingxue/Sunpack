use std::io;
mod win {
    use std::ffi::c_void;
    use std::io;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        fn ReplaceFileW(
            target: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *const c_void,
            reserved: *const c_void,
        ) -> i32;
    }
    pub(crate) fn replace(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        // Match the existing GUI atomic writer: ReplaceFile allows a reader
        // with FILE_SHARE_DELETE to retain the old file. MoveFileEx replacement
        // can return ACCESS_DENIED while that perfectly valid reader is open.
        // An external reader controls when the sharing lock is released.
        // Retry only Windows sharing conflicts; all other errors remain
        // terminal. No arbitrary two-attempt failure under heavy I/O.
        loop {
            if unsafe {
                ReplaceFileW(
                    to.as_ptr(),
                    from.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            } != 0
            {
                return Ok(());
            }
            let replace_error = io::Error::last_os_error();
            // A new log has no target. Installed Modify-only directories can
            // also reject ReplaceFile with UNABLE_TO_REMOVE_REPLACED (1175).
            // Preserve that existing fallback without masking sharing errors.
            let error = if matches!(replace_error.raw_os_error(), Some(2 | 1175)) {
                if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } != 0 {
                    return Ok(());
                }
                io::Error::last_os_error()
            } else {
                replace_error
            };
            if !super::sharing_conflict(&error) {
                return Err(error);
            }
            // Windows has no waitable handle for another process's sharing
            // violation. Poll with a quiet interval instead of busy-spinning.
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}
pub(crate) fn sharing_conflict(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(32 | 33))
}

pub(crate) use win::replace;
