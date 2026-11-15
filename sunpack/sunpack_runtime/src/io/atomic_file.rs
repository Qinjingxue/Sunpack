use std::io;
mod win {
    use std::ffi::c_void;
    use std::io;
    use std::path::Path;
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

    pub(crate) fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use std::path::{Component, Prefix};

        let wide_path = |path: &Path| -> io::Result<Vec<u16>> {
            // Win32 directory moves can fail before reaching MAX_PATH when the
            // path leaves insufficient space for a child component.
            if path.as_os_str().len() < 248 {
                return Ok(path.as_os_str().encode_wide().chain([0]).collect());
            }
            let path = std::path::absolute(path)?;
            let (prefix, skip) = match path.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(_) => (r"\\?\", 0),
                    Prefix::UNC(_, _) => (r"\\?\UNC\", 2),
                    _ => ("", 0),
                },
                _ => ("", 0),
            };
            Ok(prefix
                .encode_utf16()
                .chain(path.as_os_str().encode_wide().skip(skip))
                .chain([0])
                .collect())
        };

        let source = wide_path(source)?;
        let destination = wide_path(destination)?;
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn replace_inner(
        from: &std::path::Path,
        to: &std::path::Path,
        cancellation: &super::super::cancellation::Cancellation,
        retry_sharing: bool,
    ) -> io::Result<()> {
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
            cancellation.check_io()?;
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
                cancellation.check_io()?;
                if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } != 0 {
                    return Ok(());
                }
                io::Error::last_os_error()
            } else {
                replace_error
            };
            if !retry_sharing || !super::sharing_conflict(&error) {
                return Err(error);
            }
            cancellation.check_io()?;
            // Windows has no waitable handle for another process's sharing
            // violation. Poll with a quiet interval instead of busy-spinning.
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    pub(crate) fn replace_with_cancel(
        from: &Path, to: &Path, cancellation: &super::super::cancellation::Cancellation,
    ) -> io::Result<()> {
        replace_inner(from, to, cancellation, true)
    }

    // Snapshot owners can retain their WAL and retry on the next mutation.
    // Do not wait for an unrelated process to release a sharing handle.
    pub(crate) fn replace_once(from: &Path, to: &Path) -> io::Result<()> {
        replace_inner(from, to, &super::super::cancellation::Cancellation::default(), false)
    }

}
pub(crate) fn sharing_conflict(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(32 | 33))
}

pub(crate) use win::{rename_no_replace, replace_once, replace_with_cancel};

// Existing transaction callers finish publication once started. Opt into
// cancellable retries only where the owner can discard its temporary file.
pub(crate) fn replace(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
    replace_with_cancel(from, to, &super::cancellation::Cancellation::default())
}
