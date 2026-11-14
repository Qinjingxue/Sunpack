//! Arm configuration notifications before publishing a directory subscription.
use super::iocp::{CancelIoEx, Overlapped};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::sync::Mutex;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(a: *mut c_void, manual: i32, initial: i32, name: *const u16) -> *mut c_void;
    fn SetEvent(event: *mut c_void) -> i32;
    fn WaitForMultipleObjects(
        count: u32,
        handles: *const *mut c_void,
        all: i32,
        timeout: u32,
    ) -> u32;
    fn ReadDirectoryChangesW(
        file: *mut c_void,
        buffer: *mut c_void,
        size: u32,
        recursive: i32,
        filter: u32,
        bytes: *mut u32,
        overlapped: *mut Overlapped,
        callback: *mut c_void,
    ) -> i32;
    fn GetOverlappedResult(
        file: *mut c_void,
        overlapped: *mut Overlapped,
        bytes: *mut u32,
        wait: i32,
    ) -> i32;
}

fn event(manual_reset: bool) -> io::Result<OwnedHandle> {
    let handle = unsafe {
        CreateEventW(
            std::ptr::null_mut(),
            i32::from(manual_reset),
            0,
            std::ptr::null(),
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(crate) struct DirectoryChange {
    pub(crate) name: String,
    pub(crate) action: u32,
}

struct Request {
    file: File,
    _event: OwnedHandle,
    // Both addresses must remain fixed until cancellation has completed.
    overlapped: Box<Overlapped>,
    buffer: Box<[u32]>,
    pending: bool,
    recursive: bool,
    filter: u32,
}

// The boxed OS buffers stay fixed; access and cancellation are serialized by
// NativeConfigChanges.request, and Drop drains I/O before freeing either box.
unsafe impl Send for Request {}

impl Request {
    fn arm(&mut self) -> io::Result<()> {
        let result = unsafe {
            ReadDirectoryChangesW(
                self.file.as_raw_handle(),
                self.buffer.as_mut_ptr().cast(),
                (self.buffer.len() * 4) as u32,
                i32::from(self.recursive),
                self.filter,
                std::ptr::null_mut(),
                &mut *self.overlapped,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(997) {
                return Err(error);
            }
        }
        self.pending = true;
        Ok(())
    }

    fn names(&self, size: usize) -> io::Result<Vec<DirectoryChange>> {
        let size = size.min(self.buffer.len() * 4);
        let bytes = unsafe { std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), size) };
        let mut names = Vec::new();
        let mut offset = 0;
        loop {
            let header = bytes
                .get(offset..offset + 12)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            let next = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
            let length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
            let name = bytes
                .get(offset + 12..offset + 12 + length)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            if length % 2 != 0 || offset % 4 != 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // FILE_NOTIFY_INFORMATION names are aligned UTF-16; decode once.
            let wide =
                unsafe { std::slice::from_raw_parts(name.as_ptr().cast::<u16>(), length / 2) };
            names.push(DirectoryChange {
                name: String::from_utf16_lossy(wide),
                action: u32::from_le_bytes(header[4..8].try_into().unwrap()),
            });
            if next == 0 {
                break;
            }
            offset += next;
        }
        Ok(names)
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if self.pending {
            // Cancellation is asynchronous: drain it before freeing the buffers.
            unsafe {
                CancelIoEx(self.file.as_raw_handle(), &mut *self.overlapped);
                let mut bytes = 0;
                GetOverlappedResult(
                    self.file.as_raw_handle(),
                    &mut *self.overlapped,
                    &mut bytes,
                    1,
                );
            }
        }
    }
}

pub(crate) struct NativeConfigChanges {
    request: Mutex<Option<Request>>,
    stopped: OwnedHandle,
}

impl NativeConfigChanges {
    pub(crate) fn observe(path: PathBuf, recursive: bool, filter: u32, buffer_bytes: usize) -> io::Result<Self> {
        let stopped = event(false)?;
        // Shares deletion, so promotion never needs to drain this subscription.
        let file = OpenOptions::new()
            .access_mode(1)
            .share_mode(7)
            .custom_flags(0x4200_0000)
            .open(path)?;
        // OVERLAPPED completion events must remain signaled until the result is collected.
        let event = event(true)?;
        let mut request = Request {
            file,
            overlapped: Box::new(Overlapped {
                event: event.as_raw_handle(),
                ..Default::default()
            }),
            _event: event,
            buffer: vec![0u32; buffer_bytes / 4].into_boxed_slice(),
            pending: false,
            recursive,
            filter,
        };
        request.arm()?;
        Ok(Self {
            request: Mutex::new(Some(request)),
            stopped,
        })
    }

    // None denotes overflow: invalidate all subscribed files in this directory.
    pub(crate) fn read(&self) -> io::Result<Option<Vec<DirectoryChange>>> {
        let mut guard = self.request.lock().unwrap();
        let Some(request) = guard.as_mut() else {
            return Ok(Some(Vec::new()));
        };
        let handles = [self.stopped.as_raw_handle(), request._event.as_raw_handle()];
        match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, u32::MAX) } {
            0 => {
                guard.take();
                return Ok(Some(Vec::new()));
            }
            1 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        let mut size = 0;
        if unsafe {
            GetOverlappedResult(
                request.file.as_raw_handle(),
                &mut *request.overlapped,
                &mut size,
                0,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            request.pending = false;
            if error.raw_os_error() == Some(1022) {
                request.arm()?;
                return Ok(None);
            }
            return Err(error);
        }
        request.pending = false;
        let names = if size == 0 {
            None
        } else {
            Some(request.names(size as usize)?)
        };
        request.arm()?;
        Ok(names)
    }

    pub(crate) fn close(&self) {
        unsafe {
            SetEvent(self.stopped.as_raw_handle());
        }
        self.request.lock().unwrap().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_buffers_recover_after_bursts_and_release_the_directory() {
        for capacity in [4096, 64_000] {
            let root = std::env::temp_dir().join(format!(
                "sunpack-notification-buffer-{}-{capacity}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            let changes = NativeConfigChanges::observe(root.clone(), true, 0x17f, capacity).unwrap();
            assert_eq!(changes.request.lock().unwrap().as_ref().unwrap().buffer.len() * 4, capacity);
            // An armed request completes first; further events accumulate while
            // its consumer is paused. Exceed both supported buffer capacities.
            for index in 0..1000 {
                std::fs::write(root.join(format!("{index:04}-{}", "x".repeat(100))), []).unwrap();
            }
            let mut overflow = false;
            for index in 0..3 {
                std::fs::write(root.join(format!("wake-{index}")), []).unwrap();
                if changes.read().unwrap().is_none() {
                    overflow = true;
                    break;
                }
            }
            assert!(overflow, "burst must exercise the recovery notification");
            std::fs::write(root.join("after-overflow"), []).unwrap();
            loop {
                if changes.read().unwrap().is_some_and(|names| names.iter().any(|name| name.name == "after-overflow" && name.action == 1)) {
                    break;
                }
            }
            changes.close();
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn completion_event_is_manual_reset_while_stop_event_is_auto_reset() {
        let completion = event(true).unwrap();
        let stopped = event(false).unwrap();
        let completion_handle = [completion.as_raw_handle()];
        let stopped_handle = [stopped.as_raw_handle()];

        unsafe {
            assert_ne!(SetEvent(completion.as_raw_handle()), 0);
            assert_eq!(
                WaitForMultipleObjects(1, completion_handle.as_ptr(), 0, 0),
                0
            );
            assert_eq!(
                WaitForMultipleObjects(1, completion_handle.as_ptr(), 0, 0),
                0
            );

            assert_ne!(SetEvent(stopped.as_raw_handle()), 0);
            assert_eq!(WaitForMultipleObjects(1, stopped_handle.as_ptr(), 0, 0), 0);
            assert_eq!(
                WaitForMultipleObjects(1, stopped_handle.as_ptr(), 0, 0),
                258
            );
        }
    }
}
