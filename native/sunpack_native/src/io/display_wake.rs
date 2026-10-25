//! One UTC deadline and one notification, both waited by the existing writer.
use std::ffi::c_void;
use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
type Handle = *mut c_void;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(attributes: Handle, manual: i32, initial: i32, name: *const u16) -> Handle;
    fn CreateWaitableTimerW(attributes: Handle, manual: i32, name: *const u16) -> Handle;
    fn SetEvent(event: Handle) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn CancelWaitableTimer(timer: Handle) -> i32;
    fn SetWaitableTimer(
        timer: Handle,
        due: *const i64,
        period: i32,
        callback: Handle,
        arg: Handle,
        resume: i32,
    ) -> i32;
    fn WaitForMultipleObjects(count: u32, handles: *const Handle, all: i32, timeout: u32) -> u32;
}
pub(crate) struct Wake {
    event: usize,
    timer: usize,
    armed: AtomicI64,
}
impl Wake {
    pub(crate) fn new() -> io::Result<Self> {
        let event = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let timer = unsafe { CreateWaitableTimerW(std::ptr::null_mut(), 0, std::ptr::null()) };
        if timer.is_null() {
            unsafe {
                CloseHandle(event);
            }
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            event: event as usize,
            timer: timer as usize,
            armed: AtomicI64::new(0),
        })
    }
    pub(crate) fn notify(&self) {
        unsafe {
            SetEvent(self.event as Handle);
        }
    }
    pub(crate) fn wait(&self, utc_us: Option<i64>) -> io::Result<()> {
        if let Some(time) = utc_us.filter(|time| self.armed.load(Ordering::Relaxed) != *time) {
            let due = time
                .saturating_mul(10)
                .saturating_add(116_444_736_000_000_000);
            if unsafe {
                SetWaitableTimer(
                    self.timer as Handle,
                    &due,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            self.armed.store(time, Ordering::Relaxed);
        } else if utc_us.is_none() && self.armed.swap(0, Ordering::Relaxed) != 0 {
            unsafe {
                CancelWaitableTimer(self.timer as Handle);
            }
        }
        let handles = [self.event as Handle, self.timer as Handle];
        let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, u32::MAX) };
        if result == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if result == 1 {
            self.armed.store(0, Ordering::Relaxed);
        }
        Ok(())
    }
}
impl Drop for Wake {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.timer as Handle);
            CloseHandle(self.event as Handle);
        }
    }
}
