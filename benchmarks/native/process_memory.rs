use std::io;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

// PROCESS_MEMORY_COUNTERS from psapi.h. Keep the binding in the test build.
#[repr(C)]
#[derive(Default)]
pub(crate) struct ProcessMemory {
    size: u32,
    page_faults: u32,
    pub(crate) peak_working_set: usize,
    pub(crate) working_set: usize,
    peak_paged_pool: usize,
    paged_pool: usize,
    peak_nonpaged_pool: usize,
    nonpaged_pool: usize,
    pub(crate) commit: usize,
    pub(crate) peak_commit: usize,
}

#[link(name = "kernel32")]
extern "system" {
    fn K32GetProcessMemoryInfo(process: HANDLE, counters: *mut ProcessMemory, size: u32) -> i32;
}

pub(crate) fn process_memory() -> io::Result<ProcessMemory> {
    let size = std::mem::size_of::<ProcessMemory>() as u32;
    let mut counters = ProcessMemory {
        size,
        ..Default::default()
    };
    if unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(counters)
}
