//! Windows-only overlapped sequential reader used by the embedded scanner.
//!
//! This module deliberately owns a scan-local file handle and completion port.
//! The normal reader, shared handle pool, and request cache remain synchronous
//! and unchanged. A scan keeps a bounded read window, hands completed buffers
//! to scoped scan workers, and immediately reissues the next sequential read with a
//! separate pooled buffer.

use super::ScanBatch;
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::{mpsc, Arc, OnceLock};

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const INFINITE: u32 = u32::MAX;
const ERROR_IO_PENDING: u32 = 997;
const WORKER_COMPLETION_KEY: usize = usize::MAX;

const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

#[repr(C)]
#[derive(Default)]
pub(super) struct Overlapped {
    pub(super) internal: usize,
    pub(super) internal_high: usize,
    pub(super) offset: u32,
    pub(super) offset_high: u32,
    pub(super) event: Handle,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
    fn CreateIoCompletionPort(
        file_handle: Handle,
        existing_completion_port: Handle,
        completion_key: usize,
        number_of_concurrent_threads: u32,
    ) -> Handle;
    fn ReadFile(
        file: Handle,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn GetQueuedCompletionStatus(
        completion_port: Handle,
        bytes_transferred: *mut u32,
        completion_key: *mut usize,
        overlapped: *mut *mut Overlapped,
        milliseconds: u32,
    ) -> i32;
    fn PostQueuedCompletionStatus(
        completion_port: Handle,
        bytes_transferred: u32,
        completion_key: usize,
        overlapped: *mut Overlapped,
    ) -> i32;
    pub(super) fn CancelIoEx(file: Handle, overlapped: *mut Overlapped) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}

struct IocpSlot {
    overlapped: Overlapped,
    buffer: Vec<u8>,
    read_start: u64,
    leading_overlap: usize,
    bytes_read: usize,
}

struct ScanJob {
    buffer: Vec<u8>,
    read_start: u64,
    leading_overlap: usize,
    bytes_read: usize,
}

// A slot is moved only after its OVERLAPPED operation has completed.  The
// completion port never accesses it after the owner removes it from pending.
unsafe impl Send for IocpSlot {}

pub(crate) struct IocpScanOutput {
    pub(crate) discarded_results: usize,
    pub(crate) read_bytes: u64,
    pub(crate) read_operations: u64,
}

fn scan_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(rayon::current_num_threads().clamp(1, 8))
            .thread_name(|index| format!("sunpack-embedded-scan-{index}"))
            .build()
            .expect("embedded scan thread pool can start")
    })
}

impl IocpSlot {
    fn new(capacity: usize) -> Self {
        Self {
            overlapped: Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: null_mut(),
            },
            buffer: vec![0; capacity],
            read_start: 0,
            leading_overlap: 0,
            bytes_read: 0,
        }
    }

    fn key(&mut self) -> usize {
        (&mut self.overlapped as *mut Overlapped).cast::<c_void>() as usize
    }
}

struct IocpHandles {
    file: Handle,
    port: Handle,
    _resource: crate::io::resource_lifecycle::NativeResourceGuard,
}

// Windows kernel handles are process-wide synchronization objects. The
// handle values are shared read-only by the producer and are closed only after
// the scan workers have joined and all pending operations have been drained.
unsafe impl Send for IocpHandles {}
unsafe impl Sync for IocpHandles {}

impl Drop for IocpHandles {
    fn drop(&mut self) {
        if !self.file.is_null() && self.file != INVALID_HANDLE_VALUE {
            // The normal path drains all operations before this point.  This
            // best-effort cancellation protects panic/error unwinding paths.
            unsafe {
                let _ = CancelIoEx(self.file, null_mut());
                let _ = CloseHandle(self.file);
            }
        }
        if !self.port.is_null() && self.port != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.port);
            }
        }
    }
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn open_handles(path: &Path) -> io::Result<IocpHandles> {
    let resource = crate::io::resource_lifecycle::NativeResourceGuard::register(
        "iocp_file_handle",
        [path.to_path_buf()],
    )?;
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let file = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
            null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }

    let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
    if port.is_null() || port == INVALID_HANDLE_VALUE {
        let error = last_error();
        unsafe {
            let _ = CloseHandle(file);
        }
        return Err(error);
    }

    let associated = unsafe { CreateIoCompletionPort(file, port, 0, 0) };
    if associated.is_null() || associated == INVALID_HANDLE_VALUE {
        let error = last_error();
        unsafe {
            let _ = CloseHandle(file);
            let _ = CloseHandle(port);
        }
        return Err(error);
    }

    Ok(IocpHandles {
        file,
        port,
        _resource: resource,
    })
}

fn configure_slot(
    slot: &mut IocpSlot,
    base: u64,
    file_size: u64,
    chunk_bytes: usize,
    overlap: usize,
) -> io::Result<()> {
    let visible_end = base.saturating_add(chunk_bytes as u64).min(file_size);
    let read_start = base.saturating_sub(overlap as u64);
    let read_len = usize::try_from(visible_end.saturating_sub(read_start))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IOCP read is too large"))?;
    let bytes_to_read = u32::try_from(read_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "IOCP read length exceeds ReadFile's DWORD limit",
        )
    })?;

    slot.overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: read_start as u32,
        offset_high: (read_start >> 32) as u32,
        event: null_mut(),
    };
    slot.buffer.resize(read_len, 0);
    slot.read_start = read_start;
    slot.leading_overlap = (base - read_start) as usize;
    slot.bytes_read = 0;
    // Keep the requested length in the buffer itself; the caller passes it to
    // ReadFile immediately while the slot remains in the pending map.
    debug_assert_eq!(slot.buffer.len(), bytes_to_read as usize);
    Ok(())
}

fn submit_slot(handles: &IocpHandles, slot: &mut IocpSlot) -> io::Result<()> {
    let bytes_to_read = u32::try_from(slot.buffer.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IOCP buffer is too large"))?;
    let completed_synchronously = unsafe {
        ReadFile(
            handles.file,
            slot.buffer.as_mut_ptr().cast::<c_void>(),
            bytes_to_read,
            null_mut(),
            &mut slot.overlapped,
        )
    };
    if completed_synchronously != 0 {
        return Ok(());
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_IO_PENDING {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error as i32))
    }
}

fn submit_next_slot(
    handles: &IocpHandles,
    pending: &mut HashMap<usize, Box<IocpSlot>>,
    next_base: &mut u64,
    file_size: u64,
    chunk_bytes: usize,
    overlap: usize,
    mut slot: Box<IocpSlot>,
) -> io::Result<bool> {
    if *next_base >= file_size {
        return Ok(false);
    }
    let base = *next_base;
    let visible_end = base.saturating_add(chunk_bytes as u64).min(file_size);
    *next_base = visible_end;
    configure_slot(&mut slot, base, file_size, chunk_bytes, overlap)?;
    let key = slot.key();
    submit_slot(handles, &mut slot)?;
    pending.insert(key, slot);
    Ok(true)
}

fn cancel_pending(handles: &IocpHandles, pending: &mut HashMap<usize, Box<IocpSlot>>) {
    for slot in pending.values_mut() {
        unsafe {
            let _ = CancelIoEx(handles.file, &mut slot.overlapped);
        }
    }

    while !pending.is_empty() {
        let mut bytes = 0u32;
        let mut key = 0usize;
        let mut overlapped = null_mut();
        let _ = unsafe {
            GetQueuedCompletionStatus(
                handles.port,
                &mut bytes,
                &mut key,
                &mut overlapped,
                INFINITE,
            )
        };
        if !overlapped.is_null() {
            pending.remove(&(overlapped as usize));
        }
    }
}

/// Run a bounded overlapped sequential scan, handing each completed batch to
/// the caller before recycling its buffer. Result storage belongs to the sink.
///
/// `scan` receives a buffer containing `leading_overlap` bytes before the
/// visible chunk.  It may return results in any order; the caller is expected
/// to sort offsets after this function returns.
pub(crate) fn scan_file<T, F, C>(
    path: &Path,
    file_size: u64,
    chunk_bytes: usize,
    buffer_count: usize,
    requested_worker_count: usize,
    overlap: usize,
    scan: F,
    mut collect: C,
) -> io::Result<IocpScanOutput>
where
    T: Send,
    F: Fn(&[u8], usize, u64) -> ScanBatch<T> + Send + Sync,
    C: FnMut(Vec<T>) -> io::Result<()> + Send,
{
    if file_size == 0 {
        return Ok(IocpScanOutput {
            discarded_results: 0,
            read_bytes: 0,
            read_operations: 0,
        });
    }
    let chunk_bytes = chunk_bytes.max(64 * 1024);
    let buffer_count = buffer_count.clamp(2, 64);
    let worker_count = requested_worker_count
        .clamp(1, 8)
        .min(rayon::current_num_threads().clamp(1, 8));
    let mut expected_read_bytes = 0u64;
    let mut expected_read_operations = 0u64;
    let mut expected_base = 0u64;
    while expected_base < file_size {
        let visible_end = expected_base
            .saturating_add(chunk_bytes as u64)
            .min(file_size);
        let read_start = expected_base.saturating_sub(overlap as u64);
        expected_read_bytes =
            expected_read_bytes.saturating_add(visible_end.saturating_sub(read_start));
        expected_read_operations = expected_read_operations.saturating_add(1);
        expected_base = visible_end;
    }
    let handles = Arc::new(open_handles(path)?);
    let scan = &scan;

    // Producers stay on their calling threads. A separate shared pool runs
    // finite matching jobs, so concurrent Rayon producers cannot starve them.
    let result = scan_pool().in_place_scope(|scope| -> io::Result<IocpScanOutput> {
        // Read slots stay owned by the IOCP producer. Completed bytes move to
        // independent scan jobs, so the slot can issue its next predicted
        // sequential read without waiting for matching to finish.
        let job_capacity = buffer_count;
        let slot_capacity = chunk_bytes.saturating_add(overlap).min(file_size as usize);
        let (done_tx, done_rx) = mpsc::channel::<(Vec<u8>, ScanBatch<T>)>();

        let mut pending = HashMap::<usize, Box<IocpSlot>>::new();
        let mut completed_slots = VecDeque::<Box<IocpSlot>>::new();
        let mut ready_jobs = VecDeque::<ScanJob>::new();
        let mut available_buffers = (0..job_capacity.saturating_add(worker_count))
            .map(|_| Vec::with_capacity(slot_capacity))
            .collect::<Vec<_>>();
        let mut next_base = 0u64;
        let mut scan_jobs = 0usize;
        let mut discarded_results = 0;
        let mut initial_error = None;
        for _ in 0..buffer_count {
            match submit_next_slot(
                &handles,
                &mut pending,
                &mut next_base,
                file_size,
                chunk_bytes,
                overlap,
                Box::new(IocpSlot::new(slot_capacity)),
            ) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    initial_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = initial_error {
            cancel_pending(&handles, &mut pending);
            return Err(error);
        }

        let mut fatal_error = None;
        while !pending.is_empty()
            || !completed_slots.is_empty()
            || !ready_jobs.is_empty()
            || scan_jobs > 0
        {
            loop {
                match done_rx.try_recv() {
                    Ok((buffer, hits)) => {
                        scan_jobs = scan_jobs.saturating_sub(1);
                        discarded_results += hits.discarded_results;
                        if let Err(error) = collect(hits.results) {
                            fatal_error = Some(error);
                            break;
                        }
                        available_buffers.push(buffer);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        fatal_error = Some(io::Error::other("IOCP scanner workers stopped"));
                        break;
                    }
                }
            }
            if fatal_error.is_some() {
                break;
            }

            // Preserve the configured IO depth whenever there is a recycled
            // buffer. A full CPU queue only consumes the separate job pool.
            while let Some(mut slot) = completed_slots.pop_front() {
                let Some(replacement_buffer) = available_buffers.pop() else {
                    completed_slots.push_front(slot);
                    break;
                };
                let job = ScanJob {
                    buffer: std::mem::replace(&mut slot.buffer, replacement_buffer),
                    read_start: slot.read_start,
                    leading_overlap: slot.leading_overlap,
                    bytes_read: slot.bytes_read,
                };
                if next_base >= file_size {
                    available_buffers.push(slot.buffer);
                    ready_jobs.push_back(job);
                    continue;
                }
                match submit_next_slot(
                    &handles,
                    &mut pending,
                    &mut next_base,
                    file_size,
                    chunk_bytes,
                    overlap,
                    slot,
                ) {
                    Ok(true) => ready_jobs.push_back(job),
                    Ok(false) => {
                        fatal_error = Some(io::Error::other("IOCP slot ended unexpectedly"));
                        break;
                    }
                    Err(error) => {
                        available_buffers.push(job.buffer);
                        fatal_error = Some(error);
                        break;
                    }
                }
            }
            if fatal_error.is_some() {
                break;
            }

            while let Some(job) = ready_jobs.pop_front() {
                // One-chunk files already run on the batch's Rayon workers;
                // matching inline avoids a second scheduling round entirely.
                if expected_read_operations == 1 {
                    let hits = scan(
                        &job.buffer[..job.bytes_read],
                        job.leading_overlap,
                        job.read_start,
                    );
                    discarded_results += hits.discarded_results;
                    if let Err(error) = collect(hits.results) {
                        fatal_error = Some(error);
                        break;
                    }
                    available_buffers.push(job.buffer);
                    continue;
                }
                let done_tx = done_tx.clone();
                let worker_handles = Arc::clone(&handles);
                scan_jobs += 1;
                scope.spawn(move |_| {
                    let hits = scan(
                        &job.buffer[..job.bytes_read],
                        job.leading_overlap,
                        job.read_start,
                    );
                    let _ = done_tx.send((job.buffer, hits));
                    unsafe {
                        let _ = PostQueuedCompletionStatus(
                            worker_handles.port,
                            0,
                            WORKER_COMPLETION_KEY,
                            null_mut(),
                        );
                    }
                });
            }
            if fatal_error.is_some() {
                break;
            }

            if pending.is_empty() && scan_jobs == 0 {
                if completed_slots.is_empty() && ready_jobs.is_empty() {
                    break;
                }
                fatal_error = Some(io::Error::other("IOCP scanner pipeline stalled"));
                break;
            }
            let mut bytes = 0u32;
            let mut completion_key = 0usize;
            let mut overlapped = null_mut();
            let completed = unsafe {
                GetQueuedCompletionStatus(
                    handles.port,
                    &mut bytes,
                    &mut completion_key,
                    &mut overlapped,
                    INFINITE,
                )
            };
            if completion_key == WORKER_COMPLETION_KEY && overlapped.is_null() {
                continue;
            }
            if overlapped.is_null() {
                fatal_error = Some(last_error());
                break;
            }
            let Some(mut slot) = pending.remove(&(overlapped as usize)) else {
                fatal_error = Some(io::Error::other("unknown IOCP completion context"));
                break;
            };
            if completed == 0 {
                let error = unsafe { GetLastError() };
                fatal_error = Some(io::Error::from_raw_os_error(error as i32));
                break;
            }
            slot.bytes_read = (bytes as usize).min(slot.buffer.len());
            if slot.bytes_read > 0 {
                completed_slots.push_back(slot);
            } else {
                available_buffers.push(slot.buffer);
            }
        }

        if fatal_error.is_some() {
            cancel_pending(&handles, &mut pending);
            return Err(fatal_error.expect("IOCP fatal error should be present"));
        }

        Ok(IocpScanOutput {
            discarded_results,
            read_bytes: expected_read_bytes,
            read_operations: expected_read_operations,
        })
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapped_offset_supports_files_above_four_gibabytes() {
        let mut slot = IocpSlot::new(16);
        configure_slot(&mut slot, (4u64 << 30) + 123, (4u64 << 30) + 1024, 512, 7).unwrap();
        assert_eq!(slot.overlapped.offset, 116);
        assert_eq!(slot.overlapped.offset_high, 1);
        assert_eq!(slot.read_start, (4u64 << 30) + 116);
    }

    #[test]
    fn keeps_io_slots_independent_of_slow_scan_workers() {
        let chunk_bytes = 64 * 1024usize;
        let data = vec![0x5a; chunk_bytes * 8 + 17];
        let path = std::env::temp_dir().join(format!(
            "sunpack_iocp_slow_worker_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::write(&path, &data).unwrap();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let mut actual = Vec::new();
        let output = pool
            .install(|| {
                scan_file(
                    &path,
                    data.len() as u64,
                    chunk_bytes,
                    2,
                    1,
                    0,
                    |_, _, base_offset| {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        ScanBatch {
                            results: vec![base_offset],
                            discarded_results: 0,
                        }
                    },
                    |batch| {
                        actual.extend(batch);
                        Ok(())
                    },
                )
            })
            .unwrap();

        let expected = (0..data.len())
            .step_by(chunk_bytes)
            .map(|offset| offset as u64)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        assert_eq!(output.read_operations, expected.len() as u64);
        let _ = std::fs::remove_file(path);
    }
}
