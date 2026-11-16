//! Windows-only overlapped sequential reader used by the embedded scanner.
//!
//! This module deliberately owns a scan-local file handle and completion port.
//! The normal reader, shared handle pool, and request cache remain synchronous
//! and unchanged. A scan keeps a bounded read window, hands completed buffers
//! to scoped scan workers, and immediately reissues the next sequential read with a
//! separate pooled buffer.

use super::cancellation::Cancellation;
use super::reader::{
    physical_file_generation, physical_file_generation_from_metadata, PhysicalFileGeneration,
};
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
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
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
    #[cfg(test)]
    pub(crate) discarded_results: usize,
    #[cfg(test)]
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
            // PendingReads drains operations before buffers or handles can
            // be released, including error and panic unwinding paths.
            unsafe {
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

fn open_handles(path: &Path, share_mode: u32) -> io::Result<IocpHandles> {
    let resource = crate::io::resource_lifecycle::NativeResourceGuard::register(
        [path.to_path_buf()],
    )?;
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let file = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            share_mode,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
            null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }

    let port = unsafe { CreateIoCompletionPort(file, null_mut(), 0, 0) };
    if port.is_null() || port == INVALID_HANDLE_VALUE {
        let error = last_error();
        unsafe {
            let _ = CloseHandle(file);
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
    pending: &mut PendingReads<'_>,
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
    submit_slot(pending.handles, &mut slot)?;
    pending.slots.insert(key, slot);
    Ok(true)
}

// Cancellation alone does not release OVERLAPPED storage: Windows may still
// write into the buffers until each completion has been dequeued.
struct PendingReads<'a> {
    handles: &'a IocpHandles,
    slots: HashMap<usize, Box<IocpSlot>>,
}

impl Drop for PendingReads<'_> {
    fn drop(&mut self) {
        for slot in self.slots.values_mut() {
            unsafe {
                let _ = CancelIoEx(self.handles.file, &mut slot.overlapped);
            }
        }

        while !self.slots.is_empty() {
            let mut bytes = 0u32;
            let mut key = 0usize;
            let mut overlapped = null_mut();
            let _ = unsafe {
                GetQueuedCompletionStatus(
                    self.handles.port,
                    &mut bytes,
                    &mut key,
                    &mut overlapped,
                    INFINITE,
                )
            };
            if !overlapped.is_null() {
                self.slots.remove(&(overlapped as usize));
            }
        }
    }
}

// Read-ahead has two slots. Hold completed buffers inline until the
// next logical chunk can be consumed and its slot recycled.
struct OrderedReads {
    next_offset: u64,
    ready: [Option<Box<IocpSlot>>; 2],
}
impl OrderedReads {
    fn new(offset: u64) -> Self {
        Self { next_offset: offset, ready: [None, None] }
    }
    fn completed(&mut self, slot: Box<IocpSlot>) {
        let vacant = self.ready.iter_mut().find(|ready| ready.is_none())
            .expect("ordered read has at most two completed slots");
        *vacant = Some(slot);
    }
    fn next(&mut self) -> Option<Box<IocpSlot>> {
        let offset = self.next_offset;
        let slot = self.ready.iter_mut()
            .find(|ready| ready.as_ref().is_some_and(|slot| slot.read_start == offset))?
            .take()?;
        self.next_offset += slot.bytes_read as u64;
        Some(slot)
    }
}

pub(crate) const ORDERED_READ_CHUNK: usize = 256 * 1024;

/// Stream one exact range of the observed file in offset order.
/// The callback runs on the caller's admitted worker; no per-file thread or
/// unbounded completion queue is created. The caller revalidates the path and
/// its USN before publishing any result derived from this handle.
pub(crate) fn read_range_ordered(
    path: &Path,
    offset: u64,
    len: u64,
    validate_generation: impl FnOnce(&PhysicalFileGeneration) -> io::Result<()>,
    mut consume: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    use std::os::windows::io::FromRawHandle;
    const CHUNK: usize = ORDERED_READ_CHUNK;
    let end = offset.checked_add(len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "IOCP range overflows")
    })?;
    let cancellation = Cancellation::current();
    cancellation.check_io()?;
    // For a single buffer, confirm readiness with the read handle itself.
    // Keep sharing enabled during long reads so writers and renames can proceed.
    let share_mode = if len <= CHUNK as u64 {
        FILE_SHARE_READ
    } else {
        SHARE_ALL
    };
    let handles = Arc::new(open_handles(path, share_mode)?);
    // Borrow the very same handle used by overlapped reads, without closing it.
    let file = std::mem::ManuallyDrop::new(unsafe {
        std::fs::File::from_raw_handle(handles.file)
    });
    let metadata = file.metadata()?;
    let before = physical_file_generation_from_metadata(&file, &metadata)?;
    validate_generation(&before)?;
    if end > metadata.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "IOCP range exceeds file"));
    }
    let wake_handles = Arc::clone(&handles);
    let _subscription = cancellation.subscribe(move || unsafe {
        CancelIoEx(wake_handles.file, null_mut());
        PostQueuedCompletionStatus(wake_handles.port, 0, WORKER_COMPLETION_KEY, null_mut());
    });
    let mut pending = PendingReads { handles: &handles, slots: HashMap::with_capacity(2) };
    let mut next_read = offset;
    for _ in 0..len.div_ceil(CHUNK as u64).min(2) {
        submit_next_slot(&mut pending, &mut next_read, end, CHUNK, 0,
            Box::new(IocpSlot::new(CHUNK.min(len as usize))))?;
    }
    let mut ordered = OrderedReads::new(offset);
    while ordered.next_offset < end {
        cancellation.check_io()?;
        let mut bytes = 0;
        let mut key = 0;
        let mut overlapped = null_mut();
        let ok = unsafe { GetQueuedCompletionStatus(handles.port, &mut bytes,
            &mut key, &mut overlapped, INFINITE) };
        if overlapped.is_null() {
            cancellation.check_io()?;
            if ok == 0 { return Err(last_error()); }
            continue;
        }
        let mut slot = pending.slots.remove(&(overlapped as usize))
            .ok_or_else(|| io::Error::other("unexpected IOCP range completion"))?;
        if ok == 0 { return Err(last_error()); }
        cancellation.check_io()?;
        if bytes as usize != slot.buffer.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short IOCP range read"));
        }
        slot.bytes_read = bytes as usize;
        ordered.completed(slot);
        while let Some(slot) = ordered.next() {
            consume(&slot.buffer[..slot.bytes_read])?;
            cancellation.check_io()?;
            submit_next_slot(&mut pending, &mut next_read, end, CHUNK, 0, slot)?;
        }
    }
    if before != physical_file_generation(&file)? {
        return Err(io::Error::other("file changed while streaming range"));
    }
    Ok(())
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
    C: FnMut(T) -> io::Result<()> + Send,
{
    let cancellation = Cancellation::current();
    cancellation.check_io()?;
    if file_size == 0 {
        return Ok(IocpScanOutput {
            #[cfg(test)]
            discarded_results: 0,
            #[cfg(test)]
            read_operations: 0,
        });
    }
    let chunk_bytes = chunk_bytes.max(64 * 1024);
    let buffer_count = buffer_count.clamp(2, 64);
    let worker_count = requested_worker_count
        .clamp(1, 8)
        .min(rayon::current_num_threads().clamp(1, 8));
    let expected_read_operations = file_size.div_ceil(chunk_bytes as u64);
    let handles = Arc::new(open_handles(path, SHARE_ALL)?);
    let wake_handles = Arc::clone(&handles);
    let _subscription = cancellation.subscribe(move || unsafe {
        CancelIoEx(wake_handles.file, null_mut());
        PostQueuedCompletionStatus(wake_handles.port, 0, WORKER_COMPLETION_KEY, null_mut());
    });
    let scan = &scan;

    // Producers stay on their calling threads. A separate shared pool runs
    // finite matching jobs, so concurrent Rayon producers cannot starve them.
    let result = scan_pool().in_place_scope(|scope| -> io::Result<IocpScanOutput> {
        // Read slots stay owned by the IOCP producer. Completed bytes move to
        // independent scan jobs, so the slot can issue its next predicted
        // sequential read without waiting for matching to finish.
        // Every allocation must be able to own a distinct real read job. Short
        // streams cannot use the full configured pool; long streams retain the
        // original IO depth and matching concurrency.
        let jobs = usize::try_from(expected_read_operations).unwrap_or(usize::MAX);
        let read_slots = buffer_count.min(jobs);
        let job_capacity = buffer_count
            .saturating_add(worker_count)
            .min(jobs - read_slots);
        let slot_capacity = chunk_bytes.saturating_add(overlap).min(file_size as usize);
        let (done_tx, done_rx) = mpsc::channel::<(Vec<u8>, std::thread::Result<ScanBatch<T>>)>();

        let mut pending = PendingReads {
            handles: &handles,
            slots: HashMap::new(),
        };
        let mut completed_slots = VecDeque::<Box<IocpSlot>>::new();
        let mut ready_jobs = VecDeque::<ScanJob>::new();
        let mut available_buffers = (0..job_capacity)
            .map(|_| Vec::with_capacity(slot_capacity))
            .collect::<Vec<_>>();
        let mut next_base = 0u64;
        let mut scan_jobs = 0usize;
        #[cfg(test)]
        let mut discarded_results = 0;
        let mut initial_error = None;
        for _ in 0..read_slots {
            if let Err(error) = cancellation.check_io() {
                initial_error = Some(error);
                break;
            }
            match submit_next_slot(
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
            return Err(error);
        }

        let mut fatal_error = None;
        while !pending.slots.is_empty()
            || !completed_slots.is_empty()
            || !ready_jobs.is_empty()
            || scan_jobs > 0
        {
            if let Err(error) = cancellation.check_io() {
                fatal_error = Some(error);
                break;
            }
            loop {
                match done_rx.try_recv() {
                    Ok((buffer, hits)) => {
                        scan_jobs = scan_jobs.saturating_sub(1);
                        let hits = hits.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
                        #[cfg(test)]
                        {
                            discarded_results += hits.discarded_results;
                        }
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
                if let Err(error) = cancellation.check_io() {
                    fatal_error = Some(error);
                    break;
                }
                if next_base >= file_size {
                    ready_jobs.push_back(ScanJob {
                        buffer: slot.buffer,
                        read_start: slot.read_start,
                        leading_overlap: slot.leading_overlap,
                        bytes_read: slot.bytes_read,
                    });
                    continue;
                }
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
                match submit_next_slot(
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
                if let Err(error) = cancellation.check_io() {
                    fatal_error = Some(error);
                    break;
                }
                // One-chunk files already run on the batch's Rayon workers;
                // matching inline avoids a second scheduling round entirely.
                if expected_read_operations == 1 {
                    let hits = scan(
                        &job.buffer[..job.bytes_read],
                        job.leading_overlap,
                        job.read_start,
                    );
                    #[cfg(test)]
                    {
                        discarded_results += hits.discarded_results;
                    }
                    if let Err(error) = collect(hits.results) {
                        fatal_error = Some(error);
                        break;
                    }
                    available_buffers.push(job.buffer);
                    continue;
                }
                let done_tx = done_tx.clone();
                let worker_handles = Arc::clone(&handles);
                let worker_cancellation = cancellation.clone();
                scan_jobs += 1;
                scope.spawn(move |_| {
                    // Always deliver a completion, including a callback panic.
                    // Rayon cannot propagate it while the producer still waits
                    // for scan_jobs to reach zero inside this scope.
                    let hits = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        worker_cancellation.run(|| {
                            scan(
                                &job.buffer[..job.bytes_read],
                                job.leading_overlap,
                                job.read_start,
                            )
                        })
                    }));
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

            if pending.slots.is_empty() && scan_jobs == 0 {
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
            let Some(mut slot) = pending.slots.remove(&(overlapped as usize)) else {
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
            return Err(fatal_error.expect("IOCP fatal error should be present"));
        }

        Ok(IocpScanOutput {
            #[cfg(test)]
            discarded_results,
            #[cfg(test)]
            read_operations: expected_read_operations,
        })
    });

    result
}

#[cfg(test)]
#[path = "../../tests/unit/io/iocp/tests.rs"]
mod tests;
