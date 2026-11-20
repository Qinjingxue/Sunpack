#![cfg(windows)]
#![windows_subsystem = "windows"]

#[cfg(not(panic = "unwind"))]
compile_error!("SunPack Watch Broker requires panic unwinding for connection and service cleanup");

use std::collections::HashMap;
use std::ffi::{c_void, OsString};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::thread;
use std::time::{Duration, Instant};
use sunpack_usn_core::protocol::{
    DirectoryQueryHeader, Opcode, Request, Response, Status, DIRECTORY_QUERY_HEADER_BYTES,
    FILE_ID_BYTES, MAX_DIRECTORY_QUERY_BYTES, MAX_VOLUME_GUID_BYTES, REQUEST_BYTES, RESPONSE_BYTES,
};
use sunpack_usn_core::{JournalReader, PIPE_NAME, SERVICE_NAME};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_NO_DATA, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const PIPE_BUFFER_BYTES: u32 = 4096;
const DIRECTORY_QUERY_CHUNK_BYTES: usize = 16 * 1024;
const _: () = assert!(MAX_DIRECTORY_QUERY_BYTES / FILE_ID_BYTES <= u16::MAX as usize + 1);
const MAX_CONNECTED_CLIENTS: u32 = 64;
const MAX_VOLUME_CONTEXTS: usize = 64;
const VOLUME_CONTEXT_IDLE_TTL: Duration = Duration::from_secs(60);
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
static CONFIG: OnceLock<BrokerConfig> = OnceLock::new();

#[derive(Debug)]
struct BrokerConfig {
    service_name: String,
    pipe_name: String,
}

impl BrokerConfig {
    fn from_args(mut arguments: impl Iterator<Item = String>) -> Self {
        let mut config = Self {
            service_name: SERVICE_NAME.to_owned(),
            pipe_name: PIPE_NAME.to_owned(),
        };
        while let Some(argument) = arguments.next() {
            let target = match argument.as_str() {
                "--service-name" => &mut config.service_name,
                "--pipe-name" => &mut config.pipe_name,
                _ => panic!("unknown Watch Broker argument: {argument}"),
            };
            *target = arguments
                .next()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| panic!("missing value for Watch Broker argument: {argument}"));
        }
        config
    }
}

fn broker_config() -> &'static BrokerConfig {
    CONFIG
        .get()
        .expect("Watch Broker configuration was not initialized")
}

define_windows_service!(ffi_service_main, service_main);

fn main() -> windows_service::Result<()> {
    let config = BrokerConfig::from_args(std::env::args().skip(1));
    CONFIG
        .set(config)
        .expect("Watch Broker configuration was initialized twice");
    service_dispatcher::start(&broker_config().service_name, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn run_service() -> windows_service::Result<()> {
    let stop_event = Arc::new(OwnedHandle::event().map_err(windows_service::Error::Winapi)?);
    let handler_event = Arc::clone(&stop_event);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_event.signal();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let config = broker_config();
    let status_handle = service_control_handler::register(&config.service_name, event_handler)?;
    let result = match PipeListener::new(&config.pipe_name) {
        Ok(listener) => {
            // A client that observes RUNNING can already connect to the first pipe.
            status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            serve_watch_lifetimes(&stop_event, listener)
        }
        Err(error) => Err(error),
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    result.map_err(windows_service::Error::Winapi)
}

fn serve_watch_lifetimes(stop_event: &OwnedHandle, mut listener: PipeListener) -> io::Result<()> {
    let journals = &JournalDispatcher::new()?;
    let connected_clients = &AtomicUsize::new(0);
    let ever_had_lease = &AtomicBool::new(false);
    let state_changed = &journals.state_changed;
    thread::scope(|workers| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            loop {
                let clients = connected_clients.load(Ordering::Acquire);
                let had_lease = ever_had_lease.load(Ordering::Acquire);
                // Before the first lease, only an explicit stop proves nobody will use us.
                let retiring = had_lease && clients == 0;
                if retiring && !listener.is_listening() {
                    break;
                }

                if clients < MAX_CONNECTED_CLIENTS as usize && !listener.is_listening() {
                    listener.listen(false)?;
                }
                let timeout = if retiring {
                    // An accepted connection may already be waiting when the
                    // previous client closes. Give that connection precedence.
                    0
                } else {
                    journals
                        .reap_idle(Instant::now())?
                        .map_or(INFINITE, |deadline| {
                            // Wait accepts whole milliseconds. Round up to avoid waking
                            // repeatedly before the expiry can be observed.
                            (deadline
                                .saturating_duration_since(Instant::now())
                                .as_millis()
                                + 1) as u32
                        })
                };
                let wait = if listener.is_listening() {
                    let handles = [stop_event.raw(), listener.event.raw(), state_changed.raw()];
                    unsafe {
                        WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout)
                    }
                } else {
                    let handles = [stop_event.raw(), state_changed.raw()];
                    unsafe {
                        WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout)
                    }
                };
                if wait == WAIT_OBJECT_0 {
                    break;
                }
                if wait == WAIT_FAILED {
                    return Err(io::Error::last_os_error());
                }
                if wait == WAIT_TIMEOUT {
                    if retiring {
                        break;
                    }
                    continue;
                }
                if listener.is_listening() && wait == WAIT_OBJECT_0 + 1 {
                    let pipe = listener.accept()?;
                    connected_clients.fetch_add(1, Ordering::AcqRel);
                    // Drop the join handle immediately. The scope still waits for
                    // clients on stop without retaining each finished OS handle.
                    thread::Builder::new().spawn_scoped(workers, move || {
                        // A failed client must release its lease count without
                        // propagating a panic to the listener's thread scope.
                        let _ = catch_unwind(|| {
                            serve_client(pipe, stop_event.raw(), journals, ever_had_lease)
                        });
                        connected_clients.fetch_sub(1, Ordering::AcqRel);
                        state_changed.signal();
                    })?;
                    continue;
                }
                let state_index = if listener.is_listening() { 2 } else { 1 };
                if wait != WAIT_OBJECT_0 + state_index {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }))
        .unwrap_or_else(|_| Err(io::Error::other("Watch Broker listener panicked")));
        // Errors must wake blocked clients before the scope joins them.
        stop_event.signal();
        drop(listener);
        result
    })
}

fn serve_client(
    pipe: OwnedHandle,
    stop_event: HANDLE,
    journals: &JournalDispatcher,
    ever_had_lease: &AtomicBool,
) -> io::Result<()> {
    // A lease belongs to this connection and ends with it.
    let mut leased = false;
    // Requests on one connection are serial. Each operation drains before
    // returning, so its event can be reused for the entire connection.
    let io_event = OwnedHandle::event()?;
    loop {
        let mut request_bytes = [0u8; REQUEST_BYTES];
        // A connected client may be descheduled between writes under load.
        // A clock is not evidence of disconnection; service stop and broken
        // pipes still end the pending overlapped read.
        let request =
            match read_overlapped(pipe.raw(), stop_event, io_event.raw(), &mut request_bytes)? {
                IoResult::Stopped | IoResult::Disconnected | IoResult::MoreData => break,
                IoResult::Completed(size) if size == REQUEST_BYTES => {
                    Request::decode(&request_bytes).ok()
                }
                IoResult::Completed(_) => None,
            };
        let Some(request) = request else {
            let response = Response {
                status: Status::InvalidRequest,
                ..Response::ok(0)
            };
            let _ = write_overlapped(pipe.raw(), stop_event, io_event.raw(), &response.encode());
            break;
        };
        let response =
            if !request_shape_is_valid(&request) || (request.opcode != Opcode::Hello && !leased) {
                (
                    Response {
                        status: Status::InvalidRequest,
                        ..Response::ok(request.request_id)
                    },
                    Vec::new(),
                )
            } else {
                if !leased {
                    ever_had_lease.store(true, Ordering::Release);
                    leased = true;
                }
                let query = if request.opcode == Opcode::ReadDirectoriesChanges {
                    let Some(query) = read_directory_query(
                        |buffer| read_overlapped(pipe.raw(), stop_event, io_event.raw(), buffer),
                        || remaining_pipe_message_bytes(pipe.raw()),
                    )?
                    else {
                        break;
                    };
                    Some(query)
                } else {
                    None
                };
                handle_request(journals, request, query)
            };
        let (response, payload) = response;
        match write_overlapped(pipe.raw(), stop_event, io_event.raw(), &response.encode())? {
            IoResult::Completed(size) if size == RESPONSE_BYTES => {}
            _ => break,
        }
        if !payload.is_empty() {
            match write_overlapped(pipe.raw(), stop_event, io_event.raw(), &payload)? {
                IoResult::Completed(size) if size == payload.len() => {}
                _ => break,
            }
        }
    }
    unsafe {
        DisconnectNamedPipe(pipe.raw());
    }
    Ok(())
}

struct DirectoryQuery {
    journal: u64,
    parents: HashMap<[u8; FILE_ID_BYTES], u16>,
}

fn read_directory_query(
    mut read: impl FnMut(&mut [u8]) -> io::Result<IoResult>,
    remaining_message_bytes: impl FnOnce() -> io::Result<usize>,
) -> io::Result<Option<DirectoryQuery>> {
    let mut header = [0u8; DIRECTORY_QUERY_HEADER_BYTES];
    if !matches!(
        read(&mut header)?,
        IoResult::Completed(DIRECTORY_QUERY_HEADER_BYTES)
    ) {
        return Ok(None);
    }
    let Some(DirectoryQueryHeader { id_bytes, journal }) = DirectoryQueryHeader::decode(&header)
    else {
        return Ok(None);
    };

    // Read the body of the single pipe message in ID-aligned fragments. In
    // message mode MORE_DATA fills the buffer and leaves the same message
    // pending. No large heap allocation is needed while waiting for its body.
    let mut buffer = [0u8; DIRECTORY_QUERY_CHUNK_BYTES];
    let first = id_bytes.min(buffer.len());
    if !receive_query_fragment(read(&mut buffer[..first])?, first, id_bytes) {
        return Ok(None);
    }
    let mut remaining = id_bytes - first;
    // MORE_DATA confirms there is a remainder of this same pipe message.
    // Check its size before reserving the index for a large client request.
    if remaining != 0 && remaining_message_bytes()? != remaining {
        return Ok(None);
    }
    let sampled_bytes = first + remaining.min(buffer.len());
    let mut parents = HashMap::with_capacity(sampled_bytes / FILE_ID_BYTES);
    let mut next_index = 0usize;
    let mut insert = |parents: &mut HashMap<_, _>, bytes: &[u8]| {
        let ids = bytes.as_chunks::<FILE_ID_BYTES>().0;
        for group in ids.chunk_by(|left, right| left == right) {
            next_index += group.len();
            parents.insert(group[0], (next_index - 1) as u16);
        }
    };
    insert(&mut parents, &buffer[..first]);
    while remaining != 0 {
        let size = remaining.min(buffer.len());
        if !receive_query_fragment(read(&mut buffer[..size])?, size, remaining) {
            return Ok(None);
        }
        insert(&mut parents, &buffer[..size]);
        // A single distinct prefix can precede runs of the same directory.
        // Reserve for the rest only after two fragments confirm distinct IDs.
        if remaining == id_bytes - first && parents.len() == sampled_bytes / FILE_ID_BYTES {
            parents.reserve((remaining - size) / FILE_ID_BYTES);
        }
        remaining -= size;
    }
    Ok(Some(DirectoryQuery { journal, parents }))
}

fn remaining_pipe_message_bytes(pipe: HANDLE) -> io::Result<usize> {
    let mut remaining = 0;
    if unsafe { PeekNamedPipe(pipe, null_mut(), 0, null_mut(), null_mut(), &mut remaining) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(remaining as usize)
}

fn receive_query_fragment(result: IoResult, size: usize, remaining: usize) -> bool {
    match result {
        IoResult::Completed(received) => size == remaining && received == size,
        IoResult::MoreData => size < remaining,
        IoResult::Disconnected | IoResult::Stopped => false,
    }
}

fn request_shape_is_valid(request: &Request<'_>) -> bool {
    match request.opcode {
        Opcode::Hello => {
            request.volume_guid.is_empty()
                && request.file_id_len == 0
                && request.previous_usn == 0
                && request.current_usn == 0
        }
        Opcode::ProbeVolume => {
            !request.volume_guid.is_empty()
                && request.file_id_len == 0
                && request.previous_usn == 0
                && request.current_usn == 0
        }
        Opcode::ReadChangeReasons => {
            !request.volume_guid.is_empty()
                && matches!(request.file_id_len, 8 | 16)
                && request.previous_usn > 0
                && request.current_usn > request.previous_usn
        }
        Opcode::ReadDirectoriesChanges => {
            !request.volume_guid.is_empty()
                && request.file_id_len == 0
                && request.previous_usn >= 0
                && request.current_usn > request.previous_usn
        }
    }
}

struct JournalDispatcher {
    volumes: Mutex<VolumeTable>,
    state_changed: OwnedHandle,
}

type SharedJournalReader = Arc<Mutex<JournalReader>>;
type VolumeEntries = HashMap<Arc<str>, (SharedJournalReader, Instant)>;

#[derive(Default)]
struct VolumeTable {
    entries: VolumeEntries,
    next_reap: Option<Instant>,
}

impl JournalDispatcher {
    fn new() -> io::Result<Self> {
        Ok(Self {
            volumes: Mutex::default(),
            state_changed: OwnedHandle::auto_reset_event()?,
        })
    }

    fn reap_idle(&self, now: Instant) -> io::Result<Option<Instant>> {
        let mut volumes = self
            .volumes
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        let VolumeTable { entries, next_reap } = &mut *volumes;
        if next_reap.is_none_or(|deadline| now < deadline) {
            return Ok(*next_reap);
        }
        let previous_len = entries.len();
        let mut next_deadline: Option<Instant> = None;
        entries.retain(|_, (_, deadline)| {
            if *deadline <= now {
                // An active borrower owns its reader independently. A valid
                // handle can be admitted again when that operation finishes.
                return false;
            }
            next_deadline = Some(next_deadline.map_or(*deadline, |next| next.min(*deadline)));
            true
        });
        if entries.len() != previous_len {
            trim_volume_table(entries);
        }
        *next_reap = next_deadline;
        Ok(next_deadline)
    }

    fn reader_for(&self, volume_guid: &str) -> io::Result<SharedJournalReader> {
        let mut normalized = [0; MAX_VOLUME_GUID_BYTES];
        let volume_guid = if let Some(bytes) = normalized.get_mut(..volume_guid.len()) {
            bytes.copy_from_slice(volume_guid.as_bytes());
            bytes.make_ascii_lowercase();
            std::str::from_utf8(bytes).expect("ASCII folding preserves UTF-8")
        } else {
            volume_guid
        };
        let volumes = self
            .volumes
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        if let Some((reader, _)) = volumes.entries.get(volume_guid) {
            return Ok(Arc::clone(reader));
        }
        drop(volumes);
        Ok(Arc::new(Mutex::new(JournalReader::new(
            volume_guid.into(),
        )?)))
    }

    fn update_cache(
        &self,
        key: &Arc<str>,
        reader: &SharedJournalReader,
        has_volume: bool,
        now: Instant,
    ) -> io::Result<()> {
        let mut volumes = self
            .volumes
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        let VolumeTable { entries, next_reap } = &mut *volumes;
        let deadline = now + VOLUME_CONTEXT_IDLE_TTL;
        if let Some((cached, previous_deadline)) = entries.get_mut(key) {
            // A concurrent first touch may have already admitted its reader.
            if !Arc::ptr_eq(cached, reader) {
                return Ok(());
            }
            if has_volume {
                *previous_deadline = deadline;
                return Ok(());
            }
            entries.remove(key);
            trim_volume_table(entries);
            if !entries.is_empty() {
                return Ok(());
            }
            *next_reap = None;
        } else if has_volume {
            if entries.len() >= MAX_VOLUME_CONTEXTS {
                let lru = entries
                    .iter()
                    .filter(|(_, (cached, _))| Arc::strong_count(cached) == 1)
                    .min_by_key(|(_, (_, deadline))| *deadline)
                    .map(|(key, _)| Arc::clone(key));
                let Some(lru) = lru else { return Ok(()) };
                entries.remove(&lru);
            }
            // Only a successfully opened volume can consume cache capacity.
            entries.insert(Arc::clone(key), (Arc::clone(reader), deadline));
            if next_reap.is_some_and(|scheduled| scheduled <= deadline) {
                return Ok(());
            }
            *next_reap = Some(deadline);
        } else {
            return Ok(());
        }
        drop(volumes);
        self.state_changed.signal();
        Ok(())
    }

    fn with_reader<T>(
        &self,
        volume_guid: &str,
        operation: impl FnOnce(&mut JournalReader) -> io::Result<T>,
    ) -> io::Result<T> {
        let reader = self.reader_for(volume_guid)?;
        let result = match reader.try_lock() {
            Ok(mut cached) => {
                let result = operation(&mut cached);
                // Read and publish handle state under the reader lock, so a
                // reopen on another request cannot race empty-entry removal.
                let has_volume = cached.has_open_volume();
                if result.is_ok() || !has_volume {
                    self.update_cache(cached.volume_guid(), &reader, has_volume, Instant::now())?;
                }
                result
            }
            // Synchronous operations on one volume handle serialize in
            // Windows. Use a separate handle for overlapping requests.
            Err(TryLockError::WouldBlock) => {
                JournalReader::new(volume_guid.into()).and_then(|mut reader| operation(&mut reader))
            }
            Err(TryLockError::Poisoned(_)) => Err(io::Error::other("journal state poisoned")),
        };
        result
    }
}

fn trim_volume_table(entries: &mut VolumeEntries) {
    if entries.is_empty() || entries.capacity() / 4 > entries.len() {
        entries.shrink_to_fit();
    }
}

fn handle_request(
    journals: &JournalDispatcher,
    request: Request<'_>,
    query: Option<DirectoryQuery>,
) -> (Response, Vec<u8>) {
    let mut response = Response::ok(request.request_id);
    let mut payload = Vec::new();
    let result: io::Result<(u64, i64, sunpack_usn_core::ChangeReasons)> = match request.opcode {
        Opcode::Hello => Ok((0, 0, Default::default())),
        Opcode::ProbeVolume => journals
            .with_reader(request.volume_guid, JournalReader::probe_volume)
            .map(|(journal_id, next_usn)| (journal_id, next_usn, Default::default())),
        Opcode::ReadChangeReasons => journals
            .with_reader(request.volume_guid, |journal| {
                journal.read_change_reasons(
                    &request.file_id,
                    request.file_id_len,
                    request.previous_usn,
                    request.current_usn,
                )
            })
            .map(|(journal_id, reasons)| (journal_id, 0, reasons)),
        Opcode::ReadDirectoriesChanges => {
            let DirectoryQuery { journal, parents } = query.expect("validated directory query");
            journals
                .with_reader(request.volume_guid, move |reader| {
                    reader.read_directories_changes(
                        journal,
                        &parents,
                        request.previous_usn,
                        request.current_usn,
                    )
                })
                .map(|page| {
                    payload = page.payload;
                    (
                        page.journal_id,
                        page.next_usn,
                        sunpack_usn_core::ChangeReasons {
                            all: payload.len() as u32,
                            without_close: page.count,
                        },
                    )
                })
        }
    };
    match result {
        Ok((journal_id, next_usn, reasons)) => {
            response.journal_id = journal_id;
            response.next_usn = next_usn;
            response.reasons_all = reasons.all;
            response.reasons_without_close = reasons.without_close;
        }
        Err(error) => {
            response.win32_error = error.raw_os_error().unwrap_or(0) as u32;
            response.status =
                if matches!(error.raw_os_error(), Some(1178) | Some(1179) | Some(1181)) {
                    Status::JournalReset
                } else if error.kind() == io::ErrorKind::InvalidInput {
                    Status::InvalidRequest
                } else if error.kind() == io::ErrorKind::NotFound {
                    Status::NotFound
                } else if error.raw_os_error().is_some() {
                    Status::JournalUnavailable
                } else if error.kind() == io::ErrorKind::Unsupported {
                    Status::ScanLimit
                } else {
                    Status::InternalError
                };
        }
    }
    (response, payload)
}

fn create_pipe(
    name: &[u16],
    descriptor: &SecurityDescriptor,
    first_instance: bool,
) -> io::Result<OwnedHandle> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let open_mode = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first_instance {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_CONNECTED_CLIENTS,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &attributes,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(pipe))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoResult {
    Completed(usize),
    MoreData,
    Stopped,
    Disconnected,
}

struct PipeListener {
    name: Vec<u16>,
    descriptor: SecurityDescriptor,
    pipe: Option<OwnedHandle>,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    pending: bool,
}

impl PipeListener {
    fn new(name: &str) -> io::Result<Self> {
        let event = OwnedHandle::event()?;
        let overlapped = Box::new(OVERLAPPED::default());
        let mut listener = Self {
            name: wide(name),
            descriptor: SecurityDescriptor::new(PIPE_SDDL)?,
            pipe: None,
            event,
            overlapped,
            pending: false,
        };
        listener.listen(true)?;
        Ok(listener)
    }

    fn is_listening(&self) -> bool {
        self.pipe.is_some()
    }

    fn listen(&mut self, first_instance: bool) -> io::Result<()> {
        debug_assert!(!self.is_listening());
        let pipe = create_pipe(&self.name, &self.descriptor, first_instance)?;
        self.listen_on(pipe)
    }

    fn listen_on(&mut self, pipe: OwnedHandle) -> io::Result<()> {
        if unsafe { ResetEvent(self.event.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        *self.overlapped = OVERLAPPED {
            hEvent: self.event.raw(),
            ..Default::default()
        };
        let pending = loop {
            if unsafe { ConnectNamedPipe(pipe.raw(), self.overlapped.as_mut()) } != 0 {
                break false;
            }
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => break false,
                ERROR_IO_PENDING => break true,
                ERROR_NO_DATA => {
                    if unsafe { DisconnectNamedPipe(pipe.raw()) } == 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                error => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        };
        // A client may connect before ConnectNamedPipe. Route that case
        // through the same wait as async completion, preserving stop priority.
        if !pending {
            self.event.signal();
        }
        self.pipe = Some(pipe);
        self.pending = pending;
        Ok(())
    }

    fn accept(&mut self) -> io::Result<OwnedHandle> {
        if self.pending {
            let mut transferred = 0u32;
            if unsafe {
                GetOverlappedResult(
                    self.pipe.as_ref().unwrap().raw(),
                    self.overlapped.as_mut(),
                    &mut transferred,
                    0,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            self.pending = false;
        }
        Ok(self.pipe.take().unwrap())
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        if self.pending {
            let pipe = self.pipe.as_ref().unwrap().raw();
            cancel_io(pipe, self.overlapped.as_mut());
        }
    }
}

fn read_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    io_event: HANDLE,
    buffer: &mut [u8],
) -> io::Result<IoResult> {
    pipe_io(pipe, stop_event, io_event, |overlapped| unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            null_mut(),
            overlapped,
        )
    })
}

fn write_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    io_event: HANDLE,
    buffer: &[u8],
) -> io::Result<IoResult> {
    pipe_io(pipe, stop_event, io_event, |overlapped| unsafe {
        WriteFile(
            pipe,
            buffer.as_ptr(),
            buffer.len() as u32,
            null_mut(),
            overlapped,
        )
    })
}

fn cancel_io(pipe: HANDLE, overlapped: &mut OVERLAPPED) {
    // CancelIoEx only requests cancellation. Keep the OVERLAPPED, event and
    // buffer alive until the kernel finishes accessing them.
    unsafe {
        CancelIoEx(pipe, overlapped);
        let mut transferred = 0;
        GetOverlappedResult(pipe, overlapped, &mut transferred, 1);
    }
}

fn pipe_io(
    pipe: HANDLE,
    stop_event: HANDLE,
    io_event: HANDLE,
    start: impl FnOnce(&mut OVERLAPPED) -> i32,
) -> io::Result<IoResult> {
    let mut overlapped = OVERLAPPED {
        hEvent: io_event,
        ..Default::default()
    };
    if start(&mut overlapped) == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return pipe_io_error(error);
        }
    }
    wait_io(pipe, stop_event, &mut overlapped)
}

fn wait_io(pipe: HANDLE, stop_event: HANDLE, overlapped: &mut OVERLAPPED) -> io::Result<IoResult> {
    let handles = [stop_event, overlapped.hEvent];
    let wait =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE) };
    if wait == WAIT_OBJECT_0 {
        cancel_io(pipe, overlapped);
        return Ok(IoResult::Stopped);
    }
    if wait != WAIT_OBJECT_0 + 1 {
        let error = io::Error::last_os_error();
        cancel_io(pipe, overlapped);
        return Err(error);
    }
    let mut transferred = 0u32;
    if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) } == 0 {
        return pipe_io_error(unsafe { GetLastError() });
    }
    Ok(IoResult::Completed(transferred as usize))
}

fn pipe_io_error(error: u32) -> io::Result<IoResult> {
    match error {
        ERROR_BROKEN_PIPE | ERROR_NO_DATA => Ok(IoResult::Disconnected),
        ERROR_MORE_DATA => Ok(IoResult::MoreData),
        _ => Err(io::Error::from_raw_os_error(error as i32)),
    }
}

struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    fn event() -> io::Result<Self> {
        let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn auto_reset_event() -> io::Result<Self> {
        let handle = unsafe { CreateEventW(null(), 0, 0, null()) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn signal(&self) {
        unsafe { SetEvent(self.0) };
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn new(sddl: &str) -> io::Result<Self> {
        let sddl = wide(sddl);
        let mut descriptor = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(descriptor))
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
#[path = "../tests/unit/main/tests.rs"]
mod tests;
