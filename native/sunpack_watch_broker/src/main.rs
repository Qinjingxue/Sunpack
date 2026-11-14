#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::collections::HashMap;
use std::ffi::{c_void, OsString};
use std::io;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use sunpack_usn_core::protocol::{
    Opcode, Request, Response, Status, FILE_ID_BYTES, MAX_DIRECTORY_QUERY_BYTES, REQUEST_BYTES,
    RESPONSE_BYTES,
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
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const PIPE_BUFFER_BYTES: u32 = 4096;
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
    let service_name = config.service_name.clone();
    CONFIG
        .set(config)
        .expect("Watch Broker configuration was initialized twice");
    service_dispatcher::start(service_name, ffi_service_main)
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
    let status_handle =
        service_control_handler::register(&broker_config().service_name, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let result = serve_watch_lifetimes(&stop_event);
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

fn serve_watch_lifetimes(stop_event: &OwnedHandle) -> io::Result<()> {
    let journals = &JournalDispatcher::new()?;
    let connected_clients = &AtomicUsize::new(0);
    let ever_had_lease = &AtomicBool::new(false);
    let state_changed = &journals.state_changed;
    let mut first_instance = true;
    let mut pending_accept: Option<PendingPipeAccept> = None;
    thread::scope(|workers| {
        let result = (|| {
            loop {
                let clients = connected_clients.load(Ordering::Acquire);
                let had_lease = ever_had_lease.load(Ordering::Acquire);
                // Before the first lease, only an explicit stop proves nobody will use us.
                if had_lease && clients == 0 {
                    break;
                }

                if clients < MAX_CONNECTED_CLIENTS as usize && pending_accept.is_none() {
                    pending_accept = Some(PendingPipeAccept::start(first_instance)?);
                }
                let timeout = journals
                    .reap_idle(Instant::now())?
                    .map_or(INFINITE, |deadline| {
                        // Wait accepts whole milliseconds. Round up to avoid waking
                        // repeatedly before the expiry can be observed.
                        (deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            + 1) as u32
                    });
                let wait = if let Some(accept) = pending_accept.as_ref() {
                    let handles = [stop_event.raw(), accept.event(), state_changed.raw()];
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
                    continue;
                }
                if pending_accept.is_some() && wait == WAIT_OBJECT_0 + 1 {
                    let pipe = pending_accept.take().unwrap().finish()?;
                    first_instance = false;
                    connected_clients.fetch_add(1, Ordering::AcqRel);
                    // Drop the join handle immediately. The scope still waits for
                    // clients on stop without retaining each finished OS handle.
                    thread::Builder::new().spawn_scoped(workers, move || {
                        let _ = serve_client(pipe, stop_event.raw(), journals, ever_had_lease);
                        connected_clients.fetch_sub(1, Ordering::AcqRel);
                        state_changed.signal();
                    })?;
                    continue;
                }
                let state_index = if pending_accept.is_some() { 2 } else { 1 };
                if wait != WAIT_OBJECT_0 + state_index {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        })();
        // Errors must wake blocked clients before the scope joins them.
        stop_event.signal();
        drop(pending_accept);
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
                IoResult::Stopped | IoResult::Disconnected => break,
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
                let mut query = Vec::new();
                if request.opcode == Opcode::ReadDirectoriesChanges {
                    let mut length = [0u8; 4];
                    match read_overlapped(pipe.raw(), stop_event, io_event.raw(), &mut length)? {
                        IoResult::Completed(4) => {}
                        _ => break,
                    }
                    let length = u32::from_le_bytes(length) as usize;
                    if !(8 + FILE_ID_BYTES..=MAX_DIRECTORY_QUERY_BYTES).contains(&length)
                        || (length - 8) % FILE_ID_BYTES != 0
                    {
                        break;
                    }
                    query.resize(length, 0);
                    match read_overlapped(pipe.raw(), stop_event, io_event.raw(), &mut query)? {
                        IoResult::Completed(size) if size == length => {}
                        _ => break,
                    }
                }
                handle_request(journals, request, &query)
            };
        let (response, payload) = response;
        match write_overlapped(pipe.raw(), stop_event, io_event.raw(), &response.encode())? {
            IoResult::Completed(size) if size == RESPONSE_BYTES => {}
            IoResult::Completed(_) | IoResult::Disconnected | IoResult::Stopped => break,
        }
        if !payload.is_empty() {
            match write_overlapped(pipe.raw(), stop_event, io_event.raw(), &payload)? {
                IoResult::Completed(size) if size == payload.len() => {}
                IoResult::Completed(_) | IoResult::Disconnected | IoResult::Stopped => break,
            }
        }
    }
    unsafe {
        DisconnectNamedPipe(pipe.raw());
    }
    Ok(())
}

fn request_shape_is_valid(request: &Request) -> bool {
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
                && request.previous_usn > 0
                && request.current_usn > request.previous_usn
        }
    }
}

struct JournalDispatcher {
    entries: Mutex<VolumeTable>,
    state_changed: OwnedHandle,
}

type SharedJournalReader = Arc<Mutex<JournalReader>>;
type VolumeTable = HashMap<Arc<str>, (SharedJournalReader, Instant)>;

impl JournalDispatcher {
    fn new() -> io::Result<Self> {
        Ok(Self {
            entries: Mutex::default(),
            state_changed: OwnedHandle::auto_reset_event()?,
        })
    }

    fn reap_idle(&self, now: Instant) -> io::Result<Option<Instant>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        let mut next_deadline: Option<Instant> = None;
        entries.retain(|_, (reader, deadline)| {
            if *deadline <= now {
                return Arc::strong_count(reader) > 1;
            }
            next_deadline = Some(next_deadline.map_or(*deadline, |next| next.min(*deadline)));
            true
        });
        Ok(next_deadline)
    }

    fn reader_for(
        &self,
        mut volume_guid: String,
        deadline: Instant,
    ) -> io::Result<SharedJournalReader> {
        volume_guid.make_ascii_lowercase();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        if let Some((reader, previous_deadline)) = entries.get_mut(volume_guid.as_str()) {
            *previous_deadline = (*previous_deadline).max(deadline);
            return Ok(Arc::clone(reader));
        }
        let key: Arc<str> = volume_guid.into();
        let reader = Arc::new(Mutex::new(JournalReader::new(Arc::clone(&key))?));
        if entries.len() >= MAX_VOLUME_CONTEXTS {
            let lru = entries
                .iter()
                .filter(|(_, (reader, _))| Arc::strong_count(reader) == 1)
                .min_by_key(|(_, (_, deadline))| *deadline)
                .map(|(key, _)| Arc::clone(key));
            if let Some(lru) = lru {
                entries.remove(&lru);
            } else {
                return Ok(reader);
            }
        }
        entries.insert(key, (Arc::clone(&reader), deadline));
        drop(entries);
        self.state_changed.signal();
        Ok(reader)
    }

    fn with_reader<T>(
        &self,
        volume_guid: String,
        operation: impl FnOnce(&mut JournalReader) -> io::Result<T>,
    ) -> io::Result<T> {
        let deadline = Instant::now() + VOLUME_CONTEXT_IDLE_TTL;
        let reader = self.reader_for(volume_guid, deadline)?;
        let result = reader
            .lock()
            .map_err(|_| io::Error::other("journal state poisoned"))
            .and_then(|mut reader| operation(&mut reader));
        drop(reader);
        // An expired entry can stay pinned by a slow journal operation. Wake
        // the accept loop after releasing the pin so it can reap without polling.
        if Instant::now() >= deadline {
            self.state_changed.signal();
        }
        result
    }
}

fn handle_request(
    journals: &JournalDispatcher,
    request: Request,
    query: &[u8],
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
            // serve_client validates the query frame before reading these bytes.
            let expected = u64::from_le_bytes(query[..8].try_into().unwrap());
            let (ids, _) = query[8..].as_chunks::<FILE_ID_BYTES>();
            journals
                .with_reader(request.volume_guid, |journal| {
                    journal.read_directories_changes(
                        expected,
                        ids,
                        request.previous_usn,
                        request.current_usn,
                    )
                })
                .map(|page| {
                    let count = page.changes.len() as u32;
                    payload = Vec::with_capacity(page.payload_bytes);
                    for (index, name) in page.changes {
                        payload.extend_from_slice(&index.to_le_bytes());
                        payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
                        payload.extend_from_slice(name.as_bytes());
                    }
                    debug_assert_eq!(payload.len(), page.payload_bytes);
                    (
                        page.journal_id,
                        page.next_usn,
                        sunpack_usn_core::ChangeReasons {
                            all: payload.len() as u32,
                            without_close: count,
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
                } else if error.to_string().contains("fallback scan") {
                    Status::ScanLimit
                } else if error.raw_os_error().is_some() {
                    Status::JournalUnavailable
                } else {
                    Status::InternalError
                };
        }
    }
    (response, payload)
}

fn create_pipe(first_instance: bool) -> io::Result<OwnedHandle> {
    let descriptor = SecurityDescriptor::new(PIPE_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.raw(),
        bInheritHandle: 0,
    };
    let name = wide(&broker_config().pipe_name);
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
    Stopped,
    Disconnected,
}

struct PendingPipeAccept {
    pipe: Option<OwnedHandle>,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    pending: bool,
}

impl PendingPipeAccept {
    fn start(first_instance: bool) -> io::Result<Self> {
        let pipe = create_pipe(first_instance)?;
        let event = OwnedHandle::event()?;
        let mut overlapped = Box::new(unsafe { std::mem::zeroed::<OVERLAPPED>() });
        overlapped.hEvent = event.raw();
        let connected = unsafe { ConnectNamedPipe(pipe.raw(), overlapped.as_mut()) };
        let pending = if connected != 0 {
            false
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_PIPE_CONNECTED {
                false
            } else if error == ERROR_IO_PENDING {
                true
            } else {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        };
        // A client may connect before ConnectNamedPipe. Route that case
        // through the same wait as async completion, preserving stop priority.
        if !pending {
            event.signal();
        }
        Ok(Self {
            pipe: Some(pipe),
            event,
            overlapped,
            pending,
        })
    }

    fn event(&self) -> HANDLE {
        self.event.raw()
    }

    fn finish(mut self) -> io::Result<OwnedHandle> {
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

    fn cancel(&mut self) {
        if !self.pending {
            return;
        }
        let pipe = self.pipe.as_ref().unwrap().raw();
        cancel_io(pipe, self.overlapped.as_mut());
        self.pending = false;
    }
}

impl Drop for PendingPipeAccept {
    fn drop(&mut self) {
        self.cancel();
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
        ERROR_MORE_DATA => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker pipe message exceeds frame size",
        )),
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

    fn raw(&self) -> *mut c_void {
        self.0
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
mod tests {
    use super::*;

    #[test]
    fn lifetime_waits_for_first_lease_and_exits_on_stop_or_last_client() {
        // The shape/dispatcher tests never run the accept loop. This single
        // real-pipe test covers initial standby, stop, overlapping short leases
        // and a connected client without a lease, including the old 5s/1s exits.
        use std::io::{Read, Write};
        use std::sync::mpsc::{self, RecvTimeoutError};

        let name = format!(
            r"\\.\pipe\SunPack.WatchBroker.Test.lifetime.{}",
            std::process::id()
        );
        CONFIG
            .set(BrokerConfig {
                service_name: "SunPackWatchBrokerTest_lifetime".to_owned(),
                pipe_name: name.clone(),
            })
            .unwrap();

        struct Server {
            stop: Arc<OwnedHandle>,
            thread: Option<thread::JoinHandle<io::Result<()>>>,
            done: mpsc::Receiver<()>,
        }
        impl Server {
            fn start() -> Self {
                let stop = Arc::new(OwnedHandle::event().unwrap());
                let worker_stop = Arc::clone(&stop);
                let (tx, done) = mpsc::channel();
                let thread = thread::spawn(move || {
                    let result = serve_watch_lifetimes(&worker_stop);
                    let _ = tx.send(());
                    result
                });
                Self {
                    stop,
                    thread: Some(thread),
                    done,
                }
            }
        }
        impl Drop for Server {
            fn drop(&mut self) {
                self.stop.signal();
                assert!(self.thread.take().unwrap().join().unwrap().is_ok());
            }
        }
        fn connect(name: &str) -> std::fs::File {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(name)
                {
                    Ok(pipe) => return pipe,
                    Err(error)
                        if matches!(error.raw_os_error(), Some(2 | 231))
                            && Instant::now() < deadline =>
                    {
                        thread::yield_now()
                    }
                    Err(error) => panic!("test pipe connection failed: {error}"),
                }
            }
        }
        fn request(pipe: &mut std::fs::File, opcode: Opcode) {
            pipe.write_all(&Request::simple(opcode, 1).encode().unwrap())
                .unwrap();
            let mut response = [0; RESPONSE_BYTES];
            pipe.read_exact(&mut response).unwrap();
            assert_eq!(Response::decode(&response).unwrap().status, Status::Ok);
        }

        {
            let server = Server::start();
            assert_eq!(
                server.done.recv_timeout(Duration::from_millis(5_100)),
                Err(RecvTimeoutError::Timeout)
            );
            server.stop.signal();
            server.done.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        let server = Server::start();
        let mut owner = connect(&name);
        request(&mut owner, Opcode::Hello);
        for _ in 0..16 {
            let mut next = connect(&name);
            request(&mut next, Opcode::Hello);
            owner = next;
        }
        let mut unleased = connect(&name);
        // A valid probe before Hello confirms the connection is accepted and
        // cannot run journal commands without a lease.
        let mut probe = Request::simple(Opcode::ProbeVolume, 2);
        probe.volume_guid = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}".to_owned();
        unleased
            .write_all(&probe.encode().unwrap())
            .unwrap();
        let mut response = [0; RESPONSE_BYTES];
        unleased.read_exact(&mut response).unwrap();
        assert_eq!(
            Response::decode(&response).unwrap().status,
            Status::InvalidRequest
        );
        drop(owner);
        assert_eq!(
            server.done.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        );
        request(&mut unleased, Opcode::Hello);
        drop(unleased);
        server
            .done
            .recv_timeout(Duration::from_millis(500))
            .unwrap();
        drop(server);

        // Stop must drain clients blocked in a read before releasing events.
        let server = Server::start();
        let mut owner = connect(&name);
        request(&mut owner, Opcode::Hello);
        server.stop.signal();
        server.done.recv_timeout(Duration::from_secs(3)).unwrap();
        match owner.read(&mut [0u8; 1]) {
            Ok(size) => assert_eq!(size, 0),
            Err(error) => assert!(matches!(error.raw_os_error(), Some(109 | 233))),
        }
        drop(owner);
        drop(server);

        // A wait failure must cancel too, and neither exit may leave kernel IO
        // pointing into caller-owned storage. Existing request tests only
        // cover successful IO and cannot detect this pending-operation leak.
        for failed_wait in [true, false] {
            let accept = PendingPipeAccept::start(true).unwrap();
            let _client = connect(&name);
            assert_eq!(
                unsafe {
                    windows_sys::Win32::System::Threading::WaitForSingleObject(accept.event(), 3000)
                },
                WAIT_OBJECT_0
            );
            let pipe = accept.finish().unwrap();
            let stop = OwnedHandle::event().unwrap();
            stop.signal();
            let event = OwnedHandle::event().unwrap();
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = event.raw();
            let mut buffer = [0u8; 1];
            assert_eq!(
                unsafe {
                    ReadFile(
                        pipe.raw(),
                        buffer.as_mut_ptr(),
                        1,
                        null_mut(),
                        &mut overlapped,
                    )
                },
                0
            );
            assert_eq!(unsafe { GetLastError() }, ERROR_IO_PENDING);
            let result = wait_io(
                pipe.raw(),
                if failed_wait { null_mut() } else { stop.raw() },
                &mut overlapped,
            );
            let mut transferred = 0;
            let completed =
                unsafe { GetOverlappedResult(pipe.raw(), &mut overlapped, &mut transferred, 0) };
            let error = unsafe { GetLastError() };
            // Keep the test memory safe even when the regression is present.
            cancel_io(pipe.raw(), &mut overlapped);
            assert_eq!(completed, 0);
            assert_eq!(
                error,
                windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED
            );
            if failed_wait {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(6));
            } else {
                assert_eq!(result.unwrap(), IoResult::Stopped);
            }
        }
    }

    #[test]
    fn broker_identity_defaults_to_production_names() {
        let config = BrokerConfig::from_args(std::iter::empty());
        assert_eq!(config.service_name, SERVICE_NAME);
        assert_eq!(config.pipe_name, PIPE_NAME);
    }

    #[test]
    fn broker_identity_can_be_isolated_for_tests() {
        let config = BrokerConfig::from_args(
            [
                "--service-name",
                "SunPackWatchBrokerTest_example",
                "--pipe-name",
                r"\\.\pipe\SunPack.WatchBroker.Test.example",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert_eq!(config.service_name, "SunPackWatchBrokerTest_example");
        assert_eq!(
            config.pipe_name,
            r"\\.\pipe\SunPack.WatchBroker.Test.example"
        );
    }

    #[test]
    fn only_minimal_shapes_are_accepted_for_non_journal_operations() {
        assert!(request_shape_is_valid(&Request::simple(Opcode::Hello, 1)));
        let mut invalid = Request::simple(Opcode::Hello, 2);
        invalid.volume_guid = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}".to_owned();
        assert!(!request_shape_is_valid(&invalid));
    }

    #[test]
    fn journal_read_requires_a_bounded_usn_interval_and_file_identity() {
        let mut request = Request::simple(Opcode::ReadChangeReasons, 1);
        request.volume_guid = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}".to_owned();
        request.file_id_len = 8;
        request.previous_usn = 100;
        request.current_usn = 101;
        assert!(request_shape_is_valid(&request));
        request.current_usn = 100;
        assert!(!request_shape_is_valid(&request));
    }

    #[test]
    fn dispatcher_serializes_per_volume_but_keeps_volumes_independent() {
        let dispatcher = JournalDispatcher::new().unwrap();
        let deadline = Instant::now() + VOLUME_CONTEXT_IDLE_TTL;
        let first = dispatcher
            .reader_for(
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}".to_owned(),
                deadline,
            )
            .unwrap();
        let same = dispatcher
            .reader_for(
                r"\\?\VOLUME{01234567-89AB-CDEF-0123-456789ABCDEF}".to_owned(),
                deadline,
            )
            .unwrap();
        let other = dispatcher
            .reader_for(
                r"\\?\Volume{fedcba98-7654-3210-fedc-ba9876543210}".to_owned(),
                deadline,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));
    }

    #[test]
    fn dispatcher_schedules_expiry_and_preserves_in_use_readers() {
        let dispatcher = JournalDispatcher::new().unwrap();
        let now = Instant::now();
        let deadline = now + VOLUME_CONTEXT_IDLE_TTL;
        let reader = dispatcher
            .reader_for(
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}".to_owned(),
                deadline,
            )
            .unwrap();
        assert_eq!(dispatcher.reap_idle(now).unwrap(), Some(deadline));
        assert_eq!(dispatcher.reap_idle(deadline).unwrap(), None);
        assert_eq!(dispatcher.entries.lock().unwrap().len(), 1);
        drop(reader);
        assert_eq!(dispatcher.reap_idle(deadline).unwrap(), None);
        assert!(dispatcher.entries.lock().unwrap().is_empty());
    }
}
