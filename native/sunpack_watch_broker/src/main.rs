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
    Opcode, Request, Response, Status, REQUEST_BYTES, RESPONSE_BYTES,
};
use sunpack_usn_core::{validate_volume_guid, JournalReader, PIPE_NAME, SERVICE_NAME};
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
    CreateEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const PIPE_BUFFER_BYTES: u32 = 4096;
const MAX_CONNECTED_CLIENTS: u32 = 64;
const CLIENT_CONNECT_TIMEOUT_MS: u32 = 5_000;
const LAST_CLIENT_DEBOUNCE: Duration = Duration::from_secs(1);
const MAX_VOLUME_CONTEXTS: usize = 64;
const VOLUME_CONTEXT_IDLE_TTL: Duration = Duration::from_secs(60);
const BROKER_IDLE_SWEEP: Duration = Duration::from_secs(60);
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

    let result = serve_watch_lifetimes(stop_event.raw());
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

fn serve_watch_lifetimes(stop_event: HANDLE) -> io::Result<()> {
    let started = Instant::now();
    let journals = Arc::new(JournalDispatcher::default());
    let active_leases = Arc::new(AtomicUsize::new(0));
    let connected_clients = Arc::new(AtomicUsize::new(0));
    let ever_had_lease = Arc::new(AtomicBool::new(false));
    let state_changed = OwnedHandle::auto_reset_event()?;
    let mut workers = Vec::new();
    let mut first_instance = true;
    let mut idle_since = None;
    let mut pending_accept: Option<PendingPipeAccept> = None;
    loop {
        workers.retain(|worker: &thread::JoinHandle<()>| !worker.is_finished());
        let leases = active_leases.load(Ordering::Acquire);
        let clients = connected_clients.load(Ordering::Acquire);
        let had_lease = ever_had_lease.load(Ordering::Acquire);
        if leases > 0 {
            idle_since = None;
        } else if had_lease && clients == 0 {
            let since = idle_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= LAST_CLIENT_DEBOUNCE {
                break;
            }
        } else if !had_lease
            && clients == 0
            && started.elapsed() >= Duration::from_millis(CLIENT_CONNECT_TIMEOUT_MS as u64)
        {
            break;
        }

        if clients < MAX_CONNECTED_CLIENTS as usize && pending_accept.is_none() {
            pending_accept = Some(PendingPipeAccept::start(first_instance)?);
        }
        if pending_accept
            .as_ref()
            .is_some_and(PendingPipeAccept::completed_synchronously)
        {
            let pipe = pending_accept.take().unwrap().finish()?;
            first_instance = false;
            connected_clients.fetch_add(1, Ordering::AcqRel);
            let worker_journals = Arc::clone(&journals);
            let worker_leases = Arc::clone(&active_leases);
            let worker_clients = Arc::clone(&connected_clients);
            let worker_ever_had_lease = Arc::clone(&ever_had_lease);
            let worker_stop_event = stop_event as isize;
            let worker_state_changed = state_changed.raw() as isize;
            workers.push(thread::spawn(move || {
                let _ = serve_client(
                    pipe,
                    worker_stop_event as HANDLE,
                    worker_state_changed as HANDLE,
                    worker_journals,
                    &worker_leases,
                    &worker_ever_had_lease,
                );
                worker_clients.fetch_sub(1, Ordering::AcqRel);
                unsafe { SetEvent(worker_state_changed as HANDLE) };
            }));
            continue;
        }

        let idle_deadline = if clients != 0 || leases != 0 {
            None
        } else if had_lease {
            idle_since.map(|since| since + LAST_CLIENT_DEBOUNCE)
        } else {
            Some(started + Duration::from_millis(CLIENT_CONNECT_TIMEOUT_MS as u64))
        };
        let timeout_ms = deadline_timeout_ms(idle_deadline);
        let wait = if let Some(accept) = pending_accept.as_ref() {
            let handles = [stop_event, accept.event(), state_changed.raw()];
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms) }
        } else {
            let handles = [stop_event, state_changed.raw()];
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms) }
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
            let worker_journals = Arc::clone(&journals);
            let worker_leases = Arc::clone(&active_leases);
            let worker_clients = Arc::clone(&connected_clients);
            let worker_ever_had_lease = Arc::clone(&ever_had_lease);
            let worker_stop_event = stop_event as isize;
            let worker_state_changed = state_changed.raw() as isize;
            workers.push(thread::spawn(move || {
                let _ = serve_client(
                    pipe,
                    worker_stop_event as HANDLE,
                    worker_state_changed as HANDLE,
                    worker_journals,
                    &worker_leases,
                    &worker_ever_had_lease,
                );
                worker_clients.fetch_sub(1, Ordering::AcqRel);
                unsafe { SetEvent(worker_state_changed as HANDLE) };
            }));
            continue;
        }
        let state_index = if pending_accept.is_some() { 2 } else { 1 };
        if wait != WAIT_OBJECT_0 + state_index {
            return Err(io::Error::last_os_error());
        }
    }
    drop(pending_accept);
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn serve_client(
    pipe: OwnedHandle,
    stop_event: HANDLE,
    state_changed: HANDLE,
    journals: Arc<JournalDispatcher>,
    active_leases: &AtomicUsize,
    ever_had_lease: &AtomicBool,
) -> io::Result<()> {
    let mut lease = LeaseGuard::new(active_leases, ever_had_lease, state_changed);
    loop {
        let mut request_bytes = [0u8; REQUEST_BYTES];
        let read_timeout = if lease.active {
            BROKER_IDLE_SWEEP.as_millis() as u32
        } else {
            CLIENT_CONNECT_TIMEOUT_MS
        };
        match read_overlapped(pipe.raw(), stop_event, &mut request_bytes, read_timeout)? {
            IoResult::Stopped | IoResult::Disconnected => break,
            IoResult::TimedOut if lease.active => {
                journals.reap_idle()?;
                continue;
            }
            IoResult::TimedOut => break,
            IoResult::Completed(size) if size == REQUEST_BYTES => {}
            IoResult::Completed(_) => {
                let response = Response {
                    status: Status::InvalidRequest,
                    ..Response::ok(0)
                };
                let _ = write_overlapped(pipe.raw(), stop_event, &response.encode());
                break;
            }
        }

        let request = match Request::decode(&request_bytes) {
            Ok(request) => request,
            Err(error) => {
                let response = Response {
                    status: if error.kind() == io::ErrorKind::Unsupported {
                        Status::VersionMismatch
                    } else {
                        Status::InvalidRequest
                    },
                    ..Response::ok(0)
                };
                let _ = write_overlapped(pipe.raw(), stop_event, &response.encode());
                break;
            }
        };
        let release = request.opcode == Opcode::Release;
        let response = if !request_shape_is_valid(&request)
            || (request.opcode != Opcode::Hello && !lease.active)
        {
            Response {
                status: Status::InvalidRequest,
                ..Response::ok(request.request_id)
            }
        } else {
            if request.opcode == Opcode::Hello {
                lease.acquire();
            }
            handle_request(&journals, request)
        };
        match write_overlapped(pipe.raw(), stop_event, &response.encode())? {
            IoResult::Completed(size) if size == RESPONSE_BYTES => {}
            IoResult::Completed(_)
            | IoResult::Disconnected
            | IoResult::Stopped
            | IoResult::TimedOut => break,
        }
        if release {
            break;
        }
    }
    unsafe {
        DisconnectNamedPipe(pipe.raw());
    }
    Ok(())
}

fn request_shape_is_valid(request: &Request) -> bool {
    match request.opcode {
        Opcode::Hello | Opcode::Ping | Opcode::Release => {
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
    }
}

struct LeaseGuard<'a> {
    counter: &'a AtomicUsize,
    ever_had_lease: &'a AtomicBool,
    state_changed: HANDLE,
    active: bool,
}

impl<'a> LeaseGuard<'a> {
    fn new(
        counter: &'a AtomicUsize,
        ever_had_lease: &'a AtomicBool,
        state_changed: HANDLE,
    ) -> Self {
        Self {
            counter,
            ever_had_lease,
            state_changed,
            active: false,
        }
    }

    fn acquire(&mut self) {
        if !self.active {
            self.ever_had_lease.store(true, Ordering::Release);
            self.counter.fetch_add(1, Ordering::AcqRel);
            self.active = true;
            unsafe { SetEvent(self.state_changed) };
        }
    }
}

impl Drop for LeaseGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.counter.fetch_sub(1, Ordering::AcqRel);
            unsafe { SetEvent(self.state_changed) };
        }
    }
}

#[derive(Default)]
struct JournalDispatcher {
    entries: Mutex<VolumeTable>,
}

type SharedJournalReader = Arc<Mutex<JournalReader>>;
type VolumeTable = HashMap<String, (SharedJournalReader, Instant)>;

impl JournalDispatcher {
    fn reap_idle(&self) -> io::Result<()> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        Self::reap_idle_locked(&mut entries, now);
        Ok(())
    }

    fn reap_idle_locked(entries: &mut VolumeTable, now: Instant) {
        entries.retain(|_, (reader, last_used)| {
            Arc::strong_count(reader) > 1
                || now.saturating_duration_since(*last_used) < VOLUME_CONTEXT_IDLE_TTL
        });
    }

    fn reader_for(&self, volume_guid: &str) -> io::Result<Arc<Mutex<JournalReader>>> {
        validate_volume_guid(volume_guid)?;
        let key = volume_guid.to_ascii_lowercase();
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("volume table poisoned"))?;
        Self::reap_idle_locked(&mut entries, now);
        if let Some((reader, last_used)) = entries.get_mut(&key) {
            *last_used = now;
            return Ok(Arc::clone(reader));
        }
        if entries.len() >= MAX_VOLUME_CONTEXTS {
            let lru = entries
                .iter()
                .filter(|(_, (reader, _))| Arc::strong_count(reader) == 1)
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(key, _)| key.clone())
                .ok_or_else(|| io::Error::other("all broker volume contexts are currently busy"))?;
            entries.remove(&lru);
        }
        let reader = Arc::new(Mutex::new(JournalReader::new()));
        entries.insert(key, (Arc::clone(&reader), now));
        Ok(reader)
    }
}

fn handle_request(journals: &JournalDispatcher, request: Request) -> Response {
    let mut response = Response::ok(request.request_id);
    let result = match request.opcode {
        Opcode::Hello | Opcode::Ping | Opcode::Release => Ok((0, Default::default())),
        Opcode::ProbeVolume => journals
            .reader_for(&request.volume_guid)
            .and_then(|journal| {
                journal
                    .lock()
                    .map_err(|_| io::Error::other("journal state poisoned"))?
                    .probe_volume(&request.volume_guid)
            })
            .map(|journal_id| (journal_id, Default::default())),
        Opcode::ReadChangeReasons => {
            journals
                .reader_for(&request.volume_guid)
                .and_then(|journal| {
                    journal
                        .lock()
                        .map_err(|_| io::Error::other("journal state poisoned"))?
                        .read_change_reasons(
                            &request.volume_guid,
                            &request.file_id,
                            request.file_id_len,
                            request.previous_usn,
                            request.current_usn,
                        )
                })
        }
    };
    match result {
        Ok((journal_id, reasons)) => {
            response.journal_id = journal_id;
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
                } else if error.to_string().contains("scan budget") {
                    Status::ScanLimit
                } else if error.raw_os_error().is_some() {
                    Status::JournalUnavailable
                } else {
                    Status::InternalError
                };
        }
    }
    response
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
enum WaitResult {
    Completed,
    Stopped,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoResult {
    Completed(usize),
    Stopped,
    Disconnected,
    TimedOut,
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
        Ok(Self {
            pipe: Some(pipe),
            event,
            overlapped,
            pending,
        })
    }

    fn completed_synchronously(&self) -> bool {
        !self.pending
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
        unsafe {
            CancelIoEx(pipe, self.overlapped.as_mut());
            WaitForSingleObject(self.event.raw(), INFINITE);
        }
        let mut transferred = 0u32;
        unsafe {
            GetOverlappedResult(pipe, self.overlapped.as_mut(), &mut transferred, 0);
        }
        self.pending = false;
    }
}

impl Drop for PendingPipeAccept {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn deadline_timeout_ms(deadline: Option<Instant>) -> u32 {
    let Some(deadline) = deadline else {
        return INFINITE;
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return 0;
    }
    let milliseconds = remaining.as_millis().saturating_add(1);
    milliseconds.min((INFINITE - 1) as u128) as u32
}

fn read_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    buffer: &mut [u8],
    timeout_ms: u32,
) -> io::Result<IoResult> {
    let event = OwnedHandle::event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.raw();
    let ok = unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            null_mut(),
            &mut overlapped,
        )
    };
    if ok == 0 {
        let error = unsafe { GetLastError() };
        if matches!(error, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
            return Ok(IoResult::Disconnected);
        }
        if error != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
    }
    let (wait, bytes) = wait_io(pipe, stop_event, event.raw(), &mut overlapped, timeout_ms)?;
    match wait {
        WaitResult::Completed => Ok(IoResult::Completed(bytes as usize)),
        WaitResult::Stopped => Ok(IoResult::Stopped),
        WaitResult::TimedOut => Ok(IoResult::TimedOut),
    }
}

fn write_overlapped(pipe: HANDLE, stop_event: HANDLE, buffer: &[u8]) -> io::Result<IoResult> {
    let event = OwnedHandle::event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.raw();
    let ok = unsafe {
        WriteFile(
            pipe,
            buffer.as_ptr(),
            buffer.len() as u32,
            null_mut(),
            &mut overlapped,
        )
    };
    if ok == 0 {
        let error = unsafe { GetLastError() };
        if matches!(error, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
            return Ok(IoResult::Disconnected);
        }
        if error != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
    }
    let (wait, bytes) = wait_io(pipe, stop_event, event.raw(), &mut overlapped, INFINITE)?;
    match wait {
        WaitResult::Completed => Ok(IoResult::Completed(bytes as usize)),
        WaitResult::Stopped => Ok(IoResult::Stopped),
        WaitResult::TimedOut => Ok(IoResult::TimedOut),
    }
}

fn wait_io(
    pipe: HANDLE,
    stop_event: HANDLE,
    io_event: HANDLE,
    overlapped: &mut OVERLAPPED,
    timeout_ms: u32,
) -> io::Result<(WaitResult, u32)> {
    let handles = [stop_event, io_event];
    let wait =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms) };
    if wait == WAIT_OBJECT_0 {
        unsafe { CancelIoEx(pipe, overlapped) };
        return Ok((WaitResult::Stopped, 0));
    }
    if wait == WAIT_TIMEOUT {
        unsafe { CancelIoEx(pipe, overlapped) };
        return Ok((WaitResult::TimedOut, 0));
    }
    if wait != WAIT_OBJECT_0 + 1 {
        return Err(io::Error::last_os_error());
    }
    let mut transferred = 0u32;
    if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) } == 0 {
        let error = unsafe { GetLastError() };
        if matches!(error, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
            return Ok((WaitResult::Completed, 0));
        }
        if error == ERROR_MORE_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broker pipe message exceeds frame size",
            ));
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok((WaitResult::Completed, transferred))
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
        let mut invalid = Request::simple(Opcode::Ping, 2);
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
        let dispatcher = JournalDispatcher::default();
        let first = dispatcher
            .reader_for(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}")
            .unwrap();
        let same = dispatcher
            .reader_for(r"\\?\VOLUME{01234567-89AB-CDEF-0123-456789ABCDEF}")
            .unwrap();
        let other = dispatcher
            .reader_for(r"\\?\Volume{fedcba98-7654-3210-fedc-ba9876543210}")
            .unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));
    }

    #[test]
    fn dispatcher_reaps_idle_volume_without_a_new_request() {
        let dispatcher = JournalDispatcher::default();
        let reader = dispatcher
            .reader_for(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}")
            .unwrap();
        drop(reader);
        {
            let mut entries = dispatcher.entries.lock().unwrap();
            let (_, last_used) = entries
                .get_mut(r"\\?\volume{01234567-89ab-cdef-0123-456789abcdef}")
                .unwrap();
            *last_used = Instant::now() - VOLUME_CONTEXT_IDLE_TTL - Duration::from_secs(1);
        }
        dispatcher.reap_idle().unwrap();
        assert!(dispatcher.entries.lock().unwrap().is_empty());
    }
}
