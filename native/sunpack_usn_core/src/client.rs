use crate::protocol::{
    Opcode, Request, Response, Status, FILE_ID_BYTES, MAX_DIRECTORY_QUERY_BYTES,
    MAX_DIRECTORY_RESPONSE_BYTES, RESPONSE_BYTES,
};
use crate::{
    ChangeReasons, PIPE_NAME, PIPE_NAME_ENV, SERVICE_NAME, SERVICE_NAME_ENV, TEST_PIPE_NAME_PREFIX,
    TEST_SERVICE_NAME_PREFIX,
};
use std::env;
use std::io;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_SEM_TIMEOUT, ERROR_SERVICE_ALREADY_RUNNING, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{
    SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_MESSAGE,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, NotifyServiceStatusChangeW, OpenSCManagerW, OpenServiceW,
    QueryServiceStatusEx, StartServiceW, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING,
    SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED, SERVICE_NOTIFY_STOP_PENDING,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

static REQUEST_IDS: AtomicU64 = AtomicU64::new(1);
static STATE: OnceLock<Mutex<ClientState>> = OnceLock::new();

#[derive(Default)]
struct ClientState {
    connection: Option<BrokerConnection>,
    leases: usize,
}

struct BrokerConnection(HANDLE);

unsafe impl Send for BrokerConnection {}

impl Drop for BrokerConnection {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl BrokerConnection {
    fn transact(
        &mut self,
        request: &Request,
        query: &[u8],
        payload: &mut Vec<u8>,
    ) -> io::Result<Response> {
        let request_id = request.request_id;
        let payload_response = request.opcode == Opcode::ReadDirectoriesChanges;
        let request = request.encode()?;
        write_exact(self.0, &request)?;
        if !query.is_empty() {
            write_exact(self.0, &(query.len() as u32).to_le_bytes())?;
            write_exact(self.0, query)?;
        }
        let mut response_bytes = [0u8; RESPONSE_BYTES];
        read_exact(self.0, &mut response_bytes)?;
        let response = Response::decode(&response_bytes)?;
        if response.request_id != request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broker response request ID mismatch",
            ));
        }
        let payload_len = if payload_response && response.status == Status::Ok {
            response.reasons_all as usize
        } else {
            0
        };
        if payload_len > MAX_DIRECTORY_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broker payload exceeds limit",
            ));
        }
        payload.resize(payload_len, 0);
        if payload_len > 0 {
            read_exact(self.0, payload)?;
        }
        Ok(response)
    }
}

pub fn broker_acquire() -> io::Result<()> {
    let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("broker client state poisoned"))?;
    if state.connection.is_none() {
        state.connection = Some(connect_and_hello()?);
    }
    state.leases += 1;
    Ok(())
}

pub fn broker_release() -> io::Result<()> {
    let Some(state) = STATE.get() else {
        return Ok(());
    };
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("broker client state poisoned"))?;
    if state.leases == 0 {
        return Ok(());
    }
    state.leases -= 1;
    if state.leases == 0 {
        // Disconnecting ends the server-side lease, including on process exit.
        state.connection = None;
    }
    Ok(())
}

pub fn broker_probe_volume(volume_guid: &str) -> io::Result<()> {
    broker_volume_cursor(volume_guid).map(|_| ())
}

pub fn broker_volume_cursor(volume_guid: &str) -> io::Result<(u64, i64)> {
    let mut request = Request::simple(Opcode::ProbeVolume, next_request_id());
    request.volume_guid = volume_guid.to_owned();
    let response = transact_request(&request, &[], &mut Vec::new())?;
    Ok((response.journal_id, response.next_usn))
}

pub fn broker_read_change_reasons(
    volume_guid: &str,
    file_id: [u8; FILE_ID_BYTES],
    file_id_len: u8,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<ChangeReasons> {
    let mut request = Request::simple(Opcode::ReadChangeReasons, next_request_id());
    request.volume_guid = volume_guid.to_owned();
    request.file_id = file_id;
    request.file_id_len = file_id_len;
    request.previous_usn = previous_usn;
    request.current_usn = current_usn;
    let response = transact_request(&request, &[], &mut Vec::new())?;
    Ok(ChangeReasons {
        all: response.reasons_all,
        without_close: response.reasons_without_close,
    })
}

pub fn broker_for_each_directory_change(
    volume: &str,
    journal: u64,
    directories: &[[u8; FILE_ID_BYTES]],
    start: i64,
    end: i64,
    mut observe: impl FnMut(usize, &str) -> io::Result<()>,
) -> io::Result<()> {
    if directories.is_empty() || start <= 0 || end <= start {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid directory recovery query",
        ));
    }
    let batch_ids = (MAX_DIRECTORY_QUERY_BYTES - 8) / FILE_ID_BYTES;
    // Only the ID and cursor change between pages of this logical query.
    let mut request = Request::simple(Opcode::ReadDirectoriesChanges, 0);
    request.volume_guid = volume.to_owned();
    request.current_usn = end;
    let mut query = Vec::with_capacity(8 + directories.len().min(batch_ids) * FILE_ID_BYTES);
    let mut payload = Vec::new();
    for (batch, ids) in directories.chunks(batch_ids).enumerate() {
        query.clear();
        query.extend_from_slice(&journal.to_le_bytes());
        query.extend_from_slice(ids.as_flattened());
        let mut cursor = start;
        while cursor < end {
            request.request_id = next_request_id();
            request.previous_usn = cursor;
            // The pipe is unlocked after each complete frame. Parsing and
            // applying the page can proceed alongside other broker requests.
            let response = transact_request(&request, &query, &mut payload)?;
            if response.journal_id != journal
                || response.next_usn <= cursor
                || response.next_usn > end
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid directory recovery cursor",
                ));
            }
            let mut input = payload.as_slice();
            let mut count = 0usize;
            while !input.is_empty() {
                if input.len() < 8 {
                    return Err(io::Error::other("truncated directory change"));
                }
                let index = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
                let length = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;
                input = &input[8..];
                if index >= ids.len() || length > input.len() {
                    return Err(io::Error::other("invalid directory change"));
                }
                let name = std::str::from_utf8(&input[..length])
                    .map_err(|_| io::Error::other("invalid directory change UTF-8"))?;
                observe(batch * batch_ids + index, name)?;
                input = &input[length..];
                count += 1;
            }
            if count != response.reasons_without_close as usize {
                return Err(io::Error::other("directory recovery count mismatch"));
            }
            cursor = response.next_usn;
        }
    }
    Ok(())
}

fn transact_request(
    request: &Request,
    query: &[u8],
    payload: &mut Vec<u8>,
) -> io::Result<Response> {
    let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
    // Only these read-only requests are safe to replay after the pipe dies:
    // a request may have reached the broker before the connection was lost.
    let replay_safe = matches!(
        request.opcode,
        Opcode::ProbeVolume | Opcode::ReadChangeReasons
    );
    loop {
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("broker client state poisoned"))?;
        if state.leases == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SunPack Watch Broker has not been acquired",
            ));
        }
        if state.connection.is_none() {
            state.connection = Some(connect_and_hello()?);
        }
        match state
            .connection
            .as_mut()
            .unwrap()
            .transact(request, query, payload)
        {
            // Business errors have completed their exchange and keep the lease.
            Ok(response) => return ensure_ok(response),
            Err(error) => {
                state.connection.take();
                if !replay_safe || !is_transient_broker_io(&error) {
                    return Err(error);
                }
                // Give other callers the chance to release or reconnect while
                // this request backs off after the broken exchange.
                drop(state);
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn is_transient_broker_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::NotConnected
    ) || matches!(
        error.raw_os_error(),
        Some(109 | 232 | 233 | 231) // BROKEN_PIPE, NO_DATA, PIPE_NOT_CONNECTED, PIPE_BUSY
    )
}

fn connect_and_hello() -> io::Result<BrokerConnection> {
    loop {
        // Service manager/start failures are real OS errors. Never hide them
        // behind an unlimited retry loop (e.g. missing service or no access).
        let mut connection = match start_service().and_then(|_| connect_pipe()) {
            Ok(connection) => connection,
            // Include a restart raced by connect_pipe after the last lease left.
            Err(error) if matches!(error.raw_os_error(), Some(1053 | 1055 | 1061)) => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(error) => return Err(error),
        };
        match connection.transact(
            &Request::simple(Opcode::Hello, next_request_id()),
            &[],
            &mut Vec::new(),
        ) {
            Ok(response) => {
                // Protocol errors and explicit broker rejection are terminal.
                ensure_ok(response)?;
                return Ok(connection);
            }
            Err(error) if is_transient_broker_io(&error) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
}

fn next_request_id() -> u64 {
    REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
}

fn ensure_ok(response: Response) -> io::Result<Response> {
    if response.status == Status::Ok {
        return Ok(response);
    }
    if response.win32_error != 0 {
        return Err(io::Error::from_raw_os_error(response.win32_error as i32));
    }
    let kind = match response.status {
        Status::InvalidRequest => io::ErrorKind::InvalidInput,
        Status::NotFound => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    Err(io::Error::new(
        kind,
        format!("SunPack Watch Broker returned {:?}", response.status),
    ))
}

fn start_service() -> io::Result<()> {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service_name = wide(&configured_name(
        SERVICE_NAME_ENV,
        SERVICE_NAME,
        TEST_SERVICE_NAME_PREFIX,
    ));
    let service = unsafe {
        OpenServiceW(
            manager,
            service_name.as_ptr(),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        let error = io::Error::last_os_error();
        unsafe { CloseServiceHandle(manager) };
        return Err(error);
    }
    let result = drive_service_start(
        || query_service_status(service),
        || {
            if unsafe { StartServiceW(service, 0, null()) } != 0 {
                return Ok(());
            }
            let error = unsafe { GetLastError() };
            if error == ERROR_SERVICE_ALREADY_RUNNING {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(error as i32))
            }
        },
        |state| wait_service_change(service, state),
    );
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    result
}

fn drive_service_start(
    mut query: impl FnMut() -> io::Result<SERVICE_STATUS_PROCESS>,
    mut start: impl FnMut() -> io::Result<()>,
    mut wait: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    let mut requested = false;
    loop {
        let status = query()?;
        match status.dwCurrentState {
            SERVICE_RUNNING => return Ok(()),
            SERVICE_STOPPED => {
                // A successful old instance can stop between StartService and
                // the status query. Re-enter the same startup path; a real
                // startup failure still propagates its OS error immediately.
                if requested && status.dwWin32ExitCode != 0 {
                    return Err(io::Error::from_raw_os_error(status.dwWin32ExitCode as i32));
                }
                start()?;
                requested = true;
            }
            SERVICE_START_PENDING => {
                requested = true;
                wait(SERVICE_START_PENDING)?;
            }
            SERVICE_STOP_PENDING => wait(SERVICE_STOP_PENDING)?,
            state => {
                return Err(io::Error::other(format!(
                    "unexpected Watch Broker service state {state}"
                )))
            }
        }
    }
}

fn wait_service_change(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
    state: u32,
) -> io::Result<()> {
    use std::cell::Cell;
    use std::ffi::c_void;
    use windows_sys::Win32::System::Threading::{SleepEx, INFINITE};

    unsafe extern "system" fn changed(parameter: *const c_void) {
        let notification = &*parameter.cast::<SERVICE_NOTIFY_2W>();
        let completed = &*notification.pContext.cast::<Cell<bool>>();
        completed.set(true);
    }

    let completed = Cell::new(false);
    let mut notification = SERVICE_NOTIFY_2W {
        dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
        pfnNotifyCallback: Some(changed),
        pContext: (&completed as *const Cell<bool>).cast_mut().cast(),
        ..Default::default()
    };
    let current = match state {
        SERVICE_START_PENDING => SERVICE_NOTIFY_START_PENDING,
        SERVICE_STOP_PENDING => SERVICE_NOTIFY_STOP_PENDING,
        _ => unreachable!(),
    };
    let mask = (SERVICE_NOTIFY_STOPPED
        | SERVICE_NOTIFY_START_PENDING
        | SERVICE_NOTIFY_STOP_PENDING
        | SERVICE_NOTIFY_RUNNING)
        & !current;
    let error = unsafe { NotifyServiceStatusChangeW(service, mask, &mut notification) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SCM queues the callback on this thread. Keeping both stack values alive
    // through its delivery avoids an extra thread, timer, or polling loop.
    while !completed.get() {
        unsafe {
            SleepEx(INFINITE, 1);
        }
    }
    if notification.dwNotificationStatus != 0 {
        return Err(io::Error::from_raw_os_error(
            notification.dwNotificationStatus as i32,
        ));
    }
    Ok(())
}

fn query_service_status(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> io::Result<SERVICE_STATUS_PROCESS> {
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

fn connect_pipe() -> io::Result<BrokerConnection> {
    let pipe_name = wide(&configured_name(
        PIPE_NAME_ENV,
        PIPE_NAME,
        TEST_PIPE_NAME_PREFIX,
    ));
    loop {
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            let mode = PIPE_READMODE_MESSAGE;
            if unsafe { SetNamedPipeHandleState(handle, &mode, null(), null()) } == 0 {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
            return Ok(BrokerConnection(handle));
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        if error == ERROR_FILE_NOT_FOUND {
            // The last lease may have left after start_service observed RUNNING.
            // Reuse SCM startup instead of waiting forever for an exited broker.
            start_service()?;
        }
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), 50) } != 0 {
            continue;
        }
        match unsafe { GetLastError() } {
            ERROR_SEM_TIMEOUT => {}
            // The SCM can report RUNNING before the first pipe is created.
            // WaitNamedPipeW returns immediately when the pipe doesn't exist.
            ERROR_FILE_NOT_FOUND => thread::sleep(Duration::from_millis(10)),
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

fn write_exact(handle: HANDLE, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            handle,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            null_mut(),
        )
    };
    if ok == 0 || written as usize != bytes.len() {
        return Err(pipe_error());
    }
    Ok(())
}

fn read_exact(handle: HANDLE, bytes: &mut [u8]) -> io::Result<()> {
    let mut read = 0u32;
    let ok = unsafe {
        ReadFile(
            handle,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut read,
            null_mut(),
        )
    };
    if ok == 0 || read as usize != bytes.len() {
        return Err(pipe_error());
    }
    Ok(())
}

fn pipe_error() -> io::Error {
    let error = unsafe { GetLastError() };
    if error == ERROR_BROKEN_PIPE {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "SunPack Watch Broker disconnected",
        )
    } else {
        io::Error::from_raw_os_error(error as i32)
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn configured_name(variable: &str, default: &str, test_prefix: &str) -> String {
    env::var(variable)
        .ok()
        .filter(|value| value.starts_with(test_prefix))
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_follows_retiring_instances_but_propagates_real_failures() {
        // Real service tests cannot force each SCM transition window. One
        // deterministic trace covers that gap without timers or admin rights.
        let status = |state, exit| SERVICE_STATUS_PROCESS {
            dwCurrentState: state,
            dwWin32ExitCode: exit,
            ..Default::default()
        };
        let mut states = [
            status(SERVICE_STOP_PENDING, 0),
            status(SERVICE_STOPPED, 0),
            status(SERVICE_STOPPED, 0),
            status(SERVICE_START_PENDING, 0),
            status(SERVICE_STOPPED, 0),
            status(SERVICE_START_PENDING, 0),
            status(SERVICE_RUNNING, 0),
        ]
        .into_iter();
        let (mut starts, mut waits) = (0, Vec::new());
        drive_service_start(
            || Ok(states.next().expect("startup must converge")),
            || {
                starts += 1;
                Ok(())
            },
            |state| {
                waits.push(state);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(starts, 3);
        assert_eq!(
            waits,
            [
                SERVICE_STOP_PENDING,
                SERVICE_START_PENDING,
                SERVICE_START_PENDING
            ]
        );
        for error in [5, 1066] {
            let mut states =
                [status(SERVICE_STOPPED, 0), status(SERVICE_STOPPED, error)].into_iter();
            let failure = drive_service_start(
                || Ok(states.next().unwrap()),
                || Ok(()),
                |_| panic!("no transition to wait for"),
            )
            .unwrap_err();
            assert_eq!(failure.raw_os_error(), Some(error as i32));
            let mut states = [
                status(SERVICE_START_PENDING, 0),
                status(SERVICE_STOPPED, error),
            ]
            .into_iter();
            let failure = drive_service_start(
                || Ok(states.next().unwrap()),
                || panic!("a failed concurrent startup must propagate"),
                |_| Ok(()),
            )
            .unwrap_err();
            assert_eq!(failure.raw_os_error(), Some(error as i32));
        }
        let failure = drive_service_start(
            || Ok(status(SERVICE_STOPPED, 0)),
            || Err(io::Error::from_raw_os_error(5)),
            |_| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(failure.raw_os_error(), Some(5));
    }

    #[test]
    fn replay_only_transport_failures_not_permission_or_protocol_failures() {
        assert!(is_transient_broker_io(&io::Error::from_raw_os_error(109)));
        assert!(is_transient_broker_io(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "disconnected",
        )));
        assert!(!is_transient_broker_io(&io::Error::from_raw_os_error(5)));
        assert!(!is_transient_broker_io(&io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid reply",
        )));
    }

    #[test]
    fn directory_recovery_allows_another_request_between_pages() {
        use crate::protocol::REQUEST_BYTES;
        use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        };

        let name = wide(&format!(
            r"\\.\pipe\SunPack.WatchBroker.Test.interleave.{}",
            std::process::id()
        ));
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                null(),
            )
        };
        assert_ne!(pipe, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
        let server = BrokerConnection(pipe);
        let client = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        assert_ne!(
            client,
            INVALID_HANDLE_VALUE,
            "{}",
            io::Error::last_os_error()
        );
        let client = BrokerConnection(client);
        assert!(unsafe {
            ConnectNamedPipe(server.0, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED
        });
        let mode = PIPE_READMODE_MESSAGE;
        assert_ne!(
            unsafe { SetNamedPipeHandleState(client.0, &mode, null(), null()) },
            0
        );

        let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
        *state.lock().unwrap() = ClientState {
            connection: Some(client),
            leases: 1,
        };
        thread::scope(|workers| {
            let server = workers.spawn(move || {
                // Keep ownership of the pipe in this thread even if a reply assertion fails.
                let server = server;
                let serve = |opcode, start, next, name: &[u8]| {
                    let mut request = [0; REQUEST_BYTES];
                    read_exact(server.0, &mut request).unwrap();
                    let request = Request::decode(&request).unwrap();
                    assert_eq!(request.opcode, opcode);
                    assert_eq!(request.previous_usn, start);
                    let mut reply = Response::ok(request.request_id);
                    reply.journal_id = 42;
                    reply.next_usn = next;
                    let mut payload = Vec::new();
                    if opcode == Opcode::ReadDirectoriesChanges {
                        let mut length = [0; 4];
                        let mut query = [0; 8 + FILE_ID_BYTES];
                        read_exact(server.0, &mut length).unwrap();
                        assert_eq!(u32::from_le_bytes(length) as usize, query.len());
                        read_exact(server.0, &mut query).unwrap();
                        payload.extend_from_slice(&0u32.to_le_bytes());
                        payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
                        payload.extend_from_slice(name);
                        reply.reasons_all = payload.len() as u32;
                        reply.reasons_without_close = 1;
                    }
                    write_exact(server.0, &reply.encode()).unwrap();
                    if !payload.is_empty() {
                        write_exact(server.0, &payload).unwrap();
                    }
                };
                serve(Opcode::ReadDirectoriesChanges, 1, 2, b"first");
                serve(Opcode::ProbeVolume, 0, 3, b"");
                serve(Opcode::ReadDirectoriesChanges, 2, 3, b"second");
            });
            let mut names = Vec::new();
            let result = broker_for_each_directory_change(
                "volume",
                42,
                &[[1; FILE_ID_BYTES]],
                1,
                3,
                |index, name| {
                    if index != 0 || state.try_lock().is_err() {
                        return Err(io::Error::other(
                            "directory observer ran inside the pipe lock",
                        ));
                    }
                    if name == "first" && broker_volume_cursor("volume")? != (42, 3) {
                        return Err(io::Error::other(
                            "probe cursor did not survive interleaving",
                        ));
                    }
                    names.push(name.to_owned());
                    Ok(())
                },
            );
            broker_release().unwrap();
            let server_result = server.join();
            result.unwrap();
            server_result.unwrap();
            assert_eq!(names, ["first", "second"]);
        });
    }

    #[test]
    fn empty_runtime_identity_uses_the_production_default() {
        let variable = "SUNPACK_TEST_EMPTY_BROKER_IDENTITY";
        std::env::set_var(variable, "");
        assert_eq!(
            configured_name(variable, SERVICE_NAME, TEST_SERVICE_NAME_PREFIX),
            SERVICE_NAME
        );
        std::env::remove_var(variable);
    }

    #[test]
    fn runtime_identity_accepts_only_the_test_namespace() {
        let variable = "SUNPACK_TEST_BROKER_IDENTITY_NAMESPACE";
        std::env::set_var(variable, "SunPackWatchBroker");
        assert_eq!(
            configured_name(variable, SERVICE_NAME, TEST_SERVICE_NAME_PREFIX),
            SERVICE_NAME
        );
        std::env::set_var(variable, "SunPackWatchBrokerTest_example");
        assert_eq!(
            configured_name(variable, SERVICE_NAME, TEST_SERVICE_NAME_PREFIX),
            "SunPackWatchBrokerTest_example"
        );
        std::env::remove_var(variable);
    }
}
