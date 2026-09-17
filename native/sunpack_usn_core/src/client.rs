use crate::protocol::{parse_file_id, Opcode, Request, Response, Status, RESPONSE_BYTES};
const MAX_BROKER_PAYLOAD_BYTES: usize = 64 * 1024;
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
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_SERVICE_ALREADY_RUNNING, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{
    SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_MESSAGE,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
    fn transact(&mut self, request: Request) -> io::Result<Response> {
        let (response, payload) = self.transact_payload(request)?;
        if !payload.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected broker payload"));
        }
        Ok(response)
    }

    fn transact_payload(&mut self, request: Request) -> io::Result<(Response, Vec<u8>)> {
        let request_id = request.request_id;
        let payload_response = request.opcode == Opcode::ReadRootChanges;
        let request = request.encode()?;
        write_exact(self.0, &request)?;
        let mut response_bytes = [0u8; RESPONSE_BYTES];
        read_exact(self.0, &mut response_bytes)?;
        let response = Response::decode(&response_bytes)?;
        if response.request_id != request_id {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "broker response request ID mismatch"));
        }
        let payload_len = if payload_response && response.status == Status::Ok {
            response.reasons_all as usize
        } else {
            0
        };
        if payload_len > MAX_BROKER_PAYLOAD_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "broker payload exceeds limit"));
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            read_exact(self.0, &mut payload)?;
        }
        Ok((response, payload))
    }
}

pub fn broker_acquire() -> io::Result<()> {
    let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("broker client state poisoned"))?;
    if state.leases > 0 {
        if state.connection.is_none() {
            state.connection = Some(connect_and_hello()?);
        }
        state.leases += 1;
        return Ok(());
    }
    state.connection = Some(connect_and_hello()?);
    state.leases = 1;
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
    if state.leases > 0 {
        return Ok(());
    }
    if let Some(mut connection) = state.connection.take() {
        let _ = connection.transact(Request::simple(Opcode::Release, next_request_id()));
    }
    Ok(())
}

pub fn broker_is_connected() -> bool {
    STATE
        .get()
        .and_then(|state| {
            state
                .lock()
                .ok()
                .map(|state| state.leases > 0 && state.connection.is_some())
        })
        .unwrap_or(false)
}

pub fn broker_ping() -> io::Result<Duration> {
    let started = Instant::now();
    ensure_ok(transact_request(Request::simple(
        Opcode::Ping,
        next_request_id(),
    ))?)?;
    Ok(started.elapsed())
}

pub fn broker_probe_volume(volume_guid: &str) -> io::Result<()> {
    broker_volume_cursor(volume_guid).map(|_| ())
}

pub fn broker_volume_cursor(volume_guid: &str) -> io::Result<(u64, i64)> {
    let mut request = Request::simple(Opcode::ProbeVolume, next_request_id());
    request.volume_guid = volume_guid.to_owned();
    let response = ensure_ok(transact_request(request)?)?;
    Ok((response.journal_id, response.next_usn))
}

pub fn broker_read_change_reasons(
    volume_guid: &str,
    file_id: &str,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<ChangeReasons> {
    let (file_id, file_id_len) = parse_file_id(file_id)?;
    let mut request = Request::simple(Opcode::ReadChangeReasons, next_request_id());
    request.volume_guid = volume_guid.to_owned();
    request.file_id = file_id;
    request.file_id_len = file_id_len;
    request.previous_usn = previous_usn;
    request.current_usn = current_usn;
    let response = ensure_ok(transact_request(request)?)?;
    Ok(ChangeReasons {
        all: response.reasons_all,
        without_close: response.reasons_without_close,
    })
}

pub fn broker_read_root_changes(
    volume_guid: &str,
    root_file_id: &str,
    start_usn: i64,
    end_usn: i64,
) -> io::Result<Vec<String>> {
    let (file_id, file_id_len) = parse_file_id(root_file_id)?;
    let mut request = Request::simple(Opcode::ReadRootChanges, next_request_id());
    request.volume_guid = volume_guid.to_owned();
    request.file_id = file_id;
    request.file_id_len = file_id_len;
    request.previous_usn = start_usn;
    request.current_usn = end_usn;
    let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
    let mut state = state.lock().map_err(|_| io::Error::other("broker client state poisoned"))?;
    if state.leases == 0 {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "SunPack Watch Broker has not been acquired"));
    }
    if state.connection.is_none() {
        state.connection = Some(connect_and_hello()?);
    }
    let (response, payload) = state.connection.as_mut().unwrap().transact_payload(request)?;
    ensure_ok(response)?;
    decode_path_payload(&payload)
}

fn decode_path_payload(payload: &[u8]) -> io::Result<Vec<String>> {
    let mut offset = 0usize;
    let mut result = Vec::new();
    while offset < payload.len() {
        if offset + 4 > payload.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated path payload"));
        }
        let length = u32::from_le_bytes(payload[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + length > payload.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated path payload item"));
        }
        result.push(std::str::from_utf8(&payload[offset..offset+length])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path payload is not UTF-8"))?
            .to_owned());
        offset += length;
    }
    Ok(result)
}

fn transact_request(request: Request) -> io::Result<Response> {
    let state = STATE.get_or_init(|| Mutex::new(ClientState::default()));
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("broker client state poisoned"))?;
    if state.leases == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "SunPack Watch Broker has not been acquired",
        ));
    }
    let mut last_error = None;
    for _ in 0..2 {
        if state.connection.is_none() {
            match connect_and_hello() {
                Ok(connection) => state.connection = Some(connection),
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }
        match state.connection.as_mut().unwrap().transact(request.clone()) {
            Ok(response) => return Ok(response),
            Err(error) => {
                state.connection.take();
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "SunPack Watch Broker is disconnected",
        )
    }))
}

fn connect_and_hello() -> io::Result<BrokerConnection> {
    let mut last_error = None;
    for attempt in 0..2 {
        if attempt > 0 {
            thread::sleep(Duration::from_millis(50));
        }
        if let Err(error) = start_service() {
            last_error = Some(error);
            continue;
        }
        let mut connection = match connect_pipe() {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let hello = match connection.transact(Request::simple(Opcode::Hello, next_request_id())) {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match ensure_ok(hello) {
            Ok(_) => return Ok(connection),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "SunPack Watch Broker could not establish a lease",
        )
    }))
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
        Status::VersionMismatch => io::ErrorKind::Unsupported,
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
        unsafe { CloseServiceHandle(manager) };
        return Err(io::Error::last_os_error());
    }
    let stop_deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        let status = match query_service_status(service) {
            Ok(status) => status,
            Err(error) => {
                unsafe {
                    CloseServiceHandle(service);
                    CloseServiceHandle(manager);
                }
                return Err(error);
            }
        };
        if status.dwCurrentState != SERVICE_STOP_PENDING {
            break;
        }
        if Instant::now() >= stop_deadline {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SunPack Watch Broker did not finish stopping",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }

    let started = unsafe { StartServiceW(service, 0, null()) };
    if started == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_SERVICE_ALREADY_RUNNING {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
    }
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        let status = match query_service_status(service) {
            Ok(status) => status,
            Err(error) => {
                unsafe {
                    CloseServiceHandle(service);
                    CloseServiceHandle(manager);
                }
                return Err(error);
            }
        };
        if status.dwCurrentState == SERVICE_RUNNING {
            break;
        }
        if status.dwCurrentState == SERVICE_STOPPED || Instant::now() >= deadline {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SunPack Watch Broker did not reach RUNNING",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
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
    let deadline = Instant::now() + CONNECT_TIMEOUT;
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
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SunPack Watch Broker pipe was not ready",
            ));
        }
        unsafe {
            WaitNamedPipeW(pipe_name.as_ptr(), 50);
        }
        thread::sleep(Duration::from_millis(10));
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
    fn disconnected_client_is_not_reported_as_connected() {
        assert!(!broker_is_connected());
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
