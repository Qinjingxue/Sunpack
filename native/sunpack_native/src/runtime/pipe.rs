use super::cli::{self, Host};
use super::windows::{self, Event};
use super::{Session, Stream};
use crate::core::{config, resources};
use crate::pipeline::Cancellation;
use std::ffi::{c_void, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, ERROR_SHARING_VIOLATION, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::Threading::{WaitForMultipleObjects, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const MAX_FIELD: usize = 16 * 1024 * 1024;
const RESIZE: u32 = u32::MAX - 1;
const CANCEL: u32 = u32::MAX;

fn state_path(cwd: &Path, identity: &str) -> io::Result<PathBuf> {
    Ok(resources::writable_data_dir(cwd)?.join(format!("runtime-{identity}.state")))
}

fn runtime_stamp(path: &Path) -> io::Result<String> {
    let metadata = path.metadata()?;
    let nanos = metadata
        .last_write_time()
        .saturating_sub(116444736000000000)
        * 100;
    Ok(format!("{:x}-{nanos:x}", metadata.file_size()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn token_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}

struct StateFile {
    path: PathBuf,
    _lock: File,
}

impl StateFile {
    fn acquire(path: PathBuf) -> io::Result<Option<Self>> {
        fs::create_dir_all(path.parent().unwrap())?;
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(lock_path)
        {
            Ok(lock) => lock,
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(Self { path, _lock: lock }))
    }

    fn publish(
        &self,
        name: &str,
        token: &[u8; 32],
        build_id: &[u8; 16],
        stamp: &str,
    ) -> io::Result<()> {
        let mut temp = self.path.as_os_str().to_owned();
        temp.push(format!(".{}.tmp", std::process::id()));
        let temp = PathBuf::from(temp);
        fs::write(
            &temp,
            format!(
                "{name}\n{}\n{}\n{}\n{stamp}\n",
                hex(token),
                std::str::from_utf8(build_id).unwrap(),
                std::process::id()
            ),
        )?;
        let result = crate::io::atomic_file::replace(&temp, &self.path);
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}

impl Drop for StateFile {
    fn drop(&mut self) {
        // Keep the lock through removal, including during error unwinding.
        let _ = fs::remove_file(&self.path);
    }
}

struct Accept {
    pipe: Option<OwnedHandle>,
    event: Event,
    overlapped: Box<OVERLAPPED>,
    pending: bool,
}

impl Accept {
    fn arm(name: &[u16], security: &SECURITY_ATTRIBUTES, first: bool) -> io::Result<Self> {
        let mut flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                flags,
                PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                8192,
                8192,
                0,
                security,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
        let event = Event::new(true)?;
        let mut overlapped = Box::new(OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        });
        let pending = if unsafe { ConnectNamedPipe(raw, &mut *overlapped) } == 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_IO_PENDING) => true,
                Some(ERROR_PIPE_CONNECTED) => false,
                _ => return Err(error),
            }
        } else {
            false
        };
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

    fn finish(mut self) -> io::Result<OwnedHandle> {
        if self.pending {
            let result = complete(
                self.pipe.as_ref().unwrap().as_raw_handle(),
                &mut self.overlapped,
            );
            self.pending = false;
            result?;
        }
        Ok(self.pipe.take().unwrap())
    }
}

impl Drop for Accept {
    fn drop(&mut self) {
        if self.pending {
            drain(
                self.pipe.as_ref().unwrap().as_raw_handle(),
                &mut self.overlapped,
            );
        }
    }
}

fn complete(pipe: *mut c_void, overlapped: &mut OVERLAPPED) -> io::Result<usize> {
    let mut transferred = 0;
    if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(transferred as usize)
    }
}

fn drain(pipe: *mut c_void, overlapped: &mut OVERLAPPED) {
    unsafe {
        CancelIoEx(pipe, overlapped);
        let mut transferred = 0;
        GetOverlappedResult(pipe, overlapped, &mut transferred, 1);
    }
}

struct Peer<'a> {
    pipe: OwnedHandle,
    stop: Event,
    shutdown: &'a Event,
}

impl<'a> Peer<'a> {
    fn new(pipe: OwnedHandle, shutdown: &'a Event) -> io::Result<Self> {
        Ok(Self {
            pipe,
            stop: Event::new(true)?,
            shutdown,
        })
    }

    fn transfer(
        &self,
        event: &Event,
        operation: impl FnOnce(*mut c_void, &mut OVERLAPPED) -> i32,
    ) -> io::Result<usize> {
        let pipe = self.pipe.as_raw_handle();
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        event.reset()?;
        if operation(pipe, &mut overlapped) == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
            let handles = [event.raw(), self.stop.raw(), self.shutdown.raw()];
            match unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, INFINITE) } {
                WAIT_OBJECT_0 => {}
                result => {
                    drain(pipe, &mut overlapped);
                    return Err(
                        if result == WAIT_OBJECT_0 + 1 || result == WAIT_OBJECT_0 + 2 {
                            io::ErrorKind::ConnectionAborted.into()
                        } else {
                            io::Error::last_os_error()
                        },
                    );
                }
            }
        }
        complete(pipe, &mut overlapped)
    }
}

struct Reader<'a> {
    peer: &'a Peer<'a>,
    event: Event,
}

impl Read for Reader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.peer.transfer(&self.event, |pipe, overlapped| unsafe {
            ReadFile(
                pipe,
                buffer.as_mut_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                null_mut(),
                overlapped,
            )
        })
    }
}

struct Writer<'a> {
    peer: &'a Peer<'a>,
    event: Event,
}

impl Write for Writer<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.peer.transfer(&self.event, |pipe, overlapped| unsafe {
            WriteFile(
                pipe,
                buffer.as_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                null_mut(),
                overlapped,
            )
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Header {
    flags: u32,
    cwd: PathBuf,
    argv: Vec<String>,
    terminal_size: u32,
}

fn encode_terminal_size(columns: u32, rows: u32) -> Option<u32> {
    ((1..=32767).contains(&columns) && (1..=32767).contains(&rows)).then_some(columns | rows << 16)
}

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut word = [0; 4];
    input.read_exact(&mut word)?;
    Ok(u32::from_be_bytes(word))
}

fn read_field(input: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    if len > MAX_FIELD {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut output = Vec::new();
    input.take(len as u64).read_to_end(&mut output)?;
    if output.len() != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(output)
}

fn read_text(input: &mut impl Read, size: usize) -> io::Result<String> {
    String::from_utf8(read_field(input, size)?).map_err(io::Error::other)
}

impl Header {
    fn read(input: &mut impl Read, build_id: &[u8; 16], token: &[u8; 32]) -> io::Result<Self> {
        let mut header = [0; 52];
        input.read_exact(&mut header)?;
        if &header[..4] != b"SPK2" || &header[4..20] != build_id || &header[20..] != token {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let flags = read_u32(input)?;
        let cwd_len = read_u32(input)? as usize;
        let argc = read_u32(input)?;
        let cwd = PathBuf::from(read_text(input, cwd_len)?);
        if !cwd.is_absolute() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut argv = Vec::new();
        let mut terminal_size = 80 | 24 << 16;
        for _ in 0..argc {
            let size = read_u32(input)? as usize;
            let arg = read_text(input, size)?;
            if let Some(value) = arg.strip_prefix("--_sunpack-terminal-size=") {
                if let Some(size) = value.split_once('x').and_then(|(width, height)| {
                    encode_terminal_size(width.parse().ok()?, height.parse().ok()?)
                }) {
                    terminal_size = size;
                }
            } else {
                argv.push(arg);
            }
        }
        Ok(Self {
            flags,
            cwd,
            argv,
            terminal_size,
        })
    }
}

struct Connection<'a> {
    writer: Mutex<Writer<'a>>,
    prompt: Mutex<Option<mpsc::SyncSender<Vec<u8>>>>,
    input: Mutex<PromptInput>,
    cancel: Cancellation,
    terminal_size: AtomicU32,
    flags: u32,
}

#[derive(Default)]
struct PromptInput {
    bytes: Vec<u8>,
    start: usize,
    searched: usize,
    eof: bool,
    swallow_lf: bool,
}

impl PromptInput {
    fn line(&mut self) -> Option<String> {
        if self.swallow_lf && self.start < self.bytes.len() {
            self.start += usize::from(self.bytes[self.start] == b'\n');
            self.searched = self.searched.max(self.start);
            self.swallow_lf = false;
        }
        let unread = &self.bytes[self.start..];
        if unread.is_empty() {
            return None;
        }
        let offset = self.searched - self.start;
        let delimiter =
            memchr::memchr2(b'\r', b'\n', &unread[offset..]).map(|index| index + offset);
        let end = match delimiter {
            Some(index) if unread[index] == b'\r' => match unread.get(index + 1) {
                Some(b'\n') => index + 2,
                Some(_) => index + 1,
                None => {
                    self.swallow_lf = true;
                    index + 1
                }
            },
            Some(index) => index + 1,
            None if self.eof => unread.len(),
            None => {
                self.searched = self.bytes.len();
                return None;
            }
        };
        let line = String::from_utf8_lossy(&unread[..end]).into_owned();
        self.start += end;
        self.searched = self.start;
        if self.start == self.bytes.len() && self.bytes.capacity() > 64 * 1024 {
            self.bytes = Vec::new();
            self.start = 0;
            self.searched = 0;
        }
        Some(line)
    }

    fn push(&mut self, chunk: Vec<u8>) -> io::Result<()> {
        if self.start != 0 {
            self.bytes.copy_within(self.start.., 0);
            self.bytes.truncate(self.bytes.len() - self.start);
            self.searched -= self.start;
            self.start = 0;
        }
        if self.bytes.len().saturating_add(chunk.len()) > MAX_FIELD {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.eof = chunk.is_empty();
        if self.bytes.is_empty() && self.bytes.capacity() < chunk.len() {
            self.bytes = chunk;
        } else {
            self.bytes.extend_from_slice(&chunk);
        }
        Ok(())
    }
}

impl Connection<'_> {
    fn frame(&self, kind: u8, bytes: &[u8]) -> io::Result<()> {
        let mut output = self.writer.lock().unwrap();
        let mut frame = Vec::with_capacity(5 + bytes.len().min(32 * 1024));
        for chunk in bytes
            .chunks(MAX_FIELD)
            .chain(bytes.is_empty().then_some(bytes))
        {
            frame.clear();
            frame.push(kind);
            frame.extend((chunk.len() as u32).to_be_bytes());
            frame.extend(chunk);
            output.write_all(&frame)?;
        }
        Ok(())
    }

    fn read_control(&self, reader: &mut impl Read, cwd: &Path) -> io::Result<()> {
        loop {
            match read_u32(reader)? {
                RESIZE if self.flags & 10 == 10 => {
                    let size = encode_terminal_size(read_u32(reader)?, read_u32(reader)?)
                        .ok_or(io::ErrorKind::InvalidData)?;
                    self.terminal_size.store(size, Ordering::Relaxed);
                }
                CANCEL => {
                    if !self.cancel.cancelled() {
                        self.cancel.cancel();
                        self.prompt.lock().unwrap().take();
                        let language = config::load_language(cwd);
                        let message = format!("{}\n", language.text("interrupt.stopping"));
                        self.frame(Stream::Err as u8, message.as_bytes())?;
                    }
                }
                length => {
                    let receiver = self.prompt.lock().unwrap().take();
                    let Some(receiver) = receiver else {
                        // Cancelling a console read can still produce its empty reply.
                        return if self.cancel.cancelled() {
                            Ok(())
                        } else {
                            Err(io::ErrorKind::InvalidData.into())
                        };
                    };
                    let response = read_field(reader, length as usize)?;
                    let _ = receiver.send(response);
                }
            }
        }
    }

    fn read_prompt_chunk(&self) -> io::Result<Option<Vec<u8>>> {
        let (send, receive) = mpsc::sync_channel(1);
        {
            let mut pending = self.prompt.lock().unwrap();
            if self.cancel.cancelled() {
                return Ok(None);
            }
            *pending = Some(send);
        }
        self.frame(3, &[])?;
        Ok(receive.recv().ok())
    }
}

impl Session for Connection<'_> {
    fn write(&self, stream: Stream, data: &[u8]) -> io::Result<()> {
        self.frame(stream as u8, data)
    }

    fn read_line(&self, prompt: &str) -> io::Result<Option<String>> {
        let mut input = self.input.lock().unwrap();
        if !prompt.is_empty() {
            self.write(Stream::Out, prompt.as_bytes())?;
        }
        loop {
            if self.cancel.cancelled() {
                return Ok(None);
            }
            if let Some(line) = input.line() {
                return Ok(Some(line));
            }
            if input.eof {
                return Ok(None);
            }
            let Some(chunk) = self.read_prompt_chunk()? else {
                return Ok(None);
            };
            input.push(chunk)?;
        }
    }

    fn interactive(&self) -> bool {
        self.flags & 2 != 0
    }

    fn unicode(&self) -> bool {
        self.flags & 16 != 0
    }

    fn terminal_size(&self) -> (usize, usize) {
        let size = self.terminal_size.load(Ordering::Relaxed);
        ((size & 0xffff) as usize, (size >> 16) as usize)
    }
}

struct Activity {
    last_idle: Instant,
    active: usize,
    shutting_down: bool,
}

struct Server {
    host: Host,
    activity: Mutex<Activity>,
    drained: Condvar,
    wake: Arc<Event>,
    stop: Event,
    token: [u8; 32],
    build_id: [u8; 16],
}

impl Server {
    fn serve_peer(&self, pipe: OwnedHandle) {
        let _ = self.request(pipe);
        let mut activity = self.activity.lock().unwrap();
        activity.active -= 1;
        if activity.active == 0 {
            activity.last_idle = Instant::now();
            self.drained.notify_all();
        }
        drop(activity);
        self.wake.signal();
    }

    fn request(&self, pipe: OwnedHandle) -> io::Result<()> {
        let peer = Peer::new(pipe, &self.stop)?;
        let mut reader = Reader {
            peer: &peer,
            event: Event::new(true)?,
        };
        let mut writer = Writer {
            peer: &peer,
            event: Event::new(true)?,
        };
        let header = Header::read(&mut reader, &self.build_id, &self.token)?;
        writer.write_all(&[b"SPS2".as_slice(), &self.build_id].concat())?;
        let connection = Connection {
            writer: Mutex::new(writer),
            prompt: Mutex::default(),
            input: Mutex::default(),
            cancel: Cancellation::new(),
            terminal_size: AtomicU32::new(header.terminal_size),
            flags: header.flags,
        };
        if header.flags & 1 != 0 {
            connection.frame(0, &0_i32.to_be_bytes())?;
            self.activity.lock().unwrap().shutting_down = true;
            self.stop.signal();
            self.wake.signal();
            return Ok(());
        }
        let cancel = connection.cancel.clone();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                if connection.read_control(&mut reader, &header.cwd).is_err() {
                    connection.cancel.cancel();
                    peer.stop.signal();
                    connection.prompt.lock().unwrap().take();
                }
            });
            let result = cli::run(&self.host, &header.cwd, header.argv, &connection, cancel);
            let code = result.unwrap_or_else(|error| {
                let _ = connection.write(Stream::Err, format!("{error}\n").as_bytes());
                3
            });
            let result = connection.frame(0, &code.to_be_bytes());
            peer.stop.signal();
            result
        })
    }
}

fn idle_wait(started: Instant, idle: Duration) -> u32 {
    let remaining = idle.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        0
    } else {
        (remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min((INFINITE - 1) as u128)) as u32
    }
}

pub(super) fn serve(cwd: &Path, identity: &str) -> io::Result<()> {
    let Some(state) = StateFile::acquire(state_path(cwd, identity)?)? else {
        return Ok(());
    };
    let exe = std::env::current_exe()?;
    let stamp = runtime_stamp(&exe)?;
    let build_id = crate::io::runtime_binary::runtime_binary_build_id(&exe)?;
    let build_id: [u8; 16] = build_id.as_bytes().try_into().map_err(io::Error::other)?;
    let token = windows::random_bytes::<32>()?;
    let nonce = windows::random_bytes::<16>()?;
    let name = format!(r"\\.\pipe\SunPack-{identity}-{}", hex(&nonce));
    let name_wide = windows::wide(OsStr::new(&name));
    let descriptor = windows::PipeSecurity::current_user()?;
    let security = descriptor.attributes();
    let wake = Arc::new(Event::new(false)?);
    let host = Host::with_wake({
        let wake = Arc::clone(&wake);
        move || wake.signal()
    });
    let server = Arc::new(Server {
        host,
        wake,
        activity: Mutex::new(Activity {
            last_idle: Instant::now(),
            active: 0,
            shutting_down: false,
        }),
        drained: Condvar::new(),
        stop: Event::new(true)?,
        token,
        build_id,
    });
    // State always names this server's unique endpoint and token.
    state.publish(&name, &server.token, &server.build_id, &stamp)?;
    if let Ok(settings) = config::load(cwd) {
        server.host.configure_idle(&settings);
    }
    let result = (|| {
        let mut accept = Accept::arm(&name_wide, &security, true)?;
        let mut served = false;
        loop {
            let (wait, shutting_down) = {
                let state = server.activity.lock().unwrap();
                let timeout = if served && state.active == 0 && !server.host.watch.is_running() {
                    idle_wait(state.last_idle, server.host.idle_after())
                } else {
                    INFINITE
                };
                (timeout, state.shutting_down)
            };
            if shutting_down {
                return Ok(());
            }
            let handles = [accept.event.raw(), server.wake.raw()];
            match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, wait) } {
                WAIT_OBJECT_0 => {
                    let connected = accept.finish();
                    accept = Accept::arm(&name_wide, &security, false)?;
                    match connected {
                        Ok(peer) => {
                            served = true;
                            let mut state = server.activity.lock().unwrap();
                            state.active += 1;
                            let handler = Arc::clone(&server);
                            if let Err(error) = std::thread::Builder::new()
                                .name("sunpack-request".into())
                                .stack_size(512 * 1024)
                                .spawn(move || handler.serve_peer(peer))
                            {
                                state.active -= 1;
                                return Err(error);
                            }
                        }
                        Err(error) if matches!(error.raw_os_error(), Some(109 | 232 | 233)) => {}
                        Err(error) => return Err(error),
                    }
                }
                WAIT_TIMEOUT if wait == 0 => return Ok(()),
                WAIT_TIMEOUT => {}
                value if value == WAIT_OBJECT_0 + 1 => {}
                _ => return Err(io::Error::last_os_error()),
            }
        }
    })();
    server.stop.signal();
    let _ = server.host.watch.stop();
    let _drained = server
        .drained
        .wait_while(server.activity.lock().unwrap(), |state| state.active != 0)
        .unwrap();
    result
}

pub(super) fn shutdown(cwd: &Path, identity: &str) -> io::Result<()> {
    submit_existing(cwd, identity, &[], true).map(|_| ())
}

pub(super) fn submit_existing(
    cwd: &Path,
    identity: &str,
    args: &[String],
    shutdown: bool,
) -> io::Result<Option<i32>> {
    let raw = match fs::read_to_string(state_path(cwd, identity)?) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut lines = raw.lines();
    let name = lines
        .next()
        .filter(|name| name.starts_with(r"\\.\pipe\SunPack-"))
        .ok_or(io::ErrorKind::InvalidData)?;
    let token = lines
        .next()
        .and_then(token_bytes)
        .ok_or(io::ErrorKind::InvalidData)?;
    let build_id = lines
        .next()
        .filter(|id| id.len() == 16)
        .ok_or(io::ErrorKind::InvalidData)?;
    let mut pipe = match OpenOptions::new().read(true).write(true).open(name) {
        Ok(pipe) => pipe,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let cwd = cwd.to_str().ok_or(io::ErrorKind::InvalidInput)?;
    let mut request = Vec::new();
    request.extend(b"SPK2");
    request.extend(build_id.as_bytes());
    request.extend(token);
    request.extend(u32::from(shutdown).to_be_bytes());
    request.extend((cwd.len() as u32).to_be_bytes());
    request.extend((args.len() as u32).to_be_bytes());
    request.extend(cwd.as_bytes());
    for arg in args {
        request.extend((arg.len() as u32).to_be_bytes());
        request.extend(arg.as_bytes());
    }
    pipe.write_all(&request)?;
    let mut handshake = [0; 20];
    pipe.read_exact(&mut handshake)?;
    if &handshake[..4] != b"SPS2" || &handshake[4..] != build_id.as_bytes() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    loop {
        let mut kind = [0];
        pipe.read_exact(&mut kind)?;
        let size = read_u32(&mut pipe)? as usize;
        let payload = read_field(&mut pipe, size)?;
        match kind[0] {
            0 if size == 4 => return Ok(Some(i32::from_be_bytes(payload.try_into().unwrap()))),
            1 | 2 => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
}
