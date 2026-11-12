use super::cli::{self, Host};
use super::windows::{self, Event};
use super::{Session, Stream};
use crate::core::{config, resources};
use crate::pipeline::{block_on, in_control_poll, Cancellation, Origin};
use super::cli::reporting::Reply;
use std::pin::Pin;
use std::future::Future;
mod transport;
mod output;
use std::ffi::{c_void, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, ERROR_SHARING_VIOLATION, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const MAX_FIELD: usize = 16 * 1024 * 1024;
const TERMINAL_SIZE_FIELD: u32 = 32;
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

async fn read_word(peer: &transport::Peer) -> io::Result<u32> {
    Ok(u32::from_be_bytes(peer.read_exact(4).await?.try_into().unwrap()))
}
async fn read_peer_field(peer: &transport::Peer, length: usize) -> io::Result<Vec<u8>> {
    if length > MAX_FIELD { return Err(io::ErrorKind::InvalidData.into()); }
    peer.read_exact(length).await
}
impl Header {
    async fn read(peer: &transport::Peer, build_id: &[u8; 16], token: &[u8; 32]) -> io::Result<Self> {
        let header = peer.read_exact(52).await?;
        if &header[..4] != b"SPK2" || &header[4..20] != build_id || &header[20..] != token {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let flags = read_word(peer).await?;
        let cwd_len = read_word(peer).await? as usize;
        let argc = read_word(peer).await?;
        let cwd = PathBuf::from(String::from_utf8(read_peer_field(peer, cwd_len).await?).map_err(io::Error::other)?);
        if !cwd.is_absolute() { return Err(io::ErrorKind::InvalidInput.into()); }
        let mut argv = Vec::new();
        let mut terminal_size = 80 | 24 << 16;
        for index in 0..argc {
            let size = read_word(peer).await? as usize;
            let arg = String::from_utf8(read_peer_field(peer, size).await?).map_err(io::Error::other)?;
            if flags & TERMINAL_SIZE_FIELD != 0 && index + 1 == argc {
                terminal_size = arg.strip_prefix("--_sunpack-terminal-size=")
                    .and_then(|value| value.split_once('x'))
                    .and_then(|(width, height)| encode_terminal_size(width.parse().ok()?, height.parse().ok()?))
                    .ok_or(io::ErrorKind::InvalidData)?;
            } else { argv.push(arg); }
        }
        Ok(Self { flags, cwd, argv, terminal_size })
    }
}

struct Connection {
    peer: transport::Peer,
    output: output::Output,
    prompt: Mutex<Option<Arc<PromptAnswer>>>,
    input: Mutex<PromptInput>,
    cancel: Cancellation,
    finishing: AtomicBool,
    terminal_size: AtomicU32,
    flags: u32,
}

#[derive(Default)]
struct PromptAnswer {
    reply: Reply<Vec<u8>>,
    completed: AtomicBool,
}
impl PromptAnswer {
    fn complete(&self, value: io::Result<Vec<u8>>) {
        // Input and cancellation race for the same one-shot, like main's
        // Future.done check. A late cancellation must not replace an answer.
        if !self.completed.swap(true, Ordering::AcqRel) { self.reply.complete(value); }
    }
    async fn wait(&self) -> io::Result<Vec<u8>> { self.reply.wait().await }
}

struct PromptReply<'a> {
    slot: &'a Mutex<Option<Arc<PromptAnswer>>>,
    reply: Arc<PromptAnswer>,
    _cancellation: Option<crate::io::cancellation::Subscription>,
}
impl<'a> PromptReply<'a> {
    fn new(slot: &'a Mutex<Option<Arc<PromptAnswer>>>, cancel: &Cancellation) -> io::Result<Option<Self>> {
        let reply = Arc::new(PromptAnswer::default());
        {
            let mut pending = slot.lock().unwrap();
            if cancel.cancelled() { return Ok(None); }
            if pending.is_some() { return Err(io::Error::other("a prompt is already awaiting input")); }
            *pending = Some(Arc::clone(&reply));
        }
        let wake = Arc::clone(&reply);
        let cancellation = cancel.subscribe(move || wake.complete(Ok(Vec::new())));
        Ok(Some(Self { slot, reply, _cancellation: cancellation }))
    }
}
impl Drop for PromptReply<'_> {
    fn drop(&mut self) {
        let mut slot = self.slot.lock().unwrap();
        if slot.as_ref().is_some_and(|reply| Arc::ptr_eq(reply, &self.reply)) { slot.take(); }
    }
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

// Console clients decode each output frame independently. Only inspect the
// boundary (at most three continuation bytes), not the entire output buffer.
fn frame_chunk_len(kind: u8, bytes: &[u8]) -> usize {
    let limit = if matches!(kind, 1 | 2) { 64 * 1024 } else { MAX_FIELD };
    if bytes.len() <= limit { return bytes.len(); }
    let mut end = limit;
    while end > limit - 3 && bytes[end] & 0xc0 == 0x80 {
        end -= 1;
    }
    if bytes[end] & 0xc0 == 0x80 {
        // Arbitrary byte output must still make progress without losing data.
        limit
    } else {
        end
    }
}

fn output_frame(kind: u8, bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + bytes.len());
    frame.push(kind);
    frame.extend((bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

impl Connection {
    fn close(&self) {
        self.peer.close();
        self.output.close();
        if let Some(reply) = self.prompt.lock().unwrap().take() {
            reply.complete(Err(io::ErrorKind::ConnectionAborted.into()));
        }
    }

    async fn frame(&self, kind: u8, bytes: &[u8]) -> io::Result<()> {
        let mut remaining = bytes;
        loop {
            let count = frame_chunk_len(kind, remaining);
            let (chunk, rest) = remaining.split_at(count);
            self.output.enqueue(output_frame(kind, chunk)).await?;
            if rest.is_empty() { return Ok(()); }
            remaining = rest;
        }
    }

    async fn finish_request(
        &self,
        request: impl Future<Output = io::Result<()>>,
        control: Option<crate::pipeline::RequestHandle<()>>,
        output: crate::pipeline::RequestHandle<()>,
    ) -> io::Result<()> {
        let result = cli::settle_unwind(request).await;
        // main flushes output in finally, including a failed request. Keep
        // control reads alive during drain so disconnect cancels blocked IO.
        let _ = self.output.drain().await;
        self.finishing.store(true, Ordering::Release);
        self.close();
        if let Some(control) = control { control.wait().await; }
        output.wait().await;
        match result { Ok(result) => result, Err(panic) => std::panic::resume_unwind(panic) }
    }

    async fn pump_output(&self) {
        let _close = CloseOutput(&self.output);
        while let Some(frame) = self.output.next().await {
            let acknowledge = OutputFrame(&self.output);
            let result = self.peer.write_all(frame).await;
            drop(acknowledge);
            if result.is_err() {
                self.cancel.cancel();
                self.close();
                return;
            }
        }
    }

    async fn read_control(&self, cwd: &Path) -> io::Result<()> {
        loop {
            match read_word(&self.peer).await? {
                RESIZE if self.flags & 10 == 10 => {
                    let size = encode_terminal_size(read_word(&self.peer).await?, read_word(&self.peer).await?)
                        .ok_or(io::ErrorKind::InvalidData)?;
                    self.terminal_size.store(size, Ordering::Relaxed);
                }
                CANCEL => {
                    if !self.cancel.cancelled() {
                        self.cancel.cancel();
                        self.prompt.lock().unwrap().take();
                        let language = config::load_language(cwd);
                        let message = format!("{}\n", language.text("interrupt.stopping"));
                        // Like main, reserve the one cancellation notice even
                        // while ordinary producers are waiting on output space.
                        self.output.try_enqueue(output_frame(Stream::Err as u8, message.as_bytes()), true)?;
                    }
                }
                length => {
                    let reply = self.prompt.lock().unwrap().take();
                    let Some(reply) = reply else {
                        return if self.cancel.cancelled() { Ok(()) } else { Err(io::ErrorKind::InvalidData.into()) };
                    };
                    reply.complete(read_peer_field(&self.peer, length as usize).await);
                }
            }
        }
    }

    async fn read_prompt_chunk(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(reply) = PromptReply::new(&self.prompt, &self.cancel)? else { return Ok(None); };
        self.frame(3, &[]).await?;
        self.output.drain().await?;
        reply.reply.wait().await.map(Some)
    }

    async fn read_line_async(&self, prompt: &str) -> io::Result<Option<String>> {
        if !prompt.is_empty() { self.frame(Stream::Out as u8, prompt.as_bytes()).await?; }
        loop {
            if self.cancel.cancelled() { return Ok(None); }
            {
                let mut input = self.input.lock().unwrap();
                if let Some(line) = input.line() { return Ok(Some(line)); }
                if input.eof { return Ok(None); }
            }
            let Some(chunk) = self.read_prompt_chunk().await? else { return Ok(None); };
            self.input.lock().unwrap().push(chunk)?;
        }
    }
}
impl Session for Connection {
    fn write(&self, stream: Stream, data: &[u8]) -> io::Result<()> {
        if self.output.closed() { return Ok(()); }
        if !in_control_poll() { return block_on(self.awrite(stream, data)); }
        let mut remaining = data;
        loop {
            let count = frame_chunk_len(stream as u8, remaining);
            let (chunk, rest) = remaining.split_at(count);
            self.output.try_enqueue(output_frame(stream as u8, chunk), false)?;
            if rest.is_empty() { return Ok(()); }
            remaining = rest;
        }
    }
    fn awrite<'a>(&'a self, stream: Stream, data: &'a [u8]) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.output.closed() { return Ok(()); }
            let result = self.frame(stream as u8, data).await;
            if self.output.closed() { Ok(()) } else { result }
        })
    }
    fn drain(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> { Box::pin(self.output.drain()) }
    fn read_line(&self, prompt: &str) -> io::Result<Option<String>> { block_on(self.read_line_async(prompt)) }
    fn aread_line<'a>(&'a self, prompt: &'a str) -> Pin<Box<dyn Future<Output = io::Result<Option<String>>> + Send + 'a>> {
        Box::pin(self.read_line_async(prompt))
    }
    fn interactive(&self) -> bool { self.flags & 2 != 0 }
    fn input_is_terminal(&self) -> bool { self.flags & 4 != 0 }
    fn unicode(&self) -> bool { self.flags & 16 != 0 }
    fn terminal_size(&self) -> (usize, usize) {
        let size = self.terminal_size.load(Ordering::Relaxed);
        ((size & 0xffff) as usize, (size >> 16) as usize)
    }
}
struct CloseOutput<'a>(&'a output::Output);
impl Drop for CloseOutput<'_> { fn drop(&mut self) { self.0.close(); } }
struct OutputFrame<'a>(&'a output::Output);
impl Drop for OutputFrame<'_> { fn drop(&mut self) { self.0.acknowledge(); } }
struct CloseConnection(Arc<Connection>);
impl Drop for CloseConnection { fn drop(&mut self) { self.0.close(); } }

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
    shutdown: Cancellation,
    io: transport::Reactor,
    token: [u8; 32],
    build_id: [u8; 16],
}

/// Each connection owns its active count even if thread creation is rejected
/// (the unstarted closure is dropped), or request execution unwinds.
struct ActiveRequest(Arc<Server>);

impl ActiveRequest {
    fn new(server: Arc<Server>) -> Self {
        server.activity.lock().unwrap().active += 1;
        Self(server)
    }

}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        let mut activity = self.0.activity.lock().unwrap();
        activity.active -= 1;
        if activity.active == 0 {
            activity.last_idle = Instant::now();
            self.0.drained.notify_all();
        }
        drop(activity);
        self.0.wake.signal();
    }
}

impl Server {
    fn submit(self: &Arc<Self>, pipe: OwnedHandle) -> crate::pipeline::RequestHandle<io::Result<()>> {
        let activity = ActiveRequest::new(Arc::clone(self));
        let handler = Arc::clone(self);
        let cancel = Cancellation::new();
        let request = self.host.scheduler.submit(self.host.scheduler.next_id(), Origin::Foreground, &cancel.clone(),
            move |spawner| Box::pin(async move { handler.request(pipe, spawner, cancel).await }));
        // Connection lifetime includes output/control and CLI cleanup, like the
        // protocol's on_closed callback after its owned work finishes.
        request.on_ready(move || drop(activity));
        request
    }

    async fn request(self: &Arc<Self>, pipe: OwnedHandle, spawner: crate::pipeline::scheduling::Spawner<'static>, cancel: Cancellation) -> io::Result<()> {
        let peer = self.io.bind(pipe, &self.shutdown)?;
        let header = Header::read(&peer, &self.build_id, &self.token).await?;
        let connection = Arc::new(Connection {
            peer, output: output::Output::default(), prompt: Mutex::default(), input: Mutex::default(),
            cancel: cancel.clone(), finishing: AtomicBool::new(false),
            terminal_size: AtomicU32::new(header.terminal_size), flags: header.flags,
        });
        let _close = CloseConnection(Arc::clone(&connection));
        let output = {
            let connection = Arc::clone(&connection);
            spawner.spawn(Box::pin(async move { connection.pump_output().await }))
        };
        let control = if header.flags & 1 == 0 {
            let connection = Arc::clone(&connection);
            let cwd = header.cwd.clone();
            Some(spawner.spawn(Box::pin(async move {
                if connection.read_control(&cwd).await.is_err() {
                    if !connection.finishing.load(Ordering::Acquire) { connection.cancel.cancel(); }
                    connection.close();
                }
            })))
        } else { None };
        connection.finish_request(async {
            connection.output.enqueue([b"SPS2".as_slice(), &self.build_id].concat()).await?;
            if header.flags & 1 != 0 {
                connection.frame(0, &0_i32.to_be_bytes()).await?;
                connection.output.drain().await?;
                self.activity.lock().unwrap().shutting_down = true;
                self.shutdown.cancel();
                self.wake.signal();
                return Ok(());
            }
            let session: Arc<dyn Session> = connection.clone();
            let result = cli::run(&self.host, &header.cwd, header.argv, session, cancel).await;
            let code = match result {
                Ok(code) => code,
                Err(error) => {
                    let _ = connection.awrite(Stream::Err, format!("{error}\n").as_bytes()).await;
                    3
                }
            };
            connection.frame(0, &code.to_be_bytes()).await?;
            connection.output.drain().await
        }, control, output).await
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
        shutdown: Cancellation::new(),
        io: transport::Reactor::new()?,
        token,
        build_id,
    });
    let ready_name = windows::wide(OsStr::new(&format!("Global\\SunPack-{identity}-ready")));
    let ready = unsafe { CreateEventW(std::ptr::null(), 1, 0, ready_name.as_ptr()) };
    if ready.is_null() {
        return Err(io::Error::last_os_error());
    }
    let ready = unsafe { OwnedHandle::from_raw_handle(ready) };
    if let Ok(settings) = config::load(cwd) {
        server.host.configure_idle(&settings);
    }
    let result = (|| {
        let mut accept = Accept::arm(&name_wide, &security, true)?;
        // Publish only an already-listening endpoint, then wake startup clients.
        state.publish(&name, &server.token, &server.build_id, &stamp)?;
        if unsafe { SetEvent(ready.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
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
                            server.submit(peer);
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
    server.shutdown.cancel();
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

#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn output_frames_keep_utf8_boundaries_and_binary_payloads() {
        // Ordinary short-output tests never cross the protocol limit. Check
        // every possible split inside a UTF-8 scalar with one reusable buffer.
        let limit = 64 * 1024;
        let mut bytes = Vec::with_capacity(limit + 4);
        for scalar in ["é", "中", "😀"] {
            for split in 1..scalar.len() {
                bytes.clear();
                bytes.resize(limit - split, b'a');
                bytes.extend_from_slice(scalar.as_bytes());
                bytes.push(b'\n');
                for kind in [1, 2] {
                    let end = frame_chunk_len(kind, &bytes);
                    assert_eq!(end, limit - split);
                    let (first, rest) = bytes.split_at(end);
                    assert!(std::str::from_utf8(first).is_ok());
                    assert_eq!(std::str::from_utf8(rest).unwrap(), format!("{scalar}\n"));
                    assert_eq!(frame_chunk_len(kind, rest), rest.len());
                }
                // Control payloads are binary, never interpreted as text.
                assert_eq!(frame_chunk_len(0, &bytes), bytes.len());
            }
        }
        bytes.fill(0x80);
        assert_eq!(frame_chunk_len(1, &bytes), limit);
        assert_eq!(frame_chunk_len(2, &[]), 0);
        assert_eq!(frame_chunk_len(0, &(-1_i32).to_be_bytes()), 4);
        assert_eq!(frame_chunk_len(3, &[]), 0);
    }
}


#[cfg(test)]
mod async_connection_tests {
    use super::*;
    use std::sync::mpsc;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    fn server() -> Arc<Server> {
        Arc::new(Server {
            host: Host::new(), activity: Mutex::new(Activity { last_idle: Instant::now(), active: 0, shutting_down: false }),
            drained: Condvar::new(), wake: Arc::new(Event::new(false).unwrap()),
            shutdown: Cancellation::new(), io: transport::Reactor::new().unwrap(), token: [0; 32], build_id: [0; 16],
        })
    }
    fn pipe_pair() -> (File, OwnedHandle) {
        let name = format!(r"\\.\pipe\SunPack-connection-test-{}-{}", std::process::id(), hex(&windows::random_bytes::<16>().unwrap()));
        let security = windows::PipeSecurity::current_user().unwrap();
        let accept = Accept::arm(&windows::wide(OsStr::new(&name)), &security.attributes(), true).unwrap();
        let client = OpenOptions::new().read(true).write(true).open(name).unwrap();
        assert_eq!(unsafe { WaitForSingleObject(accept.event.raw(), INFINITE) }, WAIT_OBJECT_0);
        (client, accept.finish().unwrap())
    }
    fn connect(server: &Arc<Server>) -> (File, crate::pipeline::RequestHandle<io::Result<()>>) {
        let (client, peer) = pipe_pair();
        (client, server.submit(peer))
    }
    fn help_request(server: &Server) -> Vec<u8> {
        let cwd = std::env::current_dir().unwrap().to_string_lossy().into_owned();
        let mut bytes = [b"SPK2".as_slice(), &server.build_id, &server.token].concat();
        for word in [0, cwd.len() as u32, 1] { bytes.extend(word.to_be_bytes()); }
        bytes.extend(cwd.as_bytes());
        bytes.extend(6_u32.to_be_bytes());
        bytes.extend(b"--help");
        bytes
    }

    #[test]
    fn incomplete_and_invalid_connections_do_not_block_a_live_cli_or_stop_service() {
        let server = server();
        let mut held = Vec::new();
        for _ in 0..64 {
            let (mut client, request) = connect(&server);
            client.write_all(b"S").unwrap();
            held.push((client, request));
        }
        let (mut invalid, rejected) = connect(&server);
        invalid.write_all(&[0; 52]).unwrap();
        assert_eq!(rejected.join().unwrap().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(!server.activity.lock().unwrap().shutting_down);
        let (mut client, healthy) = connect(&server);
        client.write_all(&help_request(&server)).unwrap();
        let (finished, ready) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = (|| -> io::Result<i32> {
                let mut handshake = [0; 20];
                client.read_exact(&mut handshake)?;
                assert_eq!(&handshake[..4], b"SPS2");
                loop {
                    let mut kind = [0];
                    client.read_exact(&mut kind)?;
                    let length = read_u32(&mut client)? as usize;
                    let bytes = read_field(&mut client, length)?;
                    if kind[0] == 0 { return Ok(i32::from_be_bytes(bytes.try_into().unwrap())); }
                }
            })();
            finished.send((client, result)).unwrap();
        });
        let response = ready.recv_timeout(Duration::from_secs(10));
        if response.is_err() { server.shutdown.cancel(); }
        reader.join().unwrap();
        let (_client, code) = response.expect("incomplete clients consumed CLI execution capacity");
        assert_eq!(code.unwrap(), 0);
        healthy.join().unwrap().unwrap();
        server.shutdown.cancel();
        for (_client, request) in held { assert!(request.join().unwrap().is_err()); }
        let activity = server.drained.wait_while(server.activity.lock().unwrap(), |state| state.active != 0).unwrap();
        assert!(!activity.shutting_down);
    }

    #[test]
    fn real_prompt_resize_cancel_and_panic_flush_settle_all_connection_work() {
        let server = server();
        let (mut client, pipe) = pipe_pair();
        let connection = Arc::new(Connection {
            peer: server.io.bind(pipe, &server.shutdown).unwrap(),
            output: output::Output::default(), prompt: Mutex::default(), input: Mutex::default(),
            cancel: Cancellation::new(), finishing: AtomicBool::new(false),
            terminal_size: AtomicU32::new(80 | 24 << 16), flags: 14,
        });
        let cancel = connection.cancel.clone();
        let request = server.host.scheduler.submit(server.host.scheduler.next_id(), Origin::Foreground, &cancel,
            move |spawner| Box::pin(async move {
                let _close = CloseConnection(connection.clone());
                let writer = connection.clone();
                let output = spawner.spawn(Box::pin(async move { writer.pump_output().await }));
                let reader = connection.clone();
                let control = spawner.spawn(Box::pin(async move {
                    if reader.read_control(&std::env::current_dir().unwrap()).await.is_err() { reader.close(); }
                }));
                connection.finish_request(async {
                    assert_eq!(connection.read_line_async("first").await?.as_deref(), Some("answer\r\n"));
                    assert_eq!(connection.terminal_size(), (120, 40));
                    assert_eq!(connection.read_line_async("second").await?, None);
                    connection.awrite(Stream::Out, b"queued-before-panic").await?;
                    panic!("request failure after enqueue");
                }, Some(control), output).await
            }));
        let (finished, ready) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut frames = Vec::new();
            let mut prompts = 0;
            let result = (|| -> io::Result<()> {
                loop {
                    let mut kind = [0];
                    if client.read_exact(&mut kind).is_err() { return Ok(()); }
                    let length = read_u32(&mut client)? as usize;
                    let bytes = read_field(&mut client, length)?;
                    if kind[0] == 3 {
                        prompts += 1;
                        if prompts == 1 {
                            for word in [RESIZE, 120, 40, 8] { client.write_all(&word.to_be_bytes())?; }
                            client.write_all(b"answer\r\n")?;
                        } else { client.write_all(&CANCEL.to_be_bytes())?; }
                    }
                    frames.push((kind[0], bytes));
                }
            })();
            finished.send((result, prompts, frames)).unwrap();
        });
        let response = ready.recv_timeout(Duration::from_secs(10));
        if response.is_err() { server.shutdown.cancel(); }
        reader.join().unwrap();
        let (result, prompts, frames) = response.expect("prompt/cancel or panic teardown stalled");
        result.unwrap();
        assert_eq!(prompts, 2);
        let notice = frames.iter().position(|(kind, _)| *kind == Stream::Err as u8).unwrap();
        let final_output = frames.iter().position(|(_, data)| data == b"queued-before-panic").unwrap();
        assert!(notice < final_output);
        assert!(request.join().is_err());
    }

    #[test]
    fn async_prompt_is_first_wins_and_old_waiter_cannot_remove_new_prompt() {
        let slot = Mutex::default();
        let cancel = Cancellation::new();
        let first = PromptReply::new(&slot, &cancel).unwrap().unwrap();
        assert!(PromptReply::new(&slot, &Cancellation::new()).is_err());
        let partial_reply = slot.lock().unwrap().take().unwrap();
        let next_cancel = Cancellation::new();
        let next = PromptReply::new(&slot, &next_cancel).unwrap().unwrap();
        cancel.cancel();
        assert!(block_on(first.reply.wait()).unwrap().is_empty());
        partial_reply.complete(Ok(b"late".to_vec()));
        drop(first);
        assert!(slot.lock().unwrap().as_ref().is_some_and(|reply| Arc::ptr_eq(reply, &next.reply)));
        next.reply.complete(Ok(b"yes".to_vec()));
        next_cancel.cancel();
        assert_eq!(block_on(next.reply.wait()).unwrap(), b"yes");
        drop(next);
        assert!(slot.lock().unwrap().is_none());
        assert!(PromptReply::new(&slot, &next_cancel).unwrap().is_none());
    }
}
