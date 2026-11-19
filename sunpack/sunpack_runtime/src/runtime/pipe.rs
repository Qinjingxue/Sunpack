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
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    LockFileEx, UnlockFileEx, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
    FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, WaitNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const MAX_FIELD: usize = 16 * 1024 * 1024;
const TERMINAL_SIZE_FIELD: u32 = 32;
const RESIZE: u32 = u32::MAX - 1;
const CANCEL: u32 = u32::MAX;

#[cfg(test)]
thread_local! {
    static PIPE_BUSY: std::cell::Cell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::Cell::new(None) };
}

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
    lock: File,
}

impl StateFile {
    fn acquire(path: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(path.parent().unwrap())?;
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(lock_path)?;
        let lock_range = |offset, flags| {
            let mut range = OVERLAPPED::default();
            range.Anonymous.Anonymous.Offset = offset;
            if unsafe { LockFileEx(lock.as_raw_handle(), flags, 0, 1, 0, &mut range) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        // An unreadable endpoint must not make a second launcher wait for a
        // live listener. After it closes, wait for the old owner's log and
        // state file to finish before opening a replacement.
        lock_range(0, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)?;
        lock_range(1, LOCKFILE_EXCLUSIVE_LOCK)?;
        Ok(Self { path, lock })
    }

    fn stop_accepting(&self) -> io::Result<()> {
        let mut listener = OVERLAPPED::default();
        if unsafe { UnlockFileEx(self.lock.as_raw_handle(), 0, 1, 0, &mut listener) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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

#[derive(Default)]
struct PipeReader {
    // Keep bytes already fetched after the last argument for the control stream.
    buffer: Vec<u8>,
    unread: std::ops::Range<usize>,
}

impl PipeReader {
    async fn take(&mut self, peer: &transport::Peer, limit: usize) -> io::Result<&[u8]> {
        if self.unread.is_empty() {
            if self.buffer.is_empty() {
                self.buffer.resize(8192, 0);
            }
            let (buffer, bytes) = peer.read_some(std::mem::take(&mut self.buffer)).await?;
            self.buffer = buffer;
            self.unread = 0..bytes;
        }
        let start = self.unread.start;
        self.unread.start += limit.min(self.unread.len());
        Ok(&self.buffer[start..self.unread.start])
    }

    async fn fixed<const N: usize>(&mut self, peer: &transport::Peer) -> io::Result<[u8; N]> {
        let mut result = [0; N];
        let mut offset = 0;
        while offset < N {
            let chunk = self.take(peer, N - offset).await?;
            result[offset..offset + chunk.len()].copy_from_slice(chunk);
            offset += chunk.len();
        }
        Ok(result)
    }

    async fn word(&mut self, peer: &transport::Peer) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.fixed(peer).await?))
    }

    async fn field(&mut self, peer: &transport::Peer, length: usize) -> io::Result<Vec<u8>> {
        if length > MAX_FIELD {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut result = Vec::new();
        while result.len() < length {
            result.extend_from_slice(self.take(peer, length - result.len()).await?);
        }
        Ok(result)
    }
}

impl Header {
    async fn read(reader: &mut PipeReader, peer: &transport::Peer, build_id: &[u8; 16], token: &[u8; 32]) -> io::Result<Self> {
        let header = reader.fixed::<64>(peer).await?;
        if &header[..4] != b"SPK2" || &header[4..20] != build_id || &header[20..52] != token {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let flags = u32::from_be_bytes(header[52..56].try_into().unwrap());
        let cwd_len = u32::from_be_bytes(header[56..60].try_into().unwrap()) as usize;
        let argc = u32::from_be_bytes(header[60..64].try_into().unwrap());
        let cwd = PathBuf::from(String::from_utf8(reader.field(peer, cwd_len).await?).map_err(io::Error::other)?);
        if !cwd.is_absolute() { return Err(io::ErrorKind::InvalidInput.into()); }
        let mut argv = Vec::new();
        let mut terminal_size = 80 | 24 << 16;
        for index in 0..argc {
            let size = reader.word(peer).await? as usize;
            let arg = String::from_utf8(reader.field(peer, size).await?).map_err(io::Error::other)?;
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
    prompt: Mutex<Option<Arc<Reply<Vec<u8>>>>>,
    input: Mutex<PromptInput>,
    cancel: Cancellation,
    finishing: AtomicBool,
    language: std::sync::OnceLock<crate::core::i18n::Language>,
    terminal_size: AtomicU32,
    flags: u32,
}

struct PromptReply<'a> {
    slot: &'a Mutex<Option<Arc<Reply<Vec<u8>>>>>,
    reply: Arc<Reply<Vec<u8>>>,
    _cancellation: Option<crate::io::cancellation::Subscription>,
}
impl<'a> PromptReply<'a> {
    fn new(slot: &'a Mutex<Option<Arc<Reply<Vec<u8>>>>>, cancel: &Cancellation) -> io::Result<Option<Self>> {
        let reply = Arc::new(Reply::default());
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
        let mut slot = self.slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if end == unread.len() && self.bytes.capacity() > 64 * 1024 {
            let mut bytes = std::mem::take(&mut self.bytes);
            if self.start != 0 {
                bytes.copy_within(self.start.., 0);
                bytes.truncate(end);
            }
            self.start = 0;
            self.searched = 0;
            return Some(String::from_utf8(bytes).unwrap_or_else(|error|
                String::from_utf8_lossy(error.as_bytes()).into_owned()));
        }
        let line = String::from_utf8_lossy(&unread[..end]).into_owned();
        self.start += end;
        self.searched = self.start;
        Some(line)
    }

    fn push(&mut self, chunk: Vec<u8>) -> io::Result<()> {
        if self.start != 0 {
            self.bytes.copy_within(self.start.., 0);
            self.bytes.truncate(self.bytes.len() - self.start);
            self.searched -= self.start;
            self.start = 0;
        }
        self.eof = chunk.is_empty();
        if self.bytes.is_empty() && self.bytes.capacity() < chunk.len() {
            self.bytes = chunk;
        } else {
            self.bytes.try_reserve(chunk.len()).map_err(|error|
                io::Error::new(io::ErrorKind::OutOfMemory, error))?;
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
        // Closing discards the prompt; it is safe even after its owner panicked.
        let reply = self.prompt.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(reply) = reply {
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
        if result.is_err() && !self.finishing.swap(true, Ordering::AcqRel) {
            // Keep queued output ahead of the terminal status, as on normal exit.
            let _ = self.frame(0, &1_i32.to_be_bytes()).await;
        }
        // main flushes output in finally, including a failed request. Keep
        // control reads alive during drain so disconnect cancels blocked IO.
        self.output.drain().await;
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
            if result.is_err() {
                self.cancel.cancel();
                self.close();
                return;
            }
            drop(acknowledge);
        }
    }

    async fn read_control(&self, mut reader: PipeReader) -> io::Result<()> {
        loop {
            match reader.word(&self.peer).await? {
                RESIZE if self.flags & 10 == 10 => {
                    let size = encode_terminal_size(reader.word(&self.peer).await?, reader.word(&self.peer).await?)
                        .ok_or(io::ErrorKind::InvalidData)?;
                    self.terminal_size.store(size, Ordering::Relaxed);
                }
                CANCEL => {
                    if !self.cancel.cancelled() {
                        let language = self.language.get().copied().unwrap_or_default();
                        let message = format!("{}\n", language.text("interrupt.stopping"));
                        // Like main, reserve the one cancellation notice even
                        // while ordinary producers are waiting on output space.
                        // Publish it before cancellation wakes request tasks
                        // that can immediately print the final interrupt result.
                        let notice = self.output.try_enqueue(output_frame(Stream::Err as u8, message.as_bytes()), true);
                        self.cancel.cancel();
                        self.prompt.lock().unwrap().take();
                        notice?;
                    }
                }
                length => {
                    let reply = self.prompt.lock().unwrap().take();
                    let Some(reply) = reply else {
                        return if self.cancel.cancelled() { Ok(()) } else { Err(io::ErrorKind::InvalidData.into()) };
                    };
                    reply.complete(reader.field(&self.peer, length as usize).await);
                }
            }
        }
    }

    async fn read_prompt_chunk(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(reply) = PromptReply::new(&self.prompt, &self.cancel)? else { return Ok(None); };
        self.frame(3, &[]).await?;
        // The output pump runs independently. The launcher can answer only
        // after receiving the prompt frame in FIFO order.
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
    fn set_language(&self, language: crate::core::i18n::Language) {
        let _ = self.language.set(language);
    }

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
    fn drain(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async { self.output.drain().await; Ok(()) })
    }
    fn read_line(&self, prompt: &str) -> io::Result<Option<String>> { block_on(self.read_line_async(prompt)) }
    fn aread_line<'a>(&'a self, prompt: &'a str) -> Pin<Box<dyn Future<Output = io::Result<Option<String>>> + Send + 'a>> {
        Box::pin(self.read_line_async(prompt))
    }
    fn interactive(&self) -> bool { self.flags & 2 != 0 }
    fn input_is_terminal(&self) -> bool { self.flags & 4 != 0 }
    fn pause_on_exit<'a>(&'a self, _prompt: &'a str) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        // The launcher owns exit interaction even when startup/delivery fails.
        // Console sessions retain the direct-runtime CLI pause policy.
        Box::pin(async { Ok(()) })
    }
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

#[derive(Default)]
struct Activity {
    last_completed: Option<Instant>,
    last_cache_use: Option<Instant>,
    active: usize,
    observers: usize,
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

/// Count connections until their owned work has drained, including an unwind.
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
            self.0.drained.notify_all();
        }
        drop(activity);
        self.0.wake.signal();
    }
}

// Status streams participate in shutdown draining, but are not foreground work
// and must not keep an otherwise idle runtime alive.
struct StatusObserver(Arc<Server>);
impl StatusObserver {
    fn new(server: &Arc<Server>) -> Self {
        server.activity.lock().unwrap().observers += 1;
        server.wake.signal();
        Self(Arc::clone(server))
    }
}
impl Drop for StatusObserver {
    fn drop(&mut self) {
        self.0.activity.lock().unwrap().observers -= 1;
        self.0.wake.signal();
    }
}

impl Server {
    fn submit(self: &Arc<Self>, pipe: OwnedHandle) -> crate::pipeline::RequestHandle<io::Result<()>> {
        let connected = Instant::now();
        let activity = ActiveRequest::new(Arc::clone(self));
        let handler = Arc::clone(self);
        let cancel = Cancellation::new();
        let prepared = match self.host.scheduler.prepare_submit() {
            Ok(prepared) => prepared,
            Err(error) => return crate::pipeline::scheduling::Join::ready(Err(error)),
        };
        let request = prepared.submit(self.host.scheduler.next_id(), Origin::Foreground, &cancel.clone(),
            move |spawner| Box::pin(async move { handler.request(pipe, spawner, cancel, connected).await }));
        // Connection lifetime includes output/control and CLI cleanup, like the
        // protocol's on_closed callback after its owned work finishes.
        request.on_ready(move || drop(activity));
        request
    }

    async fn request(self: &Arc<Self>, pipe: OwnedHandle, spawner: crate::pipeline::scheduling::Spawner<'static>, cancel: Cancellation, connected: Instant) -> io::Result<()> {
        let peer = self.io.bind(pipe, &self.shutdown)?;
        let mut reader = PipeReader::default();
        let header = Header::read(&mut reader, &peer, &self.build_id, &self.token).await?;
        let connection = Arc::new(Connection {
            peer, output: output::Output::default(), prompt: Mutex::default(), input: Mutex::default(),
            cancel: cancel.clone(), finishing: AtomicBool::new(false), language: Default::default(),
            terminal_size: AtomicU32::new(header.terminal_size), flags: header.flags,
        });
        let _close = CloseConnection(Arc::clone(&connection));
        let output = {
            let connection = Arc::clone(&connection);
            spawner.spawn(Box::pin(async move { connection.pump_output().await }))
        };
        let control = if header.flags & 1 == 0 {
            let connection = Arc::clone(&connection);
            Some(spawner.spawn(Box::pin(async move {
                if connection.read_control(reader).await.is_err()
                    && !connection.finishing.load(Ordering::Acquire)
                {
                    connection.cancel.cancel();
                    connection.close();
                }
            })))
        } else { None };
        let mut served_cli = false;
        let result = connection.finish_request(async {
            connection.output.enqueue([b"SPS2".as_slice(), &self.build_id].concat()).await?;
            if header.flags & 1 != 0 {
                connection.finishing.store(true, Ordering::Release);
                connection.frame(0, &0_i32.to_be_bytes()).await?;
                connection.output.drain().await;
                self.activity.lock().unwrap().shutting_down = true;
                self.shutdown.cancel();
                self.wake.signal();
                return Ok(());
            }
            if header.argv.as_slice() == ["--watch-status-follow"] {
                let _observer = StatusObserver::new(self);
                loop {
                    cancel.check_io()?;
                    crate::pipeline::stage("cli", &cancel).await?;
                    let revision = self.host.watch.status_revision();
                    let status = self.host.watch.status(&header.cwd)?;
                    let mut line = serde_json::to_vec(&status).map_err(io::Error::other)?;
                    line.push(b'\n');
                    connection.awrite(Stream::Out, &line).await?;
                    self.host.watch.wait_status_change(revision, &cancel).await?;
                }
            }
            let started = Instant::now();
            let foreground = header.argv.first().is_none_or(|command| command != "--cancel-watch-batch");
            if foreground { super::diagnostics::event("foreground_request_started", || serde_json::json!({"origin":"foreground","command":header.argv.first(),"queue_ms":connected.elapsed().as_secs_f64()*1000.0})); }
            let session: Arc<dyn Session> = connection.clone();
            served_cli = true;
            let code = match cli::run(&self.host, &header.cwd, header.argv, session, cancel).await {
                Ok(code) => code,
                Err(error) => {
                    crate::pipeline::stage("cli", &Cancellation::new()).await?;
                    let message = config::load_language(&header.cwd)
                        .translate("cli.persistent_request_failed", &[("error", &error.to_string())]);
                    connection.awrite(Stream::Err, format!("{message}\n").as_bytes()).await?;
                    1
                }
            };
            if foreground { super::diagnostics::event("foreground_request_finished", || serde_json::json!({"origin":"foreground","exit_code":code,"duration_ms":started.elapsed().as_secs_f64()*1000.0})); }
            // The launcher closes as soon as it reads the status frame. Its
            // control EOF can arrive before the completed write is observed.
            connection.finishing.store(true, Ordering::Release);
            connection.frame(0, &code.to_be_bytes()).await?;
            connection.output.drain().await;
            if connection.output.closed() {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            Ok(())
        }, control, output).await;
        if served_cli {
            let mut activity = self.activity.lock().unwrap();
            let now = Instant::now();
            activity.last_cache_use = Some(now);
            if result.is_ok() {
                activity.last_completed = Some(now);
            }
        }
        result
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
    let state = StateFile::acquire(state_path(cwd, identity)?)?;
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
    let settings = config::load(cwd).ok();
    let retention = settings.as_ref().map_or(7, |settings| settings.watch.event_log_retention_days);
    let mut log_path = state.path.as_os_str().to_owned();
    log_path.push(".events.json");
    let log = super::diagnostics::Log::open(log_path.into(), retention, &host.watch)?;
    let server = Arc::new(Server {
        host,
        wake,
        activity: Mutex::default(),
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
    if let Some(settings) = settings {
        server.host.configure_idle(&settings);
    }
    let result = (|| {
        let mut accept = Accept::arm(&name_wide, &security, true)?;
        // Publish only an already-listening endpoint, then wake startup clients.
        state.publish(&name, &server.token, &server.build_id, &stamp)?;
        if unsafe { SetEvent(ready.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            let (exit_wait, cache_wait, shutting_down) = {
                let state = server.activity.lock().unwrap();
                // A live Watch schedules the same engine cache cleanup.
                let (exit, caches) = if state.active == state.observers && !server.host.watch.is_running() {
                    let policy = server.host.idle_policy();
                    (
                        state.last_completed.zip(policy.exit)
                            .map_or(INFINITE, |(completed, idle)| idle_wait(completed, idle)),
                        state.last_cache_use.zip(policy.caches)
                            .map_or(INFINITE, |(used, idle)| idle_wait(used, idle)),
                    )
                } else {
                    (INFINITE, INFINITE)
                };
                (exit, caches, state.shutting_down || server.host.watch.shutdown_requested())
            };
            if shutting_down {
                break;
            }
            let handles = [accept.event.raw(), server.wake.raw()];
            match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, exit_wait.min(cache_wait)) } {
                WAIT_OBJECT_0 => {
                    let connected = accept.finish();
                    accept = Accept::arm(&name_wide, &security, false)?;
                    match connected {
                        Ok(peer) => {
                            server.submit(peer);
                        }
                        Err(error) if matches!(error.raw_os_error(), Some(109 | 232 | 233)) => {}
                        Err(error) => return Err(error),
                    }
                }
                WAIT_TIMEOUT if exit_wait == 0 => break,
                WAIT_TIMEOUT if cache_wait == 0 => {
                    server.activity.lock().unwrap().last_cache_use = None;
                    server.host.clear_idle_caches();
                }
                WAIT_TIMEOUT => {}
                value if value == WAIT_OBJECT_0 + 1 => {}
                _ => return Err(io::Error::last_os_error()),
            }
        }
        state.stop_accepting()
    })();
    if result.is_err() {
        let _ = state.stop_accepting();
    }
    let exit_reason = if result.is_err() {
        "error"
    } else if server.activity.lock().unwrap().shutting_down || server.host.watch.shutdown_requested() {
        "cli_shutdown"
    } else {
        "idle_timeout"
    };
    super::diagnostics::event("host_stopping", || serde_json::json!({"foreground_requests":server.activity.lock().unwrap().active,"exit_reason":exit_reason}));
    server.shutdown.cancel();
    if server.host.watch.is_running() {
        let _ = server.host.watch.stop();
    }
    let _drained = server
        .drained
        .wait_while(server.activity.lock().unwrap(), |state| state.active != 0)
        .unwrap();
    drop(_drained);
    log.finish(exit_reason);
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
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    let mut pipe = loop {
        let error = match options.open(name) {
            Ok(pipe) => break pipe,
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                #[cfg(test)]
                PIPE_BUSY.with(|signal| {
                    if let Some(signal) = signal.take() { let _ = signal.send(()); }
                });
                let name = windows::wide(OsStr::new(name));
                if unsafe { WaitNamedPipeW(name.as_ptr(), INFINITE) } != 0 {
                    continue;
                }
                io::Error::last_os_error()
            }
            Err(error) => error,
        };
        return if error.kind() == io::ErrorKind::NotFound { Ok(None) } else { Err(error) };
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
#[path = "../../tests/unit/runtime/pipe/frame_tests.rs"]
mod frame_tests;


#[cfg(test)]
#[path = "../../tests/unit/runtime/pipe/async_connection_tests.rs"]
mod async_connection_tests;
