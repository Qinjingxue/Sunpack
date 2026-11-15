//! One completion port for all persistent connections. Kernel-owned buffers
//! remain registered until completion, including cancellation and dropped waits.
use super::super::cli::reporting::Reply;
use crate::pipeline::Cancellation;
use crate::io::cancellation::Subscription;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus, OVERLAPPED};
use windows_sys::Win32::System::Threading::INFINITE;

fn closed() -> io::Error { io::ErrorKind::ConnectionAborted.into() }

pub(super) struct Reactor {
    state: Arc<State>,
    thread: Option<std::thread::JoinHandle<()>>,
}
struct State {
    port: OwnedHandle,
    pending: Mutex<Pending>,
}
#[derive(Default)]
struct Pending {
    closed: bool,
    operations: HashMap<usize, Arc<Transfer>>,
}

impl Reactor {
    pub(super) fn new() -> io::Result<Self> {
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
        if port.is_null() { return Err(io::Error::last_os_error()); }
        let state = Arc::new(State {
            port: unsafe { OwnedHandle::from_raw_handle(port) },
            pending: Mutex::default(),
        });
        let worker = Arc::clone(&state);
        let thread = std::thread::Builder::new().name("sunpack-pipe-completions".into())
            .spawn(move || worker.run())?;
        Ok(Self { state, thread: Some(thread) })
    }

    pub(super) fn bind(&self, pipe: OwnedHandle, shutdown: &Cancellation) -> io::Result<Peer> {
        if self.state.pending.lock().unwrap().closed { return Err(closed()); }
        if unsafe { CreateIoCompletionPort(pipe.as_raw_handle(), self.state.port.as_raw_handle(), 0, 0) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        let cancel = Cancellation::new();
        let stop = cancel.clone();
        let subscription = shutdown.subscribe(move || stop.cancel());
        Ok(Peer { pipe: Arc::new(pipe), state: Arc::clone(&self.state), cancel, _shutdown: subscription })
    }
}
impl Drop for Reactor {
    fn drop(&mut self) {
        let operations: Vec<_> = {
            let mut pending = self.state.pending.lock().unwrap();
            pending.closed = true;
            pending.operations.values().cloned().collect()
        };
        for operation in operations { operation.cancel(); }
        self.state.wake();
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

impl State {
    fn wake(&self) { unsafe { PostQueuedCompletionStatus(self.port.as_raw_handle(), 0, 0, null_mut()); } }
    fn run(&self) {
        loop {
            let mut bytes = 0;
            let mut key = 0;
            let mut overlapped = null_mut();
            let ok = unsafe { GetQueuedCompletionStatus(self.port.as_raw_handle(), &mut bytes, &mut key, &mut overlapped, INFINITE) };
            let error = (ok == 0).then(io::Error::last_os_error);
            if !overlapped.is_null() {
                let operation = {
                    let mut pending = self.pending.lock().unwrap();
                    let operation = pending.operations.remove(&(overlapped as usize));
                    crate::collections::trim_map(&mut pending.operations);
                    operation
                };
                if let Some(operation) = operation { operation.finish(bytes as usize, error); }
            }
            let pending = self.pending.lock().unwrap();
            if pending.closed && pending.operations.is_empty() { return; }
        }
    }
}

pub(super) struct Peer {
    pipe: Arc<OwnedHandle>,
    state: Arc<State>,
    cancel: Cancellation,
    _shutdown: Option<Subscription>,
}
impl Drop for Peer {
    fn drop(&mut self) { self.close(); }
}
impl Peer {
    pub(super) fn close(&self) { self.cancel.cancel(); }

    async fn transfer(&self, buffer: Vec<u8>, offset: usize, read: bool) -> io::Result<(Vec<u8>, usize)> {
        if self.cancel.cancelled() { return Err(closed()); }
        let operation = Arc::new(Transfer {
            pipe: Arc::clone(&self.pipe),
            storage: UnsafeCell::new(Storage { overlapped: OVERLAPPED::default(), buffer }),
            status: Mutex::new(TransferStatus::default()),
            reply: Reply::default(),
        });
        let key = operation.overlapped() as usize;
        {
            let mut pending = self.state.pending.lock().unwrap();
            if pending.closed { return Err(closed()); }
            pending.operations.insert(key, Arc::clone(&operation));
        }
        let guard = TransferGuard(Arc::clone(&operation));
        let stop = Arc::clone(&operation);
        let _subscription = self.cancel.subscribe(move || stop.cancel());
        let immediate_error = {
            let mut status = operation.status.lock().unwrap();
            if status.cancelled { Some(closed()) }
            else {
                status.started = true;
                // Only this submission accesses storage before the kernel owns it.
                // The completion thread cannot finish it until status is unlocked.
                let storage = unsafe { &mut *operation.storage.get() };
                let data = &mut storage.buffer[offset..];
                let length = data.len().min(u32::MAX as usize) as u32;
                let ok = unsafe {
                    if read { ReadFile(self.pipe.as_raw_handle(), data.as_mut_ptr(), length, null_mut(), &mut storage.overlapped) }
                    else { WriteFile(self.pipe.as_raw_handle(), data.as_ptr(), length, null_mut(), &mut storage.overlapped) }
                };
                if ok != 0 { None } else {
                    let error = io::Error::last_os_error();
                    (error.raw_os_error() != Some(ERROR_IO_PENDING as i32)).then_some(error)
                }
            }
        };
        if let Some(error) = immediate_error {
            self.state.pending.lock().unwrap().operations.remove(&key);
            operation.finish(0, Some(error));
            // A rejected submission generates no kernel packet; wake shutdown
            // if this was the final registered operation.
            self.state.wake();
        }
        let result = operation.reply.wait().await;
        drop(guard);
        result
    }

    pub(super) async fn read_some(&self, buffer: Vec<u8>) -> io::Result<(Vec<u8>, usize)> {
        let (buffer, bytes) = self.transfer(buffer, 0, true).await?;
        if bytes == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok((buffer, bytes))
    }

    pub(super) async fn write_all(&self, mut buffer: Vec<u8>) -> io::Result<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            let (next, bytes) = self.transfer(buffer, offset, false).await?;
            if bytes == 0 { return Err(io::ErrorKind::WriteZero.into()); }
            buffer = next;
            offset += bytes;
        }
        Ok(())
    }
}

struct Storage { overlapped: OVERLAPPED, buffer: Vec<u8> }
#[derive(Default)]
struct TransferStatus { started: bool, cancelled: bool, finished: bool }
struct Transfer {
    pipe: Arc<OwnedHandle>,
    storage: UnsafeCell<Storage>,
    status: Mutex<TransferStatus>,
    reply: Reply<(Vec<u8>, usize)>,
}
// Storage is pinned by Arc and retained by the port's pending map. The kernel
// exclusively owns OVERLAPPED/buffer between submission and its dequeued packet;
// status serializes submit/cancel/finish, and only finish moves the completed data.
unsafe impl Send for Transfer {}
unsafe impl Sync for Transfer {}
impl Transfer {
    fn overlapped(&self) -> *mut OVERLAPPED {
        // Taking the field address does not create a reference to kernel-owned data.
        unsafe { std::ptr::addr_of_mut!((*self.storage.get()).overlapped) }
    }
    fn cancel(&self) {
        let mut status = self.status.lock().unwrap();
        if status.finished { return; }
        status.cancelled = true;
        if status.started { unsafe { CancelIoEx(self.pipe.as_raw_handle(), self.overlapped()); } }
    }
    fn finish(&self, bytes: usize, error: Option<io::Error>) {
        let result = {
            let mut status = self.status.lock().unwrap();
            status.finished = true;
            match error {
                Some(error) => Err(error),
                None => {
                    let storage = unsafe { &mut *self.storage.get() };
                    Ok((std::mem::take(&mut storage.buffer), bytes))
                }
            }
        };
        self.reply.complete(result);
    }
}
struct TransferGuard(Arc<Transfer>);
impl Drop for TransferGuard { fn drop(&mut self) { self.0.cancel(); } }

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Accept, hex, windows};
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::future::Future;
    use std::io::Write;
    use std::task::{Context, Poll, Waker};
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    fn pair(reactor: &Reactor) -> (Peer, File) {
        let name = format!(r"\\.\pipe\SunPack-iocp-test-{}-{}", std::process::id(), hex(&windows::random_bytes::<16>().unwrap()));
        let security = windows::PipeSecurity::current_user().unwrap();
        let accept = Accept::arm(&windows::wide(OsStr::new(&name)), &security.attributes(), true).unwrap();
        let client = OpenOptions::new().read(true).write(true).open(name).unwrap();
        assert_eq!(unsafe { WaitForSingleObject(accept.event.raw(), INFINITE) }, WAIT_OBJECT_0);
        (reactor.bind(accept.finish().unwrap(), &Cancellation::new()).unwrap(), client)
    }

    #[test]
    fn completion_port_handles_full_duplex_backpressure_dropped_waits_and_shutdown() {
        let reactor = Reactor::new().unwrap();
        let (peer, mut client) = pair(&reactor);
        // Buffered input may complete ReadFile synchronously; it still owns an
        // IOCP packet, so the buffer cannot be returned/freed before dequeue.
        client.write_all(b"buffered").unwrap();
        let (bytes, length) = crate::pipeline::block_on(peer.read_some(vec![0; 16])).unwrap();
        assert_eq!(&bytes[..length], b"buffered");
        let mut write = Box::pin(peer.write_all(vec![b'x'; 4 * 1024 * 1024]));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Pending));
        assert!(!reactor.state.pending.lock().unwrap().operations.is_empty());
        // A client not consuming stdout must not prevent its control input.
        client.write_all(b"cancel").unwrap();
        let (bytes, length) = crate::pipeline::block_on(peer.read_some(bytes)).unwrap();
        assert_eq!(&bytes[..length], b"cancel");
        peer.close();
        assert!(crate::pipeline::block_on(write).is_err());
        assert!(reactor.state.pending.lock().unwrap().operations.is_empty());
        assert!(crate::pipeline::block_on(peer.read_some(vec![0; 1])).is_err());

        let (broken, client) = pair(&reactor);
        drop(client);
        assert!(crate::pipeline::block_on(broken.read_some(vec![0; 1])).is_err());
        assert!(reactor.state.pending.lock().unwrap().operations.is_empty());

        let (pending, _client) = pair(&reactor);
        let mut read = Box::pin(pending.read_some(vec![0; 32]));
        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        drop(read); // CancelIoEx, never free a kernel-owned buffer here.
        let state = Arc::clone(&reactor.state);
        drop(reactor); // Joins actual cancellation packets, without a timeout/poll loop.
        assert!(state.pending.lock().unwrap().operations.is_empty());
        assert!(crate::pipeline::block_on(pending.read_some(vec![0; 1])).is_err());
    }
}
