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
