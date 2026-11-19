use super::*;
use std::future::Future;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::task::{Context, Wake};

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
}

#[test]
fn bounded_output_preserves_cancel_notice_and_joins_active_write_on_close() {
    let output = Output::default();
    output.try_enqueue(vec![0; CAPACITY], false).unwrap();
    assert_eq!(output.try_enqueue(vec![1], false).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let mut waiting = Box::pin(output.enqueue(vec![2]));
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Pending));
    output.try_enqueue(vec![3], true).unwrap();
    // Enqueuing the cancellation notice consumes space and cannot make
    // the blocked producer ready. Only dequeue makes capacity available.
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    let active = crate::pipeline::block_on(output.next()).unwrap();
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert_eq!(active.len(), CAPACITY);
    output.close();
    assert!(crate::pipeline::block_on(waiting).is_err());
    let mut drained = Box::pin(output.drain());
    assert!(matches!(drained.as_mut().poll(&mut cx), Poll::Pending));
    output.acknowledge();
    crate::pipeline::block_on(drained);
    assert!(crate::pipeline::block_on(output.next()).is_none());
}
