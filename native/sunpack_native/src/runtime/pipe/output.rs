//! main's byte-bounded connection output queue. Blocking producers may wait
//! from a stage; control continuations use enqueue().await or try_enqueue().
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::sync::Mutex;
use std::task::{Poll, Waker};

const CAPACITY: usize = 1024 * 1024;
#[derive(Default)]
pub(super) struct Output(Mutex<State>);
#[derive(Default)]
struct State {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    unfinished: usize,
    closed: bool,
    reader: Option<Waker>,
    space_waiters: Vec<Waker>,
    drain_waiters: Vec<Waker>,
}
fn closed() -> io::Error { io::ErrorKind::ConnectionAborted.into() }
fn wait(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|old| old.will_wake(waker)) { waiters.push(waker.clone()); }
}
impl State {
    fn push(&mut self, frame: Vec<u8>) -> Option<Waker> {
        self.bytes += frame.len();
        self.unfinished += 1;
        self.frames.push_back(frame);
        self.reader.take()
    }
}
fn wake(waiters: impl IntoIterator<Item = Waker>) { for waiter in waiters { waiter.wake(); } }
impl Output {
    pub(super) fn closed(&self) -> bool { self.0.lock().unwrap().closed }
    pub(super) fn try_enqueue(&self, frame: Vec<u8>, control: bool) -> io::Result<()> {
        if frame.len() > CAPACITY { return Err(io::ErrorKind::InvalidData.into()); }
        let reader = {
            let mut state = self.0.lock().unwrap();
            if state.closed { return Err(closed()); }
            if !control && state.bytes + frame.len() > CAPACITY { return Err(io::ErrorKind::WouldBlock.into()); }
            state.push(frame)
        };
        wake(reader);
        Ok(())
    }
    pub(super) async fn enqueue(&self, frame: Vec<u8>) -> io::Result<()> {
        if frame.len() > CAPACITY { return Err(io::ErrorKind::InvalidData.into()); }
        let mut frame = Some(frame);
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if state.closed { return Poll::Ready(Err(closed())); }
            if state.bytes + frame.as_ref().unwrap().len() > CAPACITY {
                wait(&mut state.space_waiters, cx.waker());
                return Poll::Pending;
            }
            let reader = state.push(frame.take().unwrap());
            drop(state);
            wake(reader);
            Poll::Ready(Ok(()))
        }).await
    }
    pub(super) async fn next(&self) -> Option<Vec<u8>> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if let Some(frame) = state.frames.pop_front() {
                state.bytes -= frame.len();
                let waiters = std::mem::take(&mut state.space_waiters);
                drop(state);
                wake(waiters);
                Poll::Ready(Some(frame))
            } else if state.closed { Poll::Ready(None) }
            else { state.reader = Some(cx.waker().clone()); Poll::Pending }
        }).await
    }
    pub(super) fn acknowledge(&self) {
        let waiters = {
            let mut state = self.0.lock().unwrap();
            state.unfinished -= 1;
            if state.unfinished != 0 { return; }
            std::mem::take(&mut state.drain_waiters)
        };
        wake(waiters);
    }
    pub(super) async fn drain(&self) -> io::Result<()> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if state.unfinished == 0 { Poll::Ready(Ok(())) }
            else { wait(&mut state.drain_waiters, cx.waker()); Poll::Pending }
        }).await
    }
    pub(super) fn close(&self) {
        let (reader, space, drained) = {
            let mut state = self.0.lock().unwrap();
            state.closed = true;
            state.unfinished -= state.frames.len();
            state.frames.clear();
            state.bytes = 0;
            let drained = if state.unfinished == 0 {
                std::mem::take(&mut state.drain_waiters)
            } else { Vec::new() };
            (state.reader.take(), std::mem::take(&mut state.space_waiters), drained)
        };
        wake(reader.into_iter().chain(space).chain(drained));
    }
}

#[cfg(test)]
mod tests {
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
        crate::pipeline::block_on(drained).unwrap();
        assert!(crate::pipeline::block_on(output.next()).is_none());
    }
}
