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
#[path = "../../../tests/unit/runtime/pipe/output/tests.rs"]
mod tests;
