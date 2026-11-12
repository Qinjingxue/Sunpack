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
    waiters: Vec<Waker>,
}
fn closed() -> io::Error { io::ErrorKind::ConnectionAborted.into() }
impl State {
    fn wait(&mut self, wake: &Waker) {
        if !self.waiters.iter().any(|old| old.will_wake(wake)) { self.waiters.push(wake.clone()); }
    }
    fn push(&mut self, frame: Vec<u8>) -> Vec<Waker> {
        self.bytes += frame.len();
        self.unfinished += 1;
        self.frames.push_back(frame);
        std::mem::take(&mut self.waiters)
    }
}
fn wake(waiters: Vec<Waker>) { for waiter in waiters { waiter.wake(); } }
impl Output {
    pub(super) fn closed(&self) -> bool { self.0.lock().unwrap().closed }
    pub(super) fn try_enqueue(&self, frame: Vec<u8>, control: bool) -> io::Result<()> {
        if frame.len() > CAPACITY { return Err(io::ErrorKind::InvalidData.into()); }
        let waiters = {
            let mut state = self.0.lock().unwrap();
            if state.closed { return Err(closed()); }
            if !control && state.bytes + frame.len() > CAPACITY { return Err(io::ErrorKind::WouldBlock.into()); }
            state.push(frame)
        };
        wake(waiters);
        Ok(())
    }
    pub(super) async fn enqueue(&self, frame: Vec<u8>) -> io::Result<()> {
        if frame.len() > CAPACITY { return Err(io::ErrorKind::InvalidData.into()); }
        let mut frame = Some(frame);
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if state.closed { return Poll::Ready(Err(closed())); }
            if state.bytes + frame.as_ref().unwrap().len() > CAPACITY {
                state.wait(cx.waker());
                return Poll::Pending;
            }
            let waiters = state.push(frame.take().unwrap());
            drop(state);
            wake(waiters);
            Poll::Ready(Ok(()))
        }).await
    }
    pub(super) async fn next(&self) -> Option<Vec<u8>> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if let Some(frame) = state.frames.pop_front() {
                state.bytes -= frame.len();
                let waiters = std::mem::take(&mut state.waiters);
                drop(state);
                wake(waiters);
                Poll::Ready(Some(frame))
            } else if state.closed { Poll::Ready(None) }
            else { state.wait(cx.waker()); Poll::Pending }
        }).await
    }
    pub(super) fn acknowledge(&self) {
        let waiters = {
            let mut state = self.0.lock().unwrap();
            state.unfinished -= 1;
            std::mem::take(&mut state.waiters)
        };
        wake(waiters);
    }
    pub(super) async fn drain(&self) -> io::Result<()> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if state.unfinished == 0 { Poll::Ready(Ok(())) }
            else { state.wait(cx.waker()); Poll::Pending }
        }).await
    }
    pub(super) fn close(&self) {
        let waiters = {
            let mut state = self.0.lock().unwrap();
            state.closed = true;
            state.unfinished -= state.frames.len();
            state.frames.clear();
            state.bytes = 0;
            std::mem::take(&mut state.waiters)
        };
        wake(waiters);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Waker};
    #[test]
    fn bounded_output_preserves_cancel_notice_and_joins_active_write_on_close() {
        let output = Output::default();
        output.try_enqueue(vec![0; CAPACITY], false).unwrap();
        assert_eq!(output.try_enqueue(vec![1], false).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let mut waiting = Box::pin(output.enqueue(vec![2]));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Pending));
        output.try_enqueue(vec![3], true).unwrap();
        let active = crate::pipeline::block_on(output.next()).unwrap();
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
