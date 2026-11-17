//! Coalesced live progress served by a shared scheduler task.
//! Lossless final scope reports stay in their archive request.

use crate::pipeline::{Event, TaskId};
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

#[derive(Default)]
pub(crate) struct Reports {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    closed: bool,
    waker: Option<Waker>,
    sequence: u64,
    // Keep creation, latest reset/phase, progress and resource state per task.
    // Sorting their sequence numbers preserves ordering without a progress backlog.
    events: HashMap<(TaskId, u8), (u64, Event)>,
    // Relocations compose and cannot be coalesced like progress updates.
    relocations: Vec<(u64, Event)>,
}

#[derive(Default)]
pub(crate) struct Reply<T>(Mutex<ReplyState<T>>);

enum ReplyState<T> {
    Pending(Option<Waker>),
    Ready(io::Result<T>),
    Consumed,
}

impl<T> Default for ReplyState<T> {
    fn default() -> Self {
        Self::Pending(None)
    }
}

impl<T> Reply<T> {
    pub(crate) fn complete(&self, value: io::Result<T>) {
        let mut state = self.0.lock().unwrap();
        // Cancellation and input can publish concurrently. A consumed reply
        // stays terminal so a late publisher cannot store a second payload.
        let ReplyState::Pending(waker) = &mut *state else { return };
        let waker = waker.take();
        *state = ReplyState::Ready(value);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    pub(crate) async fn wait(&self) -> io::Result<T> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            match &mut *state {
                ReplyState::Pending(waker) => {
                    *waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                ReplyState::Ready(_) => {
                    let ReplyState::Ready(value) = std::mem::replace(&mut *state, ReplyState::Consumed)
                        else { unreachable!() };
                    Poll::Ready(value)
                }
                ReplyState::Consumed => Poll::Ready(Err(io::Error::other("reply already consumed"))),
            }
        }).await
    }

}

fn unavailable() -> io::Error {
    io::Error::other("Output service stopped")
}

impl Reports {
    pub(crate) fn notify(&self, event: Event) {
        let mut state = self.state.lock().unwrap();
        if state.closed { return; }
        if matches!(event, Event::OutputsRelocated { .. }) {
            state.sequence += 1;
            let sequence = state.sequence;
            state.relocations.push((sequence, event));
            let waker = state.waker.take();
            drop(state);
            if let Some(waker) = waker { waker.wake(); }
            return;
        }
        let key = match &event {
            Event::Queued { id, .. } => (*id, 0),
            Event::Replanned { id, .. } => (*id, 5),
            Event::Progress { id, .. } => (*id, 2),
            Event::ResourceWait { id, .. } => (*id, 3),
            Event::Extracting { id } => (*id, 6),
            Event::ResolvingVolumes { id } => (*id, 1),
            Event::Started { id, .. } | Event::Working { id } => (*id, 1),
            Event::Waiting { id }
            | Event::Finalizing { id }
            | Event::Finished { id, .. }
            | Event::Skipped { id } => (*id, 4),
            Event::OutputsRelocated { .. } => unreachable!(),
        };
        if key.1 == 5 {
            // Keep initial registration but discard the previous attempt.
            for kind in 1..=4 { state.events.remove(&(key.0, kind)); }
            state.events.remove(&(key.0, 6));
        }
        if key.1 == 1 {
            // Started/Working clear progress in Panel, even if a later
            // phase replaces them before the progress task can run.
            state.events.remove(&(key.0, 2));
            state.events.remove(&(key.0, 4));
        }
        if key.1 == 1 || key.1 == 4 {
            state.events.remove(&(key.0, 3));
        }
        state.sequence += 1;
        let sequence = state.sequence;
        state.events.insert(key, (sequence, event));
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker { waker.wake(); }
    }

    pub(crate) async fn serve_async(
        &self,
        notify: impl Fn() + Sync,
    ) {
        let _close = Close(self);
        loop {
            let (closed, pending) = poll_fn(|cx| {
                let mut state = self.state.lock().unwrap();
                let pending = !state.events.is_empty() || !state.relocations.is_empty();
                if state.closed || pending {
                    Poll::Ready((state.closed, pending))
                } else {
                    state.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }).await;
            if !pending { return; }
            crate::pipeline::stage("report", &crate::pipeline::Cancellation::new()).await
                .expect("completion reporting is not cancellable");
            notify();
            if closed { return; }
        }
    }

    pub(crate) fn take_events(&self) -> Vec<Event> {
        let mut state = self.state.lock().unwrap();
        let mut events = Vec::with_capacity(state.events.len() + state.relocations.len());
        events.extend(state.events.drain().map(|(_, event)| event));
        events.append(&mut state.relocations);
        drop(state);
        events.sort_unstable_by_key(|(sequence, _)| *sequence);
        events.into_iter().map(|(_, event)| event).collect()
    }

    pub(crate) fn close(&self) {
        let waker = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            state.waker.take()
        };
        if let Some(waker) = waker { waker.wake(); }
    }
}

struct Close<'a>(&'a Reports);
impl Drop for Close<'_> {
    fn drop(&mut self) { self.0.close(); }
}


pub(crate) struct FailedReply<T>(pub(crate) Arc<Reply<T>>);

impl<T> Drop for FailedReply<T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.complete(Err(unavailable()));
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/runtime/cli/reporting/tests.rs"]
mod tests;
