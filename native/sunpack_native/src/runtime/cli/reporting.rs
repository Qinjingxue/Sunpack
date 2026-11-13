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
}

#[derive(Default)]
pub(crate) struct Reply<T>(Mutex<ReplyState<T>>);

#[derive(Default)]
struct ReplyState<T> {
    value: Option<io::Result<T>>,
    waker: Option<Waker>,
}

impl<T> Reply<T> {
    pub(crate) fn complete(&self, value: io::Result<T>) {
        let mut state = self.0.lock().unwrap();
        state.value = Some(value);
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    pub(crate) async fn wait(&self) -> io::Result<T> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            match state.value.take() {
                Some(value) => Poll::Ready(value),
                None => { state.waker = Some(cx.waker().clone()); Poll::Pending }
            }
        }).await
    }

}

fn unavailable() -> io::Error {
    io::Error::other("Output service stopped")
}

impl Reports {
    pub(crate) fn notify(&self, event: Event) {
        let key = match &event {
            Event::Queued { id, .. } => (*id, 0),
            Event::Replanned { id, .. } => (*id, 5),
            Event::Progress { id, .. } => (*id, 2),
            Event::ResourceWait { id, .. } => (*id, 3),
            Event::Started { id, .. } | Event::Working { id } => (*id, 1),
            Event::Waiting { id }
            | Event::Finalizing { id }
            | Event::Finished { id, .. }
            | Event::Skipped { id } => (*id, 4),
        };
        let mut state = self.state.lock().unwrap();
        if !state.closed {
            if key.1 == 5 {
                // Keep initial registration but discard the previous attempt.
                for kind in 1..=4 { state.events.remove(&(key.0, kind)); }
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
            if let Some(waker) = state.waker.take() { waker.wake(); }
        }
    }

    pub(crate) async fn serve_async(
        &self,
        notify: impl Fn() + Sync,
    ) {
        let _close = Close(self);
        loop {
            let closed = poll_fn(|cx| {
                let mut state = self.state.lock().unwrap();
                if state.closed || !state.events.is_empty() {
                    Poll::Ready(state.closed)
                } else {
                    state.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }).await;
            crate::pipeline::stage("report", &crate::pipeline::Cancellation::new()).await
                .expect("completion reporting is not cancellable");
            notify();
            if closed { return; }
        }
    }

    pub(crate) fn relocate_outputs(&self, old: &std::path::Path, new: &std::path::Path) {
        for (_, event) in self.state.lock().unwrap().events.values_mut() {
            if let Event::Finished { result, .. } = event {
                result.relocate_output(old, new);
            }
        }
    }

    pub(crate) fn take_events(&self) -> Vec<Event> {
        let mut events: Vec<_> = self.state.lock().unwrap().events.drain().map(|(_, event)| event).collect();
        events.sort_unstable_by_key(|(sequence, _)| *sequence);
        events.into_iter().map(|(_, event)| event).collect()
    }

    pub(crate) fn reopen(&self) { self.state.lock().unwrap().closed = false; }

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
mod tests {
    use super::*;
    use crate::pipeline::{Cancellation, Origin, Scheduler};
    use std::sync::mpsc;

    #[test]
    fn replan_discards_pending_old_attempt_but_keeps_registration_and_new_progress() {
        let reports = Reports::default();
        reports.notify(Event::Queued { id: 7, parent: None, path: "old.002".into(), depth: 1, segment: None });
        reports.notify(Event::Working { id: 7 });
        reports.notify(Event::Progress { id: 7, path: "old.002".into(), completed_bytes: 9, total_bytes: 10 });
        reports.notify(Event::ResourceWait { id: 7, path: "old.002".into(), state: Default::default() });
        reports.notify(Event::Replanned { id: 7, path: "new.001".into() });
        reports.notify(Event::Working { id: 7 });
        reports.notify(Event::Progress { id: 7, path: "new.001".into(), completed_bytes: 1, total_bytes: 10 });
        let events = reports.take_events();
        assert_eq!(events.len(), 4);
        assert!(matches!(&events[0], Event::Queued { .. }));
        assert!(matches!(&events[1], Event::Replanned { path, .. } if path == std::path::Path::new("new.001")));
        assert!(matches!(&events[2], Event::Working { .. }));
        assert!(matches!(&events[3], Event::Progress { completed_bytes: 1, .. }));
    }

    #[test]
    fn shared_progress_service_coalesces_events_and_wakes_without_a_private_thread() {
        let reports = Arc::new(Reports::default());
        reports.notify(Event::Working { id: 7 });
        reports.notify(Event::Working { id: 7 });
        let scheduler = Scheduler::new();
        let cancel = Cancellation::new();
        let (sent, received) = mpsc::channel();
        let service = Arc::clone(&reports);
        let output = scheduler.submit(1, Origin::Foreground, &cancel, move |_| Box::pin(async move {
            service.serve_async(|| { for event in service.take_events() { sent.send(event).unwrap(); } }).await;
        }));
        assert!(matches!(received.recv().unwrap(), Event::Working { id: 7 }));
        reports.close();
        output.join().unwrap();
        assert!(received.try_recv().is_err());
    }
}
