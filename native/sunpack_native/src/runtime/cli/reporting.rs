//! One request-owned output thread. Backpressure never occupies a host poll.

use crate::pipeline::{ArchiveResult, Event, TaskId};
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Poll, Waker};

#[derive(Default)]
pub(crate) struct Reports<T = Vec<ArchiveResult>> {
    state: Mutex<State<T>>,
    ready: Condvar,
}

#[derive(Default)]
struct State<T> {
    closed: bool,
    sequence: u64,
    // Keep creation, latest reset/phase, progress and resource state per task.
    // Sorting their sequence numbers preserves ordering without a progress backlog.
    events: HashMap<(TaskId, u8), (u64, Event)>,
    reports: VecDeque<Report<T>>,
}

struct Report<T> {
    id: TaskId,
    archives: T,
    reply: Arc<Reply<T>>,
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

impl<T: Default + Send> Reports<T> {
    pub(crate) fn notify(&self, event: Event) {
        let key = match &event {
            Event::Queued { id, .. } => (*id, 0),
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
            if key.1 == 1 {
                // Started/Working clear progress in Panel, even if a later
                // phase replaces them before the output thread can run.
                state.events.remove(&(key.0, 2));
                state.events.remove(&(key.0, 4));
            }
            if key.1 == 1 || key.1 == 4 {
                state.events.remove(&(key.0, 3));
            }
            state.sequence += 1;
            let sequence = state.sequence;
            state.events.insert(key, (sequence, event));
            self.ready.notify_one();
        }
    }

    pub(crate) async fn finish(
        &self,
        id: TaskId,
        archives: T,
    ) -> io::Result<T> {
        let reply = Arc::new(Reply::default());
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(unavailable());
            }
            // These are the existing outcome vectors, not copies or rendered
            // buffers. Outstanding reports share the scheduler's consumer bound.
            state.reports.push_back(Report { id, archives, reply: Arc::clone(&reply) });
            self.ready.notify_one();
        }
        reply.wait().await
    }

    pub(crate) fn serve<R>(
        &self,
        notify: impl Fn(Event) + Sync,
        finish: impl Fn(TaskId, &T) -> io::Result<()> + Sync,
        execute: impl FnOnce() -> R,
    ) -> R {
        self.state.lock().unwrap().closed = false;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                // Also wake every parked report if a display callback panics.
                let _close = Close(self);
                loop {
                    let (mut events, report, closed) = {
                        let mut state = self.ready.wait_while(
                            self.state.lock().unwrap(),
                            |state| !state.closed && state.events.is_empty() && state.reports.is_empty(),
                        ).unwrap();
                        let events: Vec<_> = state.events.drain().map(|(_, event)| event).collect();
                        (events, state.reports.pop_front(), state.closed)
                    };
                    let _reply = report.as_ref().map(|report| FailedReply(Arc::clone(&report.reply)));
                    events.sort_unstable_by_key(|(sequence, _)| *sequence);
                    for (_, event) in events {
                        notify(event);
                    }
                    if let Some(mut report) = report {
                        // A panicking callback must settle its active request as
                        // well as those still in the queue.
                        let value = finish(report.id, &report.archives)
                            .map(|()| std::mem::take(&mut report.archives));
                        report.reply.complete(value);
                    } else if closed {
                        return;
                    }
                }
            });
            let _close = Close(self);
            execute()
        })
    }

    fn close(&self) {
        let reports = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            state.events.clear();
            std::mem::take(&mut state.reports)
        };
        for report in reports {
            report.reply.complete(Err(unavailable()));
        }
        self.ready.notify_all();
    }
}

struct Close<'a, T: Default + Send>(&'a Reports<T>);

impl<T: Default + Send> Drop for Close<'_, T> {
    fn drop(&mut self) {
        self.0.close();
    }
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
    use crate::pipeline::DiscoverySource;
    use std::future::Future;
    use std::sync::mpsc;
    use std::task::{Context, Wake};
    use std::time::Duration;

    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) { self.0.unpark(); }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        loop {
            match future.as_mut().poll(&mut Context::from_waker(&waker)) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    fn archive(name: &str) -> ArchiveResult {
        ArchiveResult {
            path: name.into(), format: "zip".into(), output: Some(name.into()),
            failure: None, files: 1, bytes: 42, encrypted: None, depth: 1,
            offset: 0, end_offset: None, volume_completeness: None,
            volume_attempts: None, source_paths: Vec::new(), password: None,
            discovery_source: DiscoverySource::Direct, damage_flags: None,
            partial: false, retained: false, recovered_complete_files: 0,
            promoted: false, promotion_original_path: None,
        }
    }

    #[test]
    fn backpressure_parks_reports_and_coalesces_progress_without_copying_results() {
        // A byte-buffer test cannot detect blocking the archive poll or copying
        // large result vectors. Hold the output callback while sibling reports
        // enqueue and verify both polls return before the output is released.
        let reports = Reports::<Vec<ArchiveResult>>::default();
        let (entered, waiting) = mpsc::channel();
        let (release, capacity) = mpsc::channel();
        let capacity = Mutex::new(capacity);
        let written = Mutex::new(Vec::new());
        reports.serve(
            |_| {},
            |id, archives| {
                if id == 1 {
                    entered.send(()).unwrap();
                    capacity.lock().unwrap().recv().unwrap();
                }
                written.lock().unwrap().push(archives[0].path.clone());
                Ok(())
            },
            || {
                let originals = vec![archive("first.zip")];
                let allocation = originals.as_ptr();
                let mut first = Box::pin(reports.finish(1, originals));
                let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
                let mut cx = Context::from_waker(&waker);
                assert!(first.as_mut().poll(&mut cx).is_pending());
                waiting.recv_timeout(Duration::from_secs(10)).unwrap();
                for completed_bytes in 0..10_000 {
                    reports.notify(Event::Progress {
                        id: 3, path: "working.zip".into(), completed_bytes, total_bytes: 10_000,
                    });
                }
                assert_eq!(reports.state.lock().unwrap().events.len(), 1);
                let mut second = Box::pin(reports.finish(2, vec![archive("second.zip")]));
                let pending = second.as_mut().poll(&mut cx).is_pending();
                release.send(()).unwrap();
                assert!(pending, "output ran inside the caller's poll");
                let first = block_on(first).unwrap();
                assert_eq!(first.as_ptr(), allocation, "final results were copied");
                assert_eq!(first[0].bytes, 42);
                assert_eq!(block_on(second).unwrap()[0].path, std::path::Path::new("second.zip"));
            },
        );
        assert_eq!(*written.lock().unwrap(), vec![std::path::PathBuf::from("first.zip"), "second.zip".into()]);
    }

    #[test]
    fn output_errors_and_panics_settle_waiters_and_service_can_restart() {
        // A dead output thread must not leave a request parked indefinitely.
        let reports = Reports::<Vec<ArchiveResult>>::default();
        let error = reports.serve(
            |_| {}, |_, _| Err(io::Error::other("broken output")),
            || block_on(reports.finish(1, vec![archive("failed.zip")])),
        ).unwrap_err();
        assert_eq!(error.to_string(), "broken output");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reports.serve(
                |_| {}, |_, _| panic!("display failure"),
                || assert!(block_on(reports.finish(2, vec![archive("panic.zip")])).is_err()),
            );
        }));
        assert!(panic.is_err());
        let result = reports.serve(
            |_| {}, |_, _| Ok(()),
            || block_on(reports.finish(3, vec![archive("retry.zip")])),
        ).unwrap();
        assert_eq!(result[0].path, std::path::Path::new("retry.zip"));

        // Queue both before starting the service so notify deterministically
        // panics after the active report is dequeued, but before finish runs.
        let reports = Reports::<Vec<ArchiveResult>>::default();
        reports.notify(Event::Working { id: 4 });
        let mut pending = Box::pin(reports.finish(4, vec![archive("notify-panic.zip")]));
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        assert!(pending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reports.serve(
                |_| panic!("notify failure"), |_, _| Ok(()),
                || assert!(block_on(pending).is_err()),
            );
        }));
        assert!(panic.is_err());
    }

    #[test]
    fn merged_phases_preserve_panel_resets() {
        let reports = Reports::<Vec<ArchiveResult>>::default();
        reports.notify(Event::Progress {
            id: 1, path: "work.zip".into(), completed_bytes: 60, total_bytes: 100,
        });
        reports.notify(Event::Working { id: 1 });
        reports.notify(Event::ResourceWait {
            id: 1, path: "work.zip".into(), state: Default::default(),
        });
        reports.notify(Event::Finished {
            id: 1, path: "work.zip".into(), depth: 1, success: true,
        });
        let state = reports.state.lock().unwrap();
        assert_eq!(state.events.len(), 2);
        assert!(matches!(&state.events[&(1, 1)].1, Event::Working { .. }));
        assert!(matches!(&state.events[&(1, 4)].1, Event::Finished { .. }));
    }
}
