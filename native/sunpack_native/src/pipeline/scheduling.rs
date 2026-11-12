//! A request's caller owns its suspended futures. Only runnable polls enter
//! Rayon, with admission shared by all requests using the engine.

use super::{Cancellation, Origin};
use std::collections::{HashMap, VecDeque};
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

pub(crate) const MAX_PENDING_JOBS: usize = 4096;

pub(super) struct Scheduler {
    capacity: usize,
    state: Mutex<Admission>,
}

#[derive(Default)]
struct Admission {
    active: usize,
    foreground: Queue,
    watch: Queue,
}

#[derive(Default)]
struct Queue {
    order: VecDeque<u64>,
    requests: HashMap<u64, VecDeque<Grant>>,
}

struct Grant {
    id: usize,
    tx: mpsc::Sender<Signal>,
}

impl Grant {
    fn send(self, scheduler: &Arc<Scheduler>) -> bool {
        let slot = Slot(Some(Arc::clone(scheduler)));
        match self.tx.send(Signal::Granted(self.id, slot)) {
            Ok(()) => true,
            Err(mpsc::SendError(Signal::Granted(_, mut slot))) => {
                // The request unwound. Pass the slot on without recursively
                // dropping the rest of the disconnected request's grants.
                slot.0.take();
                false
            }
            Err(_) => unreachable!(),
        }
    }
}

impl Queue {
    fn push(&mut self, request: u64, grant: Grant) {
        self.requests
            .entry(request)
            .or_insert_with(|| {
                self.order.push_back(request);
                VecDeque::new()
            })
            .push_back(grant);
    }

    fn pop(&mut self) -> Option<Grant> {
        let request = self.order.pop_front()?;
        let tasks = self.requests.get_mut(&request).unwrap();
        let grant = tasks.pop_front().unwrap();
        if tasks.is_empty() {
            self.requests.remove(&request);
            crate::collections::trim_map(&mut self.requests);
            crate::collections::trim_deque(&mut self.order);
        } else {
            self.order.push_back(request);
        }
        Some(grant)
    }
}

struct Slot(Option<Arc<Scheduler>>);

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(scheduler) = self.0.take() {
            scheduler.release();
        }
    }
}

impl Scheduler {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            capacity: rayon::current_num_threads(),
            state: Mutex::default(),
        })
    }

    fn enqueue(self: &Arc<Self>, request: u64, origin: Origin, grant: Grant) {
        let mut state = self.state.lock().unwrap();
        if state.active == self.capacity {
            match origin {
                Origin::Foreground => &mut state.foreground,
                Origin::Watch => &mut state.watch,
            }
            .push(request, grant);
        } else {
            state.active += 1;
            drop(state);
            if !grant.send(self) {
                self.release();
            }
        }
    }

    fn release(self: &Arc<Self>) {
        loop {
            let next = {
                let mut state = self.state.lock().unwrap();
                match state.foreground.pop().or_else(|| state.watch.pop()) {
                    Some(next) => next,
                    None => {
                        state.active -= 1;
                        return;
                    }
                }
            };
            if next.send(self) {
                return;
            }
        }
    }

    pub(super) fn run<'a, T: Send + 'a>(
        self: &Arc<Self>,
        request: u64,
        origin: Origin,
        cancel: &Cancellation,
        run: impl FnOnce(Spawner<'a>) -> Task<'a, T>,
    ) -> T {
        let (tx, rx) = mpsc::channel();
        let (signals, ready) = mpsc::channel::<Signal>();
        let signal_tx = signals.clone();
        let spawner = Spawner {
            tx,
            signals,
            // Match main's request-level consumer budget. Rayon limits polls;
            // this separately bounds retained recursive consumer futures.
            consumers: Arc::new(AtomicUsize::new(MAX_PENDING_JOBS.max(self.capacity))),
        };
        let mut result = spawner.spawn(run(spawner.clone()));
        let mut tasks = HashMap::new();
        let mut next_id = 0;
        rayon::in_place_scope(|scope| loop {
            match ready.recv().expect("request owns its signal channel") {
                Signal::Spawned => {
                    let future = rx.try_recv().expect("spawn precedes its signal");
                    let id = next_id;
                    next_id += 1;
                    let wake = Arc::new(TaskWake {
                        id,
                        pending: AtomicBool::new(false),
                        tx: signal_tx.clone(),
                    });
                    tasks.insert(
                        id,
                        TaskState {
                            wake,
                            future: Arc::new(Mutex::new(Some(future))),
                            status: Status::Queued,
                        },
                    );
                    self.enqueue_poll(request, origin, id, &signal_tx);
                }
                Signal::Wake(id) => {
                    if let Some(task) = tasks.get_mut(&id) {
                        task.wake.pending.store(false, Ordering::Release);
                        match &mut task.status {
                            Status::Parked => {
                                task.status = Status::Queued;
                                self.enqueue_poll(request, origin, id, &signal_tx);
                            }
                            Status::Running { notified } => *notified = true,
                            Status::Queued => {}
                        }
                    }
                }
                Signal::Granted(id, slot) => {
                    let task = tasks.get_mut(&id).unwrap();
                    task.status = Status::Running { notified: false };
                    let waker = Waker::from(Arc::clone(&task.wake));
                    let parked = Arc::clone(&task.future);
                    let mut future = parked.lock().unwrap().take().unwrap();
                    let signals = signal_tx.clone();
                    let cancel = cancel.clone();
                    scope.spawn(move |_| {
                        // A panic must wake the caller so Rayon can unwind the scope.
                        let completed =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                cancel
                                    .run(|| future.as_mut().poll(&mut Context::from_waker(&waker)))
                            }));
                        match completed {
                            Ok(Poll::Ready(())) => {
                                drop(future);
                                let _ = signals.send(Signal::Done(id));
                            }
                            Ok(Poll::Pending) => {
                                *parked.lock().unwrap() = Some(future);
                                let _ = signals.send(Signal::Parked(id));
                            }
                            Err(panic) => {
                                let _ = signals.send(Signal::Panicked);
                                std::panic::resume_unwind(panic);
                            }
                        }
                        drop(slot);
                    });
                }
                Signal::Parked(id) => {
                    let task = tasks.get_mut(&id).unwrap();
                    if matches!(task.status, Status::Running { notified: true }) {
                        task.status = Status::Queued;
                        self.enqueue_poll(request, origin, id, &signal_tx);
                    } else {
                        task.status = Status::Parked;
                    }
                }
                Signal::Done(id) => {
                    tasks.remove(&id);
                    if tasks.is_empty() {
                        return result.take().expect("root poll produced a result");
                    }
                }
                Signal::Panicked => panic!("archive task panicked"),
            }
        })
    }

    fn enqueue_poll(
        self: &Arc<Self>,
        request: u64,
        origin: Origin,
        id: usize,
        tx: &mpsc::Sender<Signal>,
    ) {
        self.enqueue(request, origin, Grant { id, tx: tx.clone() });
    }
}

struct TaskState<'a> {
    wake: Arc<TaskWake>,
    future: Arc<Mutex<Option<Task<'a, ()>>>>,
    status: Status,
}

enum Status {
    Queued,
    Running { notified: bool },
    Parked,
}

enum Signal {
    Spawned,
    Wake(usize),
    Granted(usize, Slot),
    Parked(usize),
    Done(usize),
    Panicked,
}

struct TaskWake {
    id: usize,
    pending: AtomicBool,
    tx: mpsc::Sender<Signal>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            let _ = self.tx.send(Signal::Wake(self.id));
        }
    }
}

pub(super) type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub(super) struct Spawner<'a> {
    tx: mpsc::Sender<Task<'a, ()>>,
    signals: mpsc::Sender<Signal>,
    consumers: Arc<AtomicUsize>,
}

struct ConsumerReservation {
    available: Arc<AtomicUsize>,
    count: usize,
}

impl Drop for ConsumerReservation {
    fn drop(&mut self) {
        self.available.fetch_add(self.count, Ordering::AcqRel);
    }
}

type ResultCell<T> = Arc<Mutex<(Option<T>, Option<Waker>)>>;

pub(super) struct Join<T>(ResultCell<T>);

impl<T> Join<T> {
    fn take(&mut self) -> Option<T> {
        self.0.lock().unwrap().0.take()
    }

    pub(super) async fn wait(self) -> T {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if let Some(value) = state.0.take() {
                Poll::Ready(value)
            } else {
                state.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

impl<'a> Spawner<'a> {
    #[cfg(test)]
    pub(super) fn consumer_budget(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.consumers)
    }

    /// Consume a batch using a shared request-level budget, as the original
    /// coordinator did. A recursive batch with no free consumers runs inline
    /// in its parent, so parents never wait for admission held by themselves.
    /// Each consumer takes the next item immediately after finishing its own;
    /// a slow early item cannot stall admission of the rest of the batch.
    pub(super) fn bounded_map<I, T, F>(&self, items: Vec<I>, operation: F) -> Task<'a, Vec<T>>
    where
        I: Send + 'a,
        T: Send + 'a,
        F: Fn(I) -> Task<'a, T> + Send + Sync + 'a,
    {
        let spawner = self.clone();
        Box::pin(async move {
            let available = spawner.consumers.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |available| Some(available.saturating_sub(items.len())),
            ).unwrap();
            let count = available.min(items.len());
            let _reservation = ConsumerReservation {
                available: Arc::clone(&spawner.consumers),
                count,
            };
            if count == 0 {
                let mut results = Vec::with_capacity(items.len());
                for item in items {
                    results.push(operation(item).await);
                }
                return results;
            }
            let results = Arc::new(Mutex::new(
                std::iter::repeat_with(|| None).take(items.len()).collect::<Vec<Option<T>>>(),
            ));
            let remaining = Arc::new(Mutex::new(items.into_iter().enumerate()));
            let operation = Arc::new(operation);
            let mut consumers = Vec::with_capacity(count);
            for _ in 0..count {
                let remaining = Arc::clone(&remaining);
                let operation = Arc::clone(&operation);
                let results = Arc::clone(&results);
                consumers.push(spawner.spawn(Box::pin(async move {
                    loop {
                        // Never hold the iterator mutex across an await.
                        let next = remaining.lock().unwrap().next();
                        let Some((index, item)) = next else { break };
                        let result = operation(item).await;
                        results.lock().unwrap()[index] = Some(result);
                    }
                })));
            }
            for consumer in consumers {
                consumer.wait().await;
            }
            // Keep discovery-order aggregation and first-error behavior in
            // linear time, without retaining a result vector for each worker.
            // Every consumer has joined, so all indexed slots are initialized.
            let results = std::mem::take(&mut *results.lock().unwrap());
            results.into_iter().map(|result| result.expect("consumer produced a result")).collect()
        })
    }

    pub(super) fn spawn<T: Send + 'a>(&self, future: Task<'a, T>) -> Join<T> {
        let cell = Arc::new(Mutex::new((None, None::<Waker>)));
        let receiver = Arc::clone(&cell);
        let future = Box::pin(async move {
            let value = future.await;
            let mut state = cell.lock().unwrap();
            state.0 = Some(value);
            if let Some(waker) = state.1.take() {
                waker.wake();
            }
        });
        assert!(self.tx.send(future).is_ok());
        assert!(self.signals.send(Signal::Spawned).is_ok());
        Join(receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn single_slot() -> Arc<Scheduler> {
        Arc::new(Scheduler {
            capacity: 1,
            state: Mutex::default(),
        })
    }

    #[test]
    fn parked_watch_releases_the_only_host_slot_until_its_event_arrives() {
        // No elapsed-time assumption: an external event is withheld until the
        // foreground poll has completed on the only host slot.
        let scheduler = single_slot();
        let (parked, parked_rx) = mpsc::sync_channel(1);
        let event = Arc::new(Mutex::new((false, None::<Waker>)));
        let signal = Arc::clone(&event);
        let watch = Arc::clone(&scheduler);
        let watch = std::thread::spawn(move || {
            watch.run(1, Origin::Watch, &Cancellation::new(), |spawner| {
                Box::pin(async move {
                    spawner
                        .spawn(Box::pin(poll_fn(move |cx| {
                            let mut event = event.lock().unwrap();
                            if event.0 {
                                Poll::Ready(42)
                            } else {
                                if event.1.is_none() {
                                    parked.send(()).unwrap();
                                }
                                event.1 = Some(cx.waker().clone());
                                Poll::Pending
                            }
                        })))
                        .wait()
                        .await
                })
            })
        });
        parked_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (finished, finished_rx) = mpsc::sync_channel(1);
        let foreground = std::thread::spawn(move || {
            scheduler.run(2, Origin::Foreground, &Cancellation::new(), |_| {
                Box::pin(async move {
                    finished.send(()).unwrap();
                })
            });
        });
        let independent = finished_rx.recv_timeout(Duration::from_secs(10));
        {
            let mut event = signal.lock().unwrap();
            event.0 = true;
            event.1.take().unwrap().wake();
        }
        assert_eq!(watch.join().unwrap(), 42);
        foreground.join().unwrap();
        independent.expect("foreground needed a host slot held by suspended Watch work");
    }

    #[test]
    fn bounded_consumers_drain_past_slow_items_and_recurse_inline() {
        // Two consumers, more items than permits: item zero cannot finish
        // until a later item runs. Nested work must not await another permit.
        let scheduler = single_slot();
        let results = scheduler.run(1, Origin::Foreground, &Cancellation::new(), |spawner| {
            Box::pin(async move {
                spawner.consumers.store(2, Ordering::Release);
                let gate = Arc::new(Mutex::new((false, None::<Waker>)));
                let children = spawner.clone();
                let results = spawner.bounded_map((0..8).collect(), move |item| {
                    let gate = Arc::clone(&gate);
                    let children = children.clone();
                    Box::pin(async move {
                        assert_eq!(children.consumers.load(Ordering::Acquire), 0);
                        if item == 0 {
                            poll_fn(|cx| {
                                let mut gate = gate.lock().unwrap();
                                if gate.0 { Poll::Ready(()) } else {
                                    gate.1 = Some(cx.waker().clone());
                                    Poll::Pending
                                }
                            }).await;
                        } else if item == 1 {
                            let nested = children.bounded_map(vec![10, 11], |value| {
                                Box::pin(async move { value })
                            }).await;
                            assert_eq!(nested, [10, 11]);
                        } else if item == 2 {
                            let mut gate = gate.lock().unwrap();
                            gate.0 = true;
                            if let Some(waker) = gate.1.take() { waker.wake(); }
                        }
                        item
                    })
                }).await;
                assert_eq!(spawner.consumers.load(Ordering::Acquire), 2);
                results
            })
        });
        assert_eq!(results, (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn ready_requests_take_turns_after_foreground_work() {
        let scheduler = single_slot();
        let (tx, rx) = mpsc::channel();
        for (request, origin, index) in [
            (0, Origin::Watch, 0),
            (1, Origin::Watch, 1),
            (1, Origin::Watch, 2),
            (2, Origin::Watch, 3),
            (3, Origin::Foreground, 4),
        ] {
            scheduler.enqueue_poll(request, origin, index, &tx);
        }
        let mut order = Vec::new();
        while let Ok(Signal::Granted(id, slot)) = rx.try_recv() {
            order.push(id);
            drop(slot);
        }
        assert_eq!(order, [0, 4, 1, 3, 2]);
    }
}
