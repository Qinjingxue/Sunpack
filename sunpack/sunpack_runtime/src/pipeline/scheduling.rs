//! Scoped callers and owned background requests share one task state machine.
//! Async control stays outside host capacity; explicit blocking stages enter Rayon.

use super::{Cancellation, Origin};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};

/// Serializes async lifecycle transitions without blocking the shared control driver.
#[derive(Default)]
pub(crate) struct AsyncGate(Mutex<(bool, Vec<Waker>)>);
pub(crate) struct AsyncGateGuard<'a>(&'a AsyncGate);
impl AsyncGate {
    pub(crate) const fn new() -> Self { Self(Mutex::new((false, Vec::new()))) }
    pub(crate) async fn lock(&self) -> AsyncGateGuard<'_> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if !state.0 { state.0 = true; Poll::Ready(AsyncGateGuard(self)) }
            else {
                if !state.1.iter().any(|wake| wake.will_wake(cx.waker())) { state.1.push(cx.waker().clone()); }
                Poll::Pending
            }
        }).await
    }
}
impl Drop for AsyncGateGuard<'_> {
    fn drop(&mut self) {
        let wakes = { let mut state = self.0.0.lock().unwrap(); state.0 = false; std::mem::take(&mut state.1) };
        for wake in wakes { wake.wake(); }
    }
}

/// Synchronous callers may await the same wakeable operation without creating
/// another service thread. Background requests use the Future directly.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) { self.0.unpark(); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.unpark(); }
    }
    let wake = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut Context::from_waker(&wake)) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

pub(crate) const MAX_PENDING_JOBS: usize = 4096;

pub(crate) struct Scheduler {
    capacity: usize,
    next_id: AtomicU64,
    pool: OnceLock<rayon::ThreadPool>,
    state: Mutex<Admission>,
    driver: OnceLock<mpsc::Sender<DriverEvent>>,
    initialize: Mutex<()>,
    #[cfg(test)]
    pub(super) fail_pool: AtomicUsize,
    #[cfg(test)]
    pub(super) fail_driver: AtomicBool,
}

#[derive(Default)]
struct Admission {
    active: usize,
    limit: Option<usize>,
    pending: usize,
    sequence: u64,
    waiting: VecDeque<(u64, Origin, Grant)>,
    foreground: Queue,
    watch: Queue,
}

#[derive(Default)]
struct Queue {
    order: VecDeque<u64>,
    requests: HashMap<u64, StageQueue>,
}

struct Grant {
    id: usize,
    tx: Signals,
    priority: usize,
    sequence: u64,
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

#[derive(Default)]
struct StageQueue([VecDeque<Grant>; 6]);
impl StageQueue {
    fn push(&mut self, grant: Grant) { self.0[grant.priority].push_back(grant); }
    fn is_empty(&self) -> bool { self.0.iter().all(VecDeque::is_empty) }
    fn pop(&mut self, sequence: u64) -> Grant {
        let priority = self.0.iter().enumerate().filter_map(|(priority, bucket)| {
            bucket.front().map(|grant| (priority, priority as u64 * 10 + (sequence - grant.sequence) / 32, grant.sequence))
        }).max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.cmp(&a.2))).unwrap().0;
        self.0[priority].pop_front().unwrap()
    }
    fn remove(&mut self, id: usize) -> bool {
        for bucket in &mut self.0 {
            if let Some(index) = bucket.iter().position(|grant| grant.id == id) {
                bucket.remove(index);
                return true;
            }
        }
        false
    }
}

fn stage_priority(stage: &str) -> usize {
    if stage.contains("background") { 0 }
    else if ["cancel", "close", "cleanup"].iter().any(|word| stage.contains(word)) { 5 }
    else if ["commit", "postprocess", "promotion"].iter().any(|word| stage.contains(word)) { 4 }
    else if ["verify", "continuation"].iter().any(|word| stage.contains(word)) { 3 }
    else if ["preflight", "admission", "plan"].iter().any(|word| stage.contains(word)) { 2 }
    else { 1 }
}

impl Queue {
    fn push(&mut self, request: u64, grant: Grant) {
        self.requests.entry(request).or_insert_with(|| {
            self.order.push_back(request);
            StageQueue::default()
        }).push(grant);
    }
    fn pop(&mut self, sequence: u64) -> Option<Grant> {
        let request = self.order.pop_front()?;
        let tasks = self.requests.get_mut(&request).unwrap();
        let grant = tasks.pop(sequence);
        if tasks.is_empty() { self.requests.remove(&request); }
        else {
            // User policy: drain a ready batch instead of main's per-stage
            // request rotation. Foreground selection remains above Watch.
            self.order.push_front(request);
        }
        crate::collections::trim_map(&mut self.requests);
        crate::collections::trim_deque(&mut self.order);
        Some(grant)
    }
    fn remove(&mut self, request: u64, id: usize) -> bool {
        let Some(tasks) = self.requests.get_mut(&request) else { return false };
        let removed = tasks.remove(id);
        if tasks.is_empty() {
            self.requests.remove(&request);
            self.order.retain(|item| *item != request);
            crate::collections::trim_map(&mut self.requests);
            crate::collections::trim_deque(&mut self.order);
        }
        removed
    }
}

impl Admission {
    fn has_queued_work(&self) -> bool {
        self.pending != self.active || !self.waiting.is_empty()
    }

    fn queue(&mut self, request: u64, origin: Origin, mut grant: Grant) {
        self.sequence += 1;
        grant.sequence = self.sequence;
        self.pending += 1;
        match origin { Origin::Foreground => &mut self.foreground, Origin::Watch => &mut self.watch }.push(request, grant);
    }
    fn promote_waiters(&mut self, limit: usize) {
        while self.pending < limit {
            let Some((request, origin, grant)) = self.waiting.pop_front() else { break };
            self.queue(request, origin, grant);
        }
        crate::collections::trim_deque(&mut self.waiting);
    }
    fn pop(&mut self) -> Option<Grant> {
        self.foreground.pop(self.sequence).or_else(|| self.watch.pop(self.sequence))
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
    pub(crate) fn new() -> Arc<Self> {
        Self::with_capacity(std::thread::available_parallelism().map_or(1, usize::from).clamp(4, 32))
    }

    fn with_capacity(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            next_id: AtomicU64::new(1),
            pool: OnceLock::new(),
            state: Mutex::default(),
            driver: OnceLock::new(),
            initialize: Mutex::new(()),
            #[cfg(test)]
            fail_pool: AtomicUsize::new(0),
            #[cfg(test)]
            fail_driver: AtomicBool::new(false),
        })
    }

    fn pool(&self) -> io::Result<&rayon::ThreadPool> {
        if let Some(pool) = self.pool.get() { return Ok(pool); }
        let _initialize = self.initialize.lock().unwrap();
        if let Some(pool) = self.pool.get() { return Ok(pool); }
        #[cfg(test)]
        {
            let mut left = self.fail_pool.load(Ordering::Relaxed);
            while left != 0 {
                match self.fail_pool.compare_exchange_weak(left, left - 1, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return Err(io::Error::other("injected stage thread creation failure")),
                    Err(current) => left = current,
                }
            }
        }
        let pool = rayon::ThreadPoolBuilder::new().num_threads(self.capacity)
            .thread_name(|id| format!("sunpack-stage-{id}"))
            .build().map_err(io::Error::other)?;
        let _ = self.pool.set(pool);
        Ok(self.pool.get().unwrap())
    }

    pub(crate) fn prepare_submit(self: &Arc<Self>) -> io::Result<PreparedSubmit<'_>> {
        if self.driver.get().is_none() {
            let _initialize = self.initialize.lock().unwrap();
            if self.driver.get().is_none() {
                #[cfg(test)]
                if self.fail_driver.swap(false, Ordering::Relaxed) { return Err(io::Error::other("injected driver thread creation failure")); }
                let (tx, rx) = mpsc::channel();
                std::thread::Builder::new().name("sunpack-request-driver".into())
                    .spawn(move || drive_owned(rx))?;
                let _ = self.driver.set(tx);
            }
        }
        Ok(PreparedSubmit(self))
    }

    pub(crate) fn next_id(&self) -> u64 { self.next_id.fetch_add(1, Ordering::Relaxed) }

    fn acquire_or_queue(
        self: &Arc<Self>, request: u64, origin: Origin, id: usize, tx: &Signals, stage: &str,
    ) -> Option<Slot> {
        let mut state = self.state.lock().unwrap();
        let spare = state.active < state.limit.unwrap_or(self.capacity);
        if spare && !state.has_queued_work() {
            // With no older work, hand the slot straight to the request
            // driver. Queueing would allocate a bucket and send it back to
            // the same driver as a Granted signal.
            state.sequence += 1;
            state.active += 1;
            state.pending += 1;
            return Some(Slot(Some(Arc::clone(self))));
        }
        let grant = Grant { id, tx: tx.clone(), priority: stage_priority(stage), sequence: 0 };
        if state.pending == MAX_PENDING_JOBS.max(self.capacity) {
            state.waiting.push_back((request, origin, grant));
            return None;
        }
        state.queue(request, origin, grant);
        // A slot release or a capacity increase dispatches pending work.
        // Saturated submissions need only acquire the admission lock once.
        if spare {
            drop(state);
            self.dispatch();
        }
        None
    }

    /// main's worker handshake can change admission only within the original
    /// finite executor ceiling; already executing work is never preempted.
    pub(super) fn configure_capacity(self: &Arc<Self>, value: usize) {
        let value = value.max(1).min(self.capacity);
        let grew = {
            let mut state = self.state.lock().unwrap();
            let previous = state.limit.unwrap_or(self.capacity);
            state.limit = Some(value);
            value > previous
        };
        if grew { self.dispatch(); }
    }

    fn dispatch(self: &Arc<Self>) {
        loop {
            let grant = {
                let mut state = self.state.lock().unwrap();
                state.promote_waiters(MAX_PENDING_JOBS.max(self.capacity));
                if state.active >= state.limit.unwrap_or(self.capacity) { return; }
                let Some(grant) = state.pop() else { return };
                state.active += 1;
                grant
            };
            if !grant.send(self) {
                let mut state = self.state.lock().unwrap();
                state.active -= 1;
                state.pending -= 1;
            }
        }
    }

    fn withdraw(&self, request: u64, id: usize) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Some(index) = state.waiting.iter().position(|(owner, _, grant)| *owner == request && grant.id == id) {
            state.waiting.remove(index);
            crate::collections::trim_deque(&mut state.waiting);
            return true;
        }
        let removed = state.foreground.remove(request, id) || state.watch.remove(request, id);
        if removed {
            state.pending -= 1;
            state.promote_waiters(MAX_PENDING_JOBS.max(self.capacity));
        }
        removed
    }

    fn release(self: &Arc<Self>) {
        let has_queued_work = {
            let mut state = self.state.lock().unwrap();
            state.active -= 1;
            state.pending -= 1;
            state.has_queued_work()
        };
        if has_queued_work {
            self.dispatch();
        }
    }

    pub(super) fn run<'a, T: Send + 'a>(
        self: &Arc<Self>,
        request: u64,
        origin: Origin,
        cancel: &Cancellation,
        run: impl FnOnce(Spawner<'a>) -> Task<'a, T>,
    ) -> T {
        let (spawner, mut state) = RequestState::new(self, request, origin, cancel.clone(), None);
        let mut result = spawner.spawn(run(spawner.clone()));
        // Poll lightweight roots on the caller until real stage work is admitted.
        let first = loop {
            let Ok(signal) = state.ready.recv() else { break None; };
            if let Some(job) = state.handle(signal) {
                if job.slot.is_some() {
                    match self.pool() {
                        Ok(pool) => break Some((job, pool)),
                        Err(error) => job.fail_stage(error),
                    }
                } else { job.poll(); }
            }
            if state.finished() { break None; }
        };
        if let Some((first, pool)) = first { pool.in_place_scope(|scope| {
            scope.spawn(move |_| first.poll());
            while let Ok(signal) = state.ready.recv() {
                if let Some(job) = state.handle(signal) {
                    if job.slot.is_some() { scope.spawn(move |_| job.poll()); }
                    else { job.poll(); }
                }
                if state.finished() { break; }
            }
        });
        }
        result.take().expect("root poll produced a result")
    }

    /// Suspended owned requests share one wake-driven driver. Blocking stages
    /// share admission with scoped callers; no request owns an OS thread.
    fn submit_ready<T: Send + 'static>(
        self: &Arc<Self>,
        request: u64,
        origin: Origin,
        cancel: &Cancellation,
        run: impl FnOnce(Spawner<'static>) -> Task<'static, T>,
    ) -> Join<T> {
        let driver = self.driver.get().expect("prepared driver").clone();
        let (spawner, state) = RequestState::new(self, request, origin, cancel.clone(), Some(driver.clone()));
        let result = spawner.spawn(run(spawner.clone()));
        let completed = Arc::new(Completion::default());
        let reply = Arc::clone(&completed);
        let finish = Box::new(move || {
            let value = result.0.state.lock().unwrap().0.take().expect("root poll produced a result");
            reply.complete(value);
        });
        // Construction may already enqueue Spawned messages. Start drains them
        // even if their notifications arrived before the request was inserted.
        assert!(driver.send(DriverEvent::Start(request, state, finish)).is_ok());
        Join(completed)
    }
}

#[derive(Clone)]
struct Signals {
    tx: mpsc::Sender<Signal>,
    driver: Option<(u64, mpsc::Sender<DriverEvent>)>,
}

impl Signals {
    fn send(&self, signal: Signal) -> Result<(), mpsc::SendError<Signal>> {
        self.tx.send(signal)?;
        if let Some((request, driver)) = &self.driver {
            let _ = driver.send(DriverEvent::Wake(*request));
        }
        Ok(())
    }
}

type Finish = Box<dyn FnOnce() + Send>;
enum DriverEvent {
    Start(u64, RequestState<'static>, Finish),
    Wake(u64),
}

fn drive_owned(rx: mpsc::Receiver<DriverEvent>) {
    let mut requests = HashMap::<u64, (RequestState<'static>, Finish)>::new();
    while let Ok(event) = rx.recv() {
        let (request, starting) = match event {
            DriverEvent::Start(id, state, finish) => {
                assert!(requests.insert(id, (state, finish)).is_none());
                (id, true)
            }
            DriverEvent::Wake(id) => (id, false),
        };
        let Some((state, _)) = requests.get_mut(&request) else { continue };
        // Like an event-loop ready snapshot, a control task's self-wake must
        // not consume the driver indefinitely before another request's Start.
        // Start also drains the finite signals constructed before registration,
        // whose Wake notifications may already have arrived and been ignored.
        if starting {
            let signals: Vec<_> = state.ready.try_iter().collect();
            for signal in signals { dispatch_owned(state, signal); }
        } else if let Ok(signal) = state.ready.try_recv() {
            dispatch_owned(state, signal);
        }
        if state.finished() {
            let (_, finish) = requests.remove(&request).unwrap();
            crate::collections::trim_map(&mut requests);
            finish();
        }
    }
}

fn dispatch_owned(state: &mut RequestState<'static>, signal: Signal) {
    if let Some(job) = state.handle(signal) {
        if job.slot.is_some() {
            match state.scheduler.pool() {
                Ok(pool) => pool.spawn(move || job.poll()),
                Err(error) => job.fail_stage(error),
            }
        } else { job.poll(); }
    }
}

pub(crate) struct PreparedSubmit<'a>(&'a Arc<Scheduler>);
impl PreparedSubmit<'_> {
    pub(crate) fn submit<T: Send + 'static>(self, request: u64, origin: Origin,
        cancel: &Cancellation, run: impl FnOnce(Spawner<'static>) -> Task<'static, T>) -> Join<T> {
        self.0.submit_ready(request, origin, cancel, run)
    }
}
#[cfg(test)]
impl Scheduler {
    pub(crate) fn submit<T: Send + 'static>(self: &Arc<Self>, request: u64, origin: Origin,
        cancel: &Cancellation, run: impl FnOnce(Spawner<'static>) -> Task<'static, T>) -> Join<T> {
        self.prepare_submit().unwrap().submit(request, origin, cancel, run)
    }
}

struct RequestState<'a> {
    scheduler: Arc<Scheduler>,
    request: u64,
    origin: Origin,
    cancel: Cancellation,
    rx: mpsc::Receiver<Task<'a, ()>>,
    ready: mpsc::Receiver<Signal>,
    signals: Signals,
    tasks: HashMap<usize, TaskState<'a>>,
    next_id: usize,
}

impl<'a> RequestState<'a> {
    fn new(scheduler: &Arc<Scheduler>, request: u64, origin: Origin,
        cancel: Cancellation, driver: Option<mpsc::Sender<DriverEvent>>,
    ) -> (Spawner<'a>, Self) {
        let (tx, rx) = mpsc::channel();
        let (signals, ready) = mpsc::channel();
        let signals = Signals { tx: signals, driver: driver.map(|tx| (request, tx)) };
        let spawner = Spawner {
            tx, signals: signals.clone(), cancel: cancel.clone(),
            consumers: Arc::new(AtomicUsize::new(MAX_PENDING_JOBS.max(scheduler.capacity))),
        };
        (spawner, Self { scheduler: Arc::clone(scheduler), request, origin, cancel,
            rx, ready, signals, tasks: HashMap::new(), next_id: 0 })
    }

    fn finished(&self) -> bool { self.next_id != 0 && self.tasks.is_empty() }

    fn ready(&mut self, id: usize) -> Option<PollJob<'a>> {
        let stage = self.tasks[&id].wake.stage.lock().unwrap().clone();
        if let Some(stage) = stage.filter(|stage| !stage.cancel.cancelled()) {
            if let Some(slot) = self.scheduler.acquire_or_queue(self.request, self.origin, id, &self.signals, stage.name) {
                return Some(self.job(id, Some(slot)));
            }
            self.tasks.get_mut(&id).unwrap().status = Status::Queued;
            None
        } else { Some(self.job(id, None)) }
    }

    fn job(&mut self, id: usize, slot: Option<Slot>) -> PollJob<'a> {
        let task = self.tasks.get_mut(&id).unwrap();
        task.status = Status::Running { notified: false };
        PollJob { id, slot, wake: Arc::clone(&task.wake), parked: Arc::clone(&task.future),
            signals: self.signals.clone(), cancel: self.cancel.clone() }
    }

    fn handle(&mut self, signal: Signal) -> Option<PollJob<'a>> {
        match signal {
            Signal::Spawned => {
                let future = self.rx.try_recv().expect("spawn precedes its signal");
                let id = self.next_id;
                self.next_id += 1;
                let wake = Arc::new(TaskWake { id, pending: AtomicBool::new(false),
                    tx: self.signals.clone(), stage: Mutex::default() });
                self.tasks.insert(id, TaskState { wake,
                    future: Arc::new(Mutex::new(Some(future))), status: Status::Parked });
                return self.ready(id);
            }
            Signal::Wake(id) => {
                if let Some(task) = self.tasks.get_mut(&id) {
                    task.wake.pending.store(false, Ordering::Release);
                    match &mut task.status {
                        Status::Parked => return self.ready(id),
                        Status::Running { notified } => *notified = true,
                        Status::Queued => {
                            let cancelled = task.wake.stage.lock().unwrap().as_ref().is_some_and(|stage| stage.cancel.cancelled());
                            if cancelled && self.scheduler.withdraw(self.request, id) {
                                return Some(self.job(id, None));
                            }
                        }
                    }
                }
            }
            Signal::Granted(id, slot) => {
                // Dispatch owns the grant once it leaves the queue. Cancellation
                // before its first poll still skips the operation in stage().
                return Some(self.job(id, Some(slot)));
            }
            Signal::Parked(id) => {
                let task = self.tasks.get_mut(&id).unwrap();
                if matches!(task.status, Status::Running { notified: true }) {
                    return self.ready(id);
                } else { task.status = Status::Parked; }
            }
            Signal::Done(id) => {
                self.tasks.remove(&id);
                crate::collections::trim_map(&mut self.tasks);
            }
        }
        None
    }

}

struct PollJob<'a> {
    id: usize,
    slot: Option<Slot>,
    wake: Arc<TaskWake>,
    parked: Arc<Mutex<Option<Task<'a, ()>>>>,
    signals: Signals,
    cancel: Cancellation,
}

impl PollJob<'_> {
    fn fail_stage(mut self, error: io::Error) {
        if let Some(stage) = self.wake.stage.lock().unwrap().as_ref() {
            let _ = stage.failure.set(error);
        }
        drop(self.slot.take());
        self.poll();
    }

    fn poll(self) {
        let mut future = self.parked.lock().unwrap().take().unwrap();
        // A stage grant applies to this continuation only. External async wakes
        // resume as control work unless a new explicit stage boundary is reached.
        let execution_cancel = if let Some(stage) = self.wake.stage.lock().unwrap().take() {
            stage.granted.store(true, Ordering::Release);
            stage.cancel.clone()
        } else { self.cancel.clone() };
        let previous = CURRENT_TASK.with(|task| task.replace(Some(Arc::clone(&self.wake))));
        let _current = CurrentTask(previous);
        let _stage = CurrentStage(IN_STAGE.with(|active| active.replace(self.slot.is_some())));
        let waker = Waker::from(Arc::clone(&self.wake));
        // Spawner catches task panics and settles their Join before this returns.
        let signal = match execution_cancel.run(|| future.as_mut().poll(&mut Context::from_waker(&waker))) {
            Poll::Ready(()) => {
                drop(future);
                Signal::Done(self.id)
            }
            Poll::Pending => {
                *self.parked.lock().unwrap() = Some(future);
                Signal::Parked(self.id)
            }
        };
        drop(self.slot);
        let _ = self.signals.send(signal);
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
}

struct TaskWake {
    stage: Mutex<Option<Arc<StageIntent>>>,
    id: usize,
    pending: AtomicBool,
    tx: Signals,
}

thread_local! {
    static CURRENT_TASK: RefCell<Option<Arc<TaskWake>>> = const { RefCell::new(None) };
    static IN_STAGE: Cell<bool> = const { Cell::new(false) };
}
pub(crate) fn in_control_poll() -> bool {
    CURRENT_TASK.with(|task| task.borrow().is_some()) && !in_stage()
}

pub(super) fn in_stage() -> bool { IN_STAGE.with(Cell::get) }
struct CurrentStage(bool);
impl Drop for CurrentStage {
    fn drop(&mut self) { IN_STAGE.with(|active| active.set(self.0)); }
}
struct CurrentTask(Option<Arc<TaskWake>>);
impl Drop for CurrentTask {
    fn drop(&mut self) { CURRENT_TASK.with(|task| { task.replace(self.0.take()); }); }
}
struct StageIntent {
    name: &'static str,
    cancel: Cancellation,
    granted: AtomicBool,
    failure: OnceLock<io::Error>,
}

/// The future owns its stack across this boundary. Only the synchronous stage
/// continuation consumes blocking capacity; ordinary async wakeups do not.
pub(crate) async fn stage(name: &'static str, cancel: &Cancellation) -> io::Result<()> {
    let mut intent: Option<Arc<StageIntent>> = None;
    let mut subscription = None;
    poll_fn(|cx| {
        cancel.check_io()?;
        if let Some(error) = intent.as_ref().and_then(|stage| stage.failure.get()) {
            return Poll::Ready(Err(io::Error::new(error.kind(), error.to_string())));
        }
        if intent.as_ref().is_some_and(|stage| stage.granted.load(Ordering::Acquire)) {
            return Poll::Ready(Ok(()));
        }
        let Some(task) = CURRENT_TASK.with(|task| task.borrow().clone()) else {
            // Synchronous helpers/tests outside a request already own their caller.
            return Poll::Ready(Ok(()));
        };
        if intent.is_none() {
            let stage = Arc::new(StageIntent { name, cancel: cancel.clone(), granted: AtomicBool::new(false), failure: OnceLock::new() });
            *task.stage.lock().unwrap() = Some(Arc::clone(&stage));
            intent = Some(stage);
            let wake = cx.waker().clone();
            subscription = cancel.subscribe(move || wake.wake_by_ref());
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }).await
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

pub(crate) type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub(crate) struct Spawner<'a> {
    tx: mpsc::Sender<Task<'a, ()>>,
    signals: Signals,
    cancel: Cancellation,
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

type Panic = Box<dyn std::any::Any + Send>;
struct Completion<T> {
    state: Mutex<(Option<Result<T, Panic>>, Option<Waker>, Option<Finish>)>,
}
impl<T> Default for Completion<T> {
    fn default() -> Self { Self { state: Mutex::new((None, None, None)) } }
}
impl<T> Completion<T> {
    fn complete(&self, value: Result<T, Panic>) {
        let (wake, notify) = {
            let mut state = self.state.lock().unwrap();
            state.0 = Some(value);
            (state.1.take(), state.2.take())
        };
        if let Some(wake) = wake { wake.wake(); }
        if let Some(notify) = notify { notify(); }
    }
}

pub(crate) struct Join<T>(Arc<Completion<T>>);
fn completed<T>(value: Result<T, Panic>) -> T {
    value.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}
impl<T> Join<T> {
    pub(crate) fn ready(value: T) -> Self {
        let result = Arc::new(Completion::default());
        result.complete(Ok(value));
        Self(result)
    }
    fn take(&mut self) -> Option<T> {
        let value = self.0.state.lock().unwrap().0.take();
        value.map(completed)
    }
    /// Like main's Task done callback, notify only after the complete request
    /// (including all children) has published its result, never from root Drop.
    pub(crate) fn on_ready(&self, notify: impl FnOnce() + Send + 'static) {
        let notify: Finish = Box::new(notify);
        let mut state = self.0.state.lock().unwrap();
        if state.0.is_none() {
            assert!(state.2.is_none(), "completion notification already registered");
            state.2 = Some(notify);
        } else {
            drop(state);
            notify();
        }
    }
    pub(crate) fn is_finished(&self) -> bool { self.0.state.lock().unwrap().0.is_some() }
    pub(crate) fn join(self) -> std::thread::Result<T> { block_on(self.result()) }
    #[cfg(test)]
    fn blocking_wait(self) -> T { completed(self.join()) }
    pub(crate) async fn wait(self) -> T { completed(self.result().await) }
    async fn result(self) -> std::thread::Result<T> {
        poll_fn(|cx| {
            let mut state = self.0.state.lock().unwrap();
            if let Some(value) = state.0.take() { Poll::Ready(value) }
            else { state.1 = Some(cx.waker().clone()); Poll::Pending }
        }).await
    }
}

impl<'a> Spawner<'a> {
    /// Consume a batch using a shared request-level budget, as the original
    /// coordinator did. A recursive batch with no free consumers runs inline
    /// in its parent, so parents never wait for admission held by themselves.
    /// Each consumer takes the next item immediately after finishing its own;
    /// a slow early item cannot stall admission of the rest of the batch.
    pub(crate) fn bounded_map<I, T, F>(&self, items: Vec<I>, operation: F) -> Task<'a, Vec<T>>
    where
        I: Send + 'a,
        T: Send + 'a,
        F: Fn(I) -> Task<'a, T> + Send + Sync + 'a,
    {
        let spawner = self.clone();
        Box::pin(async move {
            if spawner.cancel.cancelled() { return Vec::new(); }
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
                    if spawner.cancel.cancelled() { break; }
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
                let cancel = spawner.cancel.clone();
                consumers.push(spawner.spawn(Box::pin(async move {
                    loop {
                        // Cancellation stops claiming the tail, but already
                        // started operations still run to their cleanup barrier.
                        if cancel.cancelled() { break; }
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
            // Every consumer has joined. Cancelled batches leave unclaimed
            // slots empty; retain only dispatched results, in discovery order.
            let results = std::mem::take(&mut *results.lock().unwrap());
            results.into_iter().flatten().collect()
        })
    }

    pub(crate) fn spawn<T: Send + 'a>(&self, future: Task<'a, T>) -> Join<T> {
        let cell = Arc::new(Completion::default());
        let receiver = Arc::clone(&cell);
        let cancel = self.cancel.clone();
        let mut future = future;
        let future = Box::pin(async move {
            let value = poll_fn(|cx| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                    Ok(Poll::Pending) => Poll::Pending,
                    Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
                    Err(panic) => { cancel.cancel(); Poll::Ready(Err(panic)) }
                }
            }).await;
            cell.complete(value);
        });
        assert!(self.tx.send(future).is_ok());
        assert!(self.signals.send(Signal::Spawned).is_ok());
        Join(receiver)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/pipeline/scheduling/tests.rs"]
mod tests;
