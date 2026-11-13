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
    pool: rayon::ThreadPool,
    state: Mutex<Admission>,
    driver: OnceLock<mpsc::Sender<DriverEvent>>,
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
    let stage = stage.to_ascii_lowercase();
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
            pool: rayon::ThreadPoolBuilder::new().num_threads(capacity)
                .thread_name(|id| format!("sunpack-stage-{id}"))
                .build().expect("start shared stage executor"),
            state: Mutex::default(),
            driver: OnceLock::new(),
        })
    }

    pub(crate) fn next_id(&self) -> u64 { self.next_id.fetch_add(1, Ordering::Relaxed) }

    fn enqueue(self: &Arc<Self>, request: u64, origin: Origin, grant: Grant) {
        let mut state = self.state.lock().unwrap();
        if state.pending == MAX_PENDING_JOBS.max(self.capacity) {
            state.waiting.push_back((request, origin, grant));
            return;
        }
        state.queue(request, origin, grant);
        drop(state);
        self.dispatch();
    }

    /// main's worker handshake can change admission only within the original
    /// finite executor ceiling; already executing work is never preempted.
    pub(super) fn configure_capacity(self: &Arc<Self>, value: usize) {
        self.state.lock().unwrap().limit = Some(value.max(1).min(self.capacity));
        self.dispatch();
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
        {
            let mut state = self.state.lock().unwrap();
            state.active -= 1;
            state.pending -= 1;
        }
        self.dispatch();
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
        self.pool.in_place_scope(|scope| {
            while let Ok(signal) = state.ready.recv() {
                if let Some(job) = state.handle(signal) {
                    if job.slot.is_some() { scope.spawn(move |_| job.poll()); }
                    else { job.poll(); }
                }
                if state.finished() { break; }
            }
        });
        result.take().expect("root poll produced a result")
    }

    /// Suspended owned requests share one wake-driven driver. Blocking stages
    /// share admission with scoped callers; no request owns an OS thread.
    pub(crate) fn submit<T: Send + 'static>(
        self: &Arc<Self>,
        request: u64,
        origin: Origin,
        cancel: &Cancellation,
        run: impl FnOnce(Spawner<'static>) -> Task<'static, T>,
    ) -> Join<T> {
        let driver = self.driver.get_or_init(|| {
            let (tx, rx) = mpsc::channel();
            std::thread::Builder::new().name("sunpack-request-driver".into())
                .spawn(move || drive_owned(rx)).expect("start request driver");
            tx
        }).clone();
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

    fn enqueue_poll(
        self: &Arc<Self>,
        request: u64,
        origin: Origin,
        id: usize,
        tx: &Signals,
        stage: &str,
    ) {
        self.enqueue(request, origin, Grant { id, tx: tx.clone(), priority: stage_priority(stage), sequence: 0 });
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
        if job.slot.is_some() { state.scheduler.pool.spawn(move || job.poll()); }
        else { job.poll(); }
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
            self.tasks.get_mut(&id).unwrap().status = Status::Queued;
            self.scheduler.enqueue_poll(self.request, self.origin, id, &self.signals, stage.name);
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
            Signal::Done(id) => { self.tasks.remove(&id); }
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
}

/// The future owns its stack across this boundary. Only the synchronous stage
/// continuation consumes blocking capacity; ordinary async wakeups do not.
pub(crate) async fn stage(name: &'static str, cancel: &Cancellation) -> io::Result<()> {
    let mut intent: Option<Arc<StageIntent>> = None;
    let mut subscription = None;
    poll_fn(|cx| {
        cancel.check_io()?;
        if intent.as_ref().is_some_and(|stage| stage.granted.load(Ordering::Acquire)) {
            return Poll::Ready(Ok(()));
        }
        let Some(task) = CURRENT_TASK.with(|task| task.borrow().clone()) else {
            // Synchronous helpers/tests outside a request already own their caller.
            return Poll::Ready(Ok(()));
        };
        if intent.is_none() {
            let stage = Arc::new(StageIntent { name, cancel: cancel.clone(), granted: AtomicBool::new(false) });
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
    fn take(&mut self) -> Option<T> {
        self.0.state.lock().unwrap().0.take().map(completed)
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
mod tests {
    use super::*;
    use std::time::Duration;

    fn single_slot() -> Arc<Scheduler> {
        Scheduler::with_capacity(1)
    }

    #[test]
    fn owned_requests_park_without_holding_host_slots() {
        let scheduler = single_slot();
        let gate = Arc::new(Mutex::new((false, Vec::<Waker>::new())));
        let (parked, arrivals) = mpsc::channel();
        let mut joins = Vec::new();
        for id in 1..=64 {
            let gate = Arc::clone(&gate);
            let parked = parked.clone();
            joins.push(scheduler.submit(id, Origin::Watch, &Cancellation::new(), |_| {
                Box::pin(async move {
                    poll_fn(|cx| {
                        let mut gate = gate.lock().unwrap();
                        if gate.0 { Poll::Ready(()) } else {
                            gate.1.push(cx.waker().clone());
                            parked.send(()).unwrap();
                            Poll::Pending
                        }
                    }).await;
                    id
                })
            }));
        }
        for _ in 0..64 { arrivals.recv_timeout(Duration::from_secs(10)).unwrap(); }
        let foreground = scheduler.submit(65, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async { 7 }));
        assert_eq!(foreground.blocking_wait(), 7);
        let wakes = {
            let mut gate = gate.lock().unwrap();
            gate.0 = true;
            std::mem::take(&mut gate.1)
        };
        for wake in wakes { wake.wake(); }
        for (index, join) in joins.into_iter().enumerate() {
            assert_eq!(join.blocking_wait(), index as u64 + 1);
        }
    }

    #[test]
    fn owned_control_wake_progresses_while_only_stage_slot_is_blocked() {
        let scheduler = single_slot();
        let (blocked, blocked_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (waiting, waiting_rx) = mpsc::channel();
        let (progress, progress_rx) = mpsc::channel();
        let gate = Arc::new(Mutex::new((false, None::<Waker>)));
        let signal = Arc::clone(&gate);
        let join = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |spawner| Box::pin(async move {
            let slow = spawner.spawn(Box::pin(async move {
                stage("scan", &Cancellation::new()).await.unwrap();
                blocked.send(()).unwrap();
                release_rx.recv().unwrap();
            }));
            let ready = spawner.spawn(Box::pin(async move {
                poll_fn(|cx| {
                    let mut gate = gate.lock().unwrap();
                    if gate.0 { Poll::Ready(()) } else {
                        if gate.1.is_none() { waiting.send(()).unwrap(); }
                        gate.1 = Some(cx.waker().clone());
                        Poll::Pending
                    }
                }).await;
                progress.send(()).unwrap();
            }));
            slow.wait().await;
            ready.wait().await;
        }));
        blocked_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let wake = {
            let mut gate = signal.lock().unwrap();
            gate.0 = true;
            gate.1.take().unwrap()
        };
        // Coalescing repeated wakes must neither poll concurrently nor lose the wake.
        for _ in 0..100 { wake.wake_by_ref(); }
        let independent = progress_rx.recv_timeout(Duration::from_secs(10));
        release.send(()).unwrap();
        join.blocking_wait();
        independent.expect("a scoped poll wave blocked its independently woken sibling");
    }

    #[test]
    fn cancelled_queued_stage_settles_without_waiting_for_busy_stage() {
        let scheduler = single_slot();
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let active = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |_| Box::pin(async move {
            stage("scan", &Cancellation::new()).await.unwrap();
            entered.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let cancel = Cancellation::new();
        let token = cancel.clone();
        let (settled, settled_rx) = mpsc::channel();
        let pending = scheduler.submit(2, Origin::Watch, &cancel, |_| Box::pin(async move {
            let cancelled = stage("cleanup", &token).await.is_err();
            settled.send(cancelled).unwrap();
        }));
        // The shared driver's FIFO Start handling has admitted request 2 before
        // this control-only request completes, despite the occupied worker.
        scheduler.submit(3, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async {})).blocking_wait();
        assert_eq!(scheduler.state.lock().unwrap().pending, 2);
        cancel.cancel();
        let result = settled_rx.recv_timeout(Duration::from_secs(10));
        release.send(()).unwrap();
        active.blocking_wait();
        pending.blocking_wait();
        assert_eq!(result.unwrap(), true);
        assert_eq!(scheduler.state.lock().unwrap().pending, 0);
    }

    #[test]
    fn owned_panic_cancels_and_joins_other_request_writers() {
        let scheduler = single_slot();
        let cancel = Cancellation::new();
        let observed = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&observed);
        let token = cancel.clone();
        let join = scheduler.submit(1, Origin::Watch, &cancel, |spawner| Box::pin(async move {
            let child = spawner.spawn(Box::pin(async move {
                let mut subscription = None;
                poll_fn(|cx| {
                    if token.cancelled() { return Poll::Ready(()); }
                    let wake = cx.waker().clone();
                    subscription = token.subscribe(move || wake.wake_by_ref());
                    if token.cancelled() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                drop(subscription);
                stage("cancel_cleanup", &Cancellation::new()).await.unwrap();
                Cancellation::check_current_io().expect("cleanup must use its own uncancelled native scope");
                finished.store(true, Ordering::Release);
            }));
            let failed = spawner.spawn(Box::pin(async { panic!("owned task panic"); }));
            failed.wait().await;
            child.wait().await;
        }));
        let (notified, notification) = mpsc::channel();
        let at_completion = Arc::clone(&observed);
        join.on_ready(move || notified.send(at_completion.load(Ordering::Acquire)).unwrap());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join.blocking_wait())).is_err());
        assert!(cancel.cancelled());
        assert!(observed.load(Ordering::Acquire), "root completed before its writer settled");
        assert!(notification.recv_timeout(Duration::from_secs(10)).unwrap(),
            "done callback overtook a child writer's cleanup");
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
    fn cancelled_batches_stop_the_tail_and_join_started_consumers() {
        for capacity in [0, 2] {
            let scheduler = single_slot();
            let cancel = Cancellation::new();
            let token = cancel.clone();
            let results = scheduler.run(1, Origin::Foreground, &cancel, |spawner| {
                Box::pin(async move {
                    spawner.consumers.store(capacity, Ordering::Release);
                    let gate = Arc::new(Mutex::new((false, None::<Waker>)));
                    let results = spawner.bounded_map((0..100).collect(), move |item| {
                        let gate = Arc::clone(&gate);
                        let token = token.clone();
                        Box::pin(async move {
                            if capacity == 2 && item == 0 {
                                poll_fn(|cx| {
                                    let mut gate = gate.lock().unwrap();
                                    if gate.0 { Poll::Ready(()) } else {
                                        gate.1 = Some(cx.waker().clone()); Poll::Pending
                                    }
                                }).await;
                            } else {
                                token.cancel();
                                let mut gate = gate.lock().unwrap();
                                gate.0 = true;
                                if let Some(waker) = gate.1.take() { waker.wake(); }
                            }
                            item
                        })
                    }).await;
                    assert_eq!(spawner.consumers.load(Ordering::Acquire), capacity);
                    results
                })
            });
            assert_eq!(results, if capacity == 0 { vec![0] } else { vec![0, 1] });
        }
    }

    #[test]
    fn control_self_wakes_do_not_starve_new_requests() {
        let scheduler = single_slot();
        let released = Arc::new(AtomicBool::new(false));
        let gate = Arc::clone(&released);
        let (started, started_rx) = mpsc::channel();
        let busy = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |_| Box::pin(async move {
            let mut started = Some(started);
            poll_fn(|cx| {
                if let Some(started) = started.take() { started.send(()).unwrap(); }
                if gate.load(Ordering::Acquire) { Poll::Ready(()) }
                else { cx.waker().wake_by_ref(); Poll::Pending }
            }).await
        }));
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (finished, finished_rx) = mpsc::channel();
        let other = scheduler.submit(2, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
            finished.send(()).unwrap();
        }));
        let result = finished_rx.recv_timeout(Duration::from_secs(10));
        released.store(true, Ordering::Release);
        busy.blocking_wait();
        other.blocking_wait();
        result.expect("a self-waking control task monopolized the shared driver");
    }

    #[test]
    fn stage_pool_keeps_main_minimum_capacity_and_nested_rayon_progress() {
        let small_host = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let scheduler = small_host.install(|| Scheduler::with_capacity(4));
        assert_eq!(scheduler.pool.current_num_threads(), 4);
        let (entered, entered_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let held = Arc::clone(&gate);
        let request = scheduler.submit(1, Origin::Watch, &Cancellation::new(), |spawner| Box::pin(async move {
            spawner.bounded_map(vec![0, 1, 2, 3], move |index| {
                let gate = Arc::clone(&held);
                let entered = entered.clone();
                Box::pin(async move {
                    stage("scan", &Cancellation::new()).await.unwrap();
                    entered.send(()).unwrap();
                    drop(gate.1.wait_while(gate.0.lock().unwrap(), |ready| !*ready).unwrap());
                    let (a, b) = rayon::join(|| index + 1, || index + 2);
                    a + b
                })
            }).await
        }));
        let progress = (0..4).try_for_each(|_| entered_rx.recv_timeout(Duration::from_secs(10)));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert_eq!(request.blocking_wait(), vec![3, 5, 7, 9]);
        progress.expect("stage executor inherited a smaller unrelated Rayon pool");
    }

    #[test]
    fn global_stage_budget_releases_cancelled_admission_to_oldest_waiter() {
        let scheduler = single_slot();
        let (tx, rx) = mpsc::channel();
        let signals = Signals { tx, driver: None };
        for id in 0..=MAX_PENDING_JOBS {
            scheduler.enqueue_poll(1, Origin::Watch, id, &signals, "scan");
        }
        {
            let state = scheduler.state.lock().unwrap();
            assert_eq!(state.pending, MAX_PENDING_JOBS);
            assert_eq!(state.waiting.len(), 1);
            assert_eq!(state.sequence, MAX_PENDING_JOBS as u64);
        }
        assert!(scheduler.withdraw(1, 1));
        {
            let state = scheduler.state.lock().unwrap();
            assert_eq!(state.pending, MAX_PENDING_JOBS);
            assert!(state.waiting.is_empty());
            assert_eq!(state.sequence, MAX_PENDING_JOBS as u64 + 1);
        }
        for _ in 0..MAX_PENDING_JOBS {
            let Signal::Granted(id, slot) = rx.recv().unwrap() else { panic!("grant") };
            assert_ne!(id, 1);
            drop(slot);
        }
        assert_eq!(scheduler.state.lock().unwrap().pending, 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn stage_priority_aging_and_handshake_capacity_match_main() {
        let scheduler = Scheduler::with_capacity(2);
        let (tx, rx) = mpsc::channel();
        let signals = Signals { tx, driver: None };
        scheduler.configure_capacity(100);
        assert_eq!(scheduler.state.lock().unwrap().limit, Some(2));
        scheduler.enqueue_poll(1, Origin::Watch, 0, &signals, "scan");
        scheduler.enqueue_poll(1, Origin::Watch, 1, &signals, "scan");
        let Signal::Granted(_, first) = rx.recv().unwrap() else { panic!("grant") };
        let Signal::Granted(_, second) = rx.recv().unwrap() else { panic!("grant") };
        scheduler.configure_capacity(1);
        scheduler.enqueue_poll(1, Origin::Watch, 2, &signals, "background_scan");
        scheduler.enqueue_poll(1, Origin::Watch, 3, &signals, "cleanup");
        drop(first);
        assert!(rx.try_recv().is_err(), "lowered capacity must wait for executing work");
        drop(second);
        let Signal::Granted(id, slot) = rx.recv().unwrap() else { panic!("grant") };
        assert_eq!(id, 3);
        drop(slot);
        let Signal::Granted(id, slot) = rx.recv().unwrap() else { panic!("grant") };
        assert_eq!(id, 2);
        drop(slot);
        assert_eq!(scheduler.state.lock().unwrap().pending, 0);

        // main selects six FIFO bucket heads by priority + sequence_age / 32,
        // breaking ties toward the oldest job, rather than permanently starving background work.
        let mut queue = StageQueue::default();
        queue.push(Grant { id: 10, tx: signals.clone(), priority: stage_priority("background"), sequence: 1 });
        queue.push(Grant { id: 11, tx: signals, priority: stage_priority("cleanup"), sequence: 1601 });
        assert_eq!(queue.pop(1601).id, 10);
        assert_eq!(queue.pop(1601).id, 11);
    }

    #[test]
    fn ready_batches_drain_in_order_after_foreground_work() {
        let scheduler = single_slot();
        let (tx, rx) = mpsc::channel();
        for (request, origin, index) in [
            (0, Origin::Watch, 0),
            (1, Origin::Watch, 1),
            (1, Origin::Watch, 2),
            (2, Origin::Watch, 3),
            (3, Origin::Foreground, 4),
        ] {
            scheduler.enqueue_poll(request, origin, index, &Signals { tx: tx.clone(), driver: None }, "scan");
        }
        let mut order = Vec::new();
        while let Ok(Signal::Granted(id, slot)) = rx.try_recv() {
            order.push(id);
            drop(slot);
        }
        assert_eq!(order, [0, 4, 1, 2, 3]);
    }
}
