//! Request cancellation shared by native IO, analysis and password work.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

thread_local! {
    static SCOPES: RefCell<Vec<Cancellation>> = const { RefCell::new(Vec::new()) };
}

type Wake = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Wakes {
    next: u64,
    callbacks: HashMap<u64, Wake>,
}

#[derive(Default)]
struct State {
    flag: Arc<AtomicBool>,
    wakes: Mutex<Wakes>,
}

impl State {
    fn cancel(&self) {
        if self.flag.swap(true, Ordering::Relaxed) {
            return;
        }
        let wakes = std::mem::take(
            &mut self
                .wakes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .callbacks,
        );
        for wake in wakes.into_values() {
            wake();
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Cancellation(Option<Arc<State>>);

impl Cancellation {
    pub(crate) fn current() -> Self {
        SCOPES.with(|scopes| scopes.borrow().last().cloned().unwrap_or_default())
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|state| state.flag.load(Ordering::Relaxed))
    }

    pub(crate) fn flag(&self) -> Option<Arc<AtomicBool>> {
        self.0.as_ref().map(|state| Arc::clone(&state.flag))
    }

    pub(crate) fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        SCOPES.with(|scopes| scopes.borrow_mut().push(self.clone()));
        let _scope = Scope;
        operation()
    }

    pub(crate) fn new() -> Self {
        Self(Some(Arc::new(State::default())))
    }

    pub(crate) fn cancel(&self) {
        if let Some(state) = &self.0 {
            state.cancel();
        }
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        self.check_io()
    }

    pub(crate) fn check_io(&self) -> io::Result<()> {
        if self.cancelled() {
            Err(cancelled_io())
        } else {
            Ok(())
        }
    }

    // Reads check the TLS scope without cloning an Arc for every small field.
    pub(crate) fn check_current_io() -> io::Result<()> {
        let cancelled = SCOPES.with(|scopes| scopes.borrow().last().is_some_and(Self::cancelled));
        if cancelled {
            Err(cancelled_io())
        } else {
            Ok(())
        }
    }

    pub(crate) fn subscribe(
        &self,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Option<Subscription> {
        let state = self.0.as_ref()?;
        let mut wakes = state
            .wakes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.cancelled() {
            drop(wakes);
            wake();
            return None;
        }
        let id = wakes.next;
        wakes.next += 1;
        wakes.callbacks.insert(id, Box::new(wake));
        Some(Subscription {
            state: Arc::clone(state),
            id,
        })
    }
}

pub(crate) fn cancelled_io() -> io::Error {
    // Interrupted is automatically retried by Read::read_exact/read_to_end.
    io::Error::other(Cancelled)
}

/// Keep cancellation distinguishable from real IO failures with the same kind.
/// In particular, Interrupted cannot be used because Read retries it internally.
#[derive(Debug)]
struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native operation cancelled")
    }
}

impl std::error::Error for Cancelled {}

pub(crate) fn is_cancellation(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|error| error.is::<Cancelled>())
}

pub(crate) struct Subscription {
    state: Arc<State>,
    id: u64,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut wakes = self
            .state
            .wakes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let removed = wakes.callbacks.remove(&self.id);
        if wakes.callbacks.capacity() > 256 {
            crate::collections::trim_map(&mut wakes.callbacks);
        }
        drop(wakes);
        drop(removed);
    }
}

/// Shared initializers publish archive facts only when their owner completes.
/// None retires this slot; an uncancelled borrower retries in the existing cache.
pub(crate) struct CancellableOnce<T>(OnceLock<Option<T>>);

impl<T> Default for CancellableOnce<T> {
    fn default() -> Self {
        Self(OnceLock::new())
    }
}

impl<T> CancellableOnce<T> {
    pub(crate) fn get_or_init(
        &self,
        cancellation: &Cancellation,
        initialize: impl FnOnce() -> T,
    ) -> Option<&T> {
        self.0
            .get_or_init(|| {
                let result = initialize();
                (!cancellation.cancelled()).then_some(result)
            })
            .as_ref()
    }

    pub(crate) fn get(&self) -> Option<&T> {
        self.0.get().and_then(Option::as_ref)
    }
}

struct Scope;
impl Drop for Scope {
    fn drop(&mut self) {
        SCOPES.with(|scopes| {
            scopes.borrow_mut().pop();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{iocp, ScanBatch};
    use std::sync::mpsc;

    #[test]
    fn cancellation_marker_preserves_io_errors_and_stops_read_retry_helpers() {
        use std::io::Read;

        // A kind-only test misses both false-positive Interrupted errors and
        // the standard Read helpers silently retrying genuine cancellation.
        let cancel = Cancellation::new();
        cancel.cancel();
        for error in [
            cancel.check().unwrap_err(),
            cancel.check_io().unwrap_err(),
            cancel.run(Cancellation::check_current_io).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(is_cancellation(&error));
        }
        for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
            assert!(!is_cancellation(&io::Error::new(kind, "native operation cancelled")));
        }
        struct CancelledRead<'a>(&'a Cancellation, usize);
        impl Read for CancelledRead<'_> {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.1 += 1;
                assert_eq!(self.1, 1, "Read retried a cancelled operation");
                self.0.check_io()?;
                Ok(0)
            }
        }
        let error = CancelledRead(&cancel, 0).read_exact(&mut [0; 1]).unwrap_err();
        assert!(is_cancellation(&error));
        let error = CancelledRead(&cancel, 0).read_to_end(&mut Vec::new()).unwrap_err();
        assert!(is_cancellation(&error));
    }

    #[test]
    fn cancellation_drains_live_scan_and_preserves_other_requests() {
        // Password-only cancellation cannot find abandoned OVERLAPPED buffers,
        // lost completion-port wakes, or a flag leaking into the next scan.
        // One bounded IO window plus a complete surviving scan covers all three.
        let path = std::env::temp_dir().join(format!(
            "sunpack_cancel_scan_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let size = 8 * 1024 * 1024;
        std::fs::write(&path, vec![0x5a; size]).unwrap();
        let state = Arc::new(State::default());
        let signal = Arc::clone(&state);
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (released_tx, released_rx) = mpsc::sync_channel(1);
        let released_rx = Mutex::new(released_rx);
        let first = AtomicBool::new(true);
        let canceller = std::thread::spawn(move || {
            entered_rx.recv().unwrap();
            signal.cancel();
            released_tx.send(()).unwrap();
        });
        let mut matched = 0;
        let result = Cancellation(Some(Arc::clone(&state))).run(|| {
            iocp::scan_file(
                &path,
                size as u64,
                64 * 1024,
                2,
                1,
                0,
                |data, _, _| {
                    if first.swap(false, Ordering::Relaxed) {
                        entered_tx.send(()).unwrap();
                        released_rx.lock().unwrap().recv().unwrap();
                    }
                    ScanBatch {
                        results: data.len(),
                        discarded_results: 0,
                    }
                },
                |count| {
                    matched += count;
                    Ok(())
                },
            )
        });
        canceller.join().unwrap();
        assert!(result.is_err());
        assert!(matched < size);
        assert!(state.wakes.lock().unwrap().callbacks.is_empty());
        assert!(!Cancellation::current().cancelled());
        let mut surviving = 0;
        iocp::scan_file(
            &path,
            size as u64,
            64 * 1024,
            2,
            1,
            0,
            |data, _, _| ScanBatch {
                results: data.len(),
                discarded_results: 0,
            },
            |count| {
                surviving += count;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(surviving, size);
        std::fs::remove_file(path).unwrap();
    }
}
