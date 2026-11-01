//! Request cancellation shared by native IO, analysis and password work.
use pyo3::prelude::*;
use std::cell::RefCell;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pyo3::create_exception!(
    sunpack_native,
    NativeOperationCancelled,
    pyo3::exceptions::PyBaseException
);

thread_local! {
    static SCOPES: RefCell<Vec<Cancellation>> = const { RefCell::new(Vec::new()) };
}

type Wake = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct State {
    flag: Arc<AtomicBool>,
    wakes: Mutex<Vec<Wake>>,
}

impl State {
    fn cancel(&self) {
        if self.flag.swap(true, Ordering::Relaxed) {
            return;
        }
        let wakes =
            std::mem::take(&mut *self.wakes.lock().unwrap_or_else(|error| error.into_inner()));
        for wake in wakes {
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

    pub(crate) fn check(&self) -> PyResult<()> {
        if self.cancelled() {
            Err(NativeOperationCancelled::new_err(
                "native operation cancelled",
            ))
        } else {
            Ok(())
        }
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
        let wake: Wake = Arc::new(wake);
        let mut wakes = state
            .wakes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.cancelled() {
            drop(wakes);
            wake();
        } else {
            wakes.push(Arc::clone(&wake));
        }
        Some(Subscription {
            state: Arc::clone(state),
            wake,
        })
    }
}

fn cancelled_io() -> io::Error {
    // Interrupted is automatically retried by Read::read_exact/read_to_end.
    io::Error::other("native operation cancelled")
}

pub(crate) struct Subscription {
    state: Arc<State>,
    wake: Wake,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.state
            .wakes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|wake| !Arc::ptr_eq(wake, &self.wake));
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

#[pyclass(frozen, module = "sunpack_native")]
pub(crate) struct NativeCancellation {
    state: Arc<State>,
}

#[pymethods]
impl NativeCancellation {
    #[new]
    fn new() -> Self {
        Self {
            state: Arc::new(State::default()),
        }
    }

    fn cancel(&self, py: Python<'_>) {
        py.detach(|| self.state.cancel());
    }

    fn __enter__(&self) {
        SCOPES.with(|scopes| {
            scopes
                .borrow_mut()
                .push(Cancellation(Some(Arc::clone(&self.state))))
        });
    }

    fn __exit__(
        &self,
        _ty: &Bound<'_, PyAny>,
        _value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) {
        drop(Scope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{iocp, ScanBatch};
    use std::sync::mpsc;

    #[test]
    fn cancelled_initializer_does_not_publish_damage_to_shared_password_input() {
        // KDF/IO stop tests cannot detect a cancelled initializer poisoning a
        // concurrent borrower's archive facts. One shared physical generation
        // checks isolation, retry and reuse together without decoding a payload.
        use crate::io::reader::ManagedReader;
        use crate::password::context::{verify_prepared, InputKey, PreparedStatus};

        Python::initialize();
        let path = std::env::temp_dir().join(format!(
            "sunpack_cancel_prepare_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"physical generation").unwrap();
        let reader = ManagedReader::open(&path).unwrap();
        let key = InputKey::file("rar", &reader).unwrap();
        let owner_key = key.clone();
        let borrower_key = key.clone();
        let state = Arc::new(State::default());
        let owner_signal = Arc::clone(&state);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            Python::attach(|py| {
                Cancellation(Some(owner_signal)).run(|| {
                    verify_prepared(py, owner_key, &[], move || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Err(PreparedStatus::new("damaged", "abandoned initializer"))
                    })
                    .unwrap_err()
                    .is_instance_of::<NativeOperationCancelled>(py)
                })
            })
        });
        entered_rx.recv().unwrap();
        let (borrow_tx, borrow_rx) = mpsc::channel();
        let borrower = std::thread::spawn(move || {
            Python::attach(|py| {
                borrow_tx.send(()).unwrap();
                verify_prepared(py, borrower_key, &[], || {
                    Err(PreparedStatus::new("not_required", "surviving initializer"))
                })
                .unwrap()
                .bind(py)
                .get_item("status")
                .unwrap()
                .extract::<String>()
                .unwrap()
            })
        });
        borrow_rx.recv().unwrap();
        // The borrower holds the GIL until it joins the shared initializer.
        // Acquiring it here proves the concurrent read is already waiting.
        Python::attach(|_| {
            state.cancel();
            release_tx.send(()).unwrap();
        });
        assert!(owner.join().unwrap());
        assert_eq!(borrower.join().unwrap(), "not_required");
        Python::attach(|py| {
            let reused =
                verify_prepared(py, key, &[], || panic!("successful facts must be reused"))
                    .unwrap();
            assert_eq!(
                reused
                    .bind(py)
                    .get_item("status")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "not_required"
            );
        });
        crate::password::context::release_under_roots(std::slice::from_ref(&path));
        drop(reader);
        std::fs::remove_file(path).unwrap();
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
        assert!(state.wakes.lock().unwrap().is_empty());
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
