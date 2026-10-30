//! Request-local cancellation, shared with candidate tasks without the GIL.
use pyo3::prelude::*;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pyo3::create_exception!(
    sunpack_native,
    PasswordProbeCancelled,
    pyo3::exceptions::PyBaseException
);

thread_local! {
    static SCOPES: RefCell<Vec<Cancellation>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Default)]
pub(crate) struct Cancellation(Option<Arc<AtomicBool>>);

impl Cancellation {
    pub(crate) fn current() -> Self {
        SCOPES.with(|scopes| scopes.borrow().last().cloned().unwrap_or_default())
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    pub(crate) fn flag(&self) -> Option<Arc<AtomicBool>> {
        self.0.clone()
    }

    pub(crate) fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        SCOPES.with(|scopes| scopes.borrow_mut().push(self.clone()));
        let _scope = Scope;
        operation()
    }

    pub(crate) fn check(&self) -> PyResult<()> {
        if self.cancelled() {
            Err(PasswordProbeCancelled::new_err("password probe cancelled"))
        } else {
            Ok(())
        }
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
pub(crate) struct PasswordCancellation {
    flag: Arc<AtomicBool>,
}

#[pymethods]
impl PasswordCancellation {
    #[new]
    fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    fn __enter__(&self) {
        SCOPES.with(|scopes| {
            scopes
                .borrow_mut()
                .push(Cancellation(Some(self.flag.clone())))
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
