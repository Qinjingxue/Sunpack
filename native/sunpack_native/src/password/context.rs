//! Immutable password material for the logical input selected by Rust analysis.
//! Physical generations and logical boundaries are part of the identity; no
//! archive detection or member discovery is performed by this cache.
use crate::io::read_fault::ReadFault;
use crate::io::reader::{FileIdentity, ManagedReader};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_CONTEXTS: usize = 128;
const MAX_CONTEXT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct InputMember {
    generation: FileIdentity,
    start: u64,
    end: Option<u64>,
    number: u32,
}

impl InputMember {
    pub(crate) fn new(
        reader: &ManagedReader,
        start: u64,
        end: Option<u64>,
        number: u32,
    ) -> std::io::Result<Self> {
        Ok(Self {
            generation: reader.file_identity()?,
            start,
            end,
            number,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct InputKey {
    format: &'static str,
    mode: &'static str,
    members: Vec<InputMember>,
}

impl InputKey {
    pub(crate) fn new(format: &'static str, mode: &'static str, members: Vec<InputMember>) -> Self {
        Self {
            format,
            mode,
            members,
        }
    }

    pub(crate) fn file(format: &'static str, reader: &ManagedReader) -> std::io::Result<Self> {
        Ok(Self::new(
            format,
            "file",
            vec![InputMember::new(reader, 0, None, 0)?],
        ))
    }

    fn is_current(&self) -> bool {
        self.members
            .iter()
            .all(|member| member.generation.is_current())
    }
}

pub(crate) enum PasswordContext {
    Zip(super::zip::ZipPasswordContext),
    Rar(super::rar::RarPasswordContext),
    SevenZip(super::seven_zip::SevenZipPasswordContext),
}

impl PasswordContext {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Zip(context) => context.retained_bytes(),
            Self::Rar(context) => context.retained_bytes(),
            Self::SevenZip(context) => context.retained_bytes(),
        }
    }

    fn verify(&self, py: Python<'_>, candidates: &[String]) -> PyResult<Py<PyAny>> {
        match self {
            Self::Zip(context) => context.verify(py, candidates),
            Self::Rar(context) => context.verify(py, candidates),
            Self::SevenZip(context) => context.verify(py, candidates),
        }
    }
}

pub(crate) enum PreparedStatus {
    Status(&'static str, String),
    ReadFault(ReadFault),
}

impl PreparedStatus {
    pub(crate) fn new(status: &'static str, message: impl Into<String>) -> Self {
        Self::Status(status, message.into())
    }

    fn to_python(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            Self::ReadFault(fault) => super::password_read_fault_status(py, fault),
            Self::Status(status, message) => {
                let result = PyDict::new(py);
                result.set_item("status", status)?;
                result.set_item("matched_index", -1)?;
                result.set_item("attempts", 0)?;
                result.set_item("message", message)?;
                Ok(result.into())
            }
        }
    }
}

impl From<ReadFault> for PreparedStatus {
    fn from(fault: ReadFault) -> Self {
        Self::ReadFault(fault)
    }
}

type Prepared = Result<PasswordContext, PreparedStatus>;
#[derive(Default)]
struct PreparedSlot {
    value: OnceLock<Prepared>,
    retired: AtomicBool,
}
type Entry = (InputKey, Arc<PreparedSlot>);

fn cache() -> &'static Mutex<VecDeque<Entry>> {
    static CACHE: OnceLock<Mutex<VecDeque<Entry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Initialize once per input, outside the cache lock and without the GIL.
/// Unrelated archives and all candidate calculations remain concurrent.
pub(crate) fn verify_prepared(
    py: Python<'_>,
    key: InputKey,
    candidates: &[String],
    prepare: impl FnOnce() -> Prepared + Send,
) -> PyResult<Py<PyAny>> {
    if !py.detach(|| key.is_current()) {
        retire(&key);
        return Err(input_changed());
    }
    let slot = {
        let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
        // A changed member retires every view of its old generation. Adding or
        // removing parts also retires the previous set of this logical input.
        retain(&mut entries, |old, _| {
            let membership_changed = old.format == key.format
                && old.mode == key.mode
                && old.members.len() != key.members.len()
                && old.members.first() == key.members.first();
            !membership_changed
                && !old.members.iter().any(|left| {
                    key.members.iter().any(|right| {
                        left.generation.path == right.generation.path
                            && left.generation != right.generation
                    })
                })
        });
        let slot = entries
            .iter()
            .position(|(old, _)| *old == key)
            .and_then(|index| entries.remove(index))
            .map(|(_, slot)| slot)
            .unwrap_or_else(|| Arc::new(PreparedSlot::default()));
        entries.push_back((key.clone(), slot.clone()));
        slot
    };
    let prepared = py.detach(|| slot.value.get_or_init(prepare));
    if slot.retired.load(Ordering::Acquire) || !py.detach(|| key.is_current()) {
        retire_slot(&key, &slot);
        return Err(input_changed());
    }
    let result = match prepared {
        Ok(context) => context.verify(py, candidates),
        Err(status) => status.to_python(py),
    };
    if slot.retired.load(Ordering::Acquire) || !py.detach(|| key.is_current()) {
        retire_slot(&key, &slot);
        return Err(input_changed());
    }
    let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
    if slot.retired.load(Ordering::Acquire) {
        return Err(input_changed());
    }
    // Physical failures may be transient; do not memoize them as archive facts.
    if matches!(prepared, Err(PreparedStatus::ReadFault(fault)) if fault.code == "io_error") {
        entries.retain(|(old, current)| *old != key || !Arc::ptr_eq(current, &slot));
    }
    let mut bytes: usize = entries
        .iter()
        .filter_map(|(_, slot)| slot.value.get())
        .filter_map(|result| result.as_ref().ok())
        .map(PasswordContext::retained_bytes)
        .sum();
    while entries.len() > MAX_CONTEXTS || bytes > MAX_CONTEXT_BYTES {
        let Some(index) = entries
            .iter()
            .position(|(_, slot)| Arc::strong_count(slot) == 1 && slot.value.get().is_some())
        else {
            break;
        };
        let (_, slot) = entries.remove(index).unwrap();
        bytes = bytes.saturating_sub(
            slot.value
                .get()
                .and_then(|result| result.as_ref().ok())
                .map_or(0, PasswordContext::retained_bytes),
        );
    }
    result
}

fn input_changed() -> PyErr {
    pyo3::exceptions::PyOSError::new_err(
        "password verification input changed; Rust archive analysis must be refreshed",
    )
}

fn retire(key: &InputKey) {
    retain(
        &mut cache().lock().unwrap_or_else(|error| error.into_inner()),
        |old, _| old != key,
    );
}

pub(crate) fn clear() {
    retain(
        &mut cache().lock().unwrap_or_else(|error| error.into_inner()),
        |_, _| false,
    );
}

pub(crate) fn release_under_roots(roots: &[PathBuf]) {
    retain(
        &mut cache().lock().unwrap_or_else(|error| error.into_inner()),
        |key, _| {
            !key.members.iter().any(|member| {
                roots
                    .iter()
                    .any(|root| member.generation.path.starts_with(root))
            })
        },
    );
}

fn retire_slot(key: &InputKey, slot: &Arc<PreparedSlot>) {
    retain(
        &mut cache().lock().unwrap_or_else(|error| error.into_inner()),
        |old, current| old != key || !Arc::ptr_eq(current, slot),
    );
}

fn retain(
    entries: &mut VecDeque<Entry>,
    mut keep: impl FnMut(&InputKey, &Arc<PreparedSlot>) -> bool,
) {
    entries.retain(|(key, slot)| {
        let keep = keep(key, slot);
        if !keep {
            slot.retired.store(true, Ordering::Release);
        }
        keep
    });
}
