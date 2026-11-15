//! Immutable password material for the logical input selected by Rust analysis.
//! Physical generations and logical boundaries are part of the identity; no
//! archive detection or member discovery is performed by this cache.
use super::PasswordVerification;
use crate::io::cancellation::CancellableOnce;
use crate::io::read_fault::ReadFault;
use crate::io::reader::{FileIdentity, ManagedReader};
use std::collections::{HashMap, VecDeque};
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
}

pub(crate) enum PasswordContext {
    Enc(super::enc::EncPasswordContext),
    Zip(super::zip::ZipPasswordContext),
    Rar(super::rar::RarPasswordContext),
    SevenZip(super::seven_zip::SevenZipPasswordContext),
}

impl PasswordContext {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Enc(context) => context.retained_bytes(),
            Self::Zip(context) => context.retained_bytes(),
            Self::Rar(context) => context.retained_bytes(),
            Self::SevenZip(context) => context.retained_bytes(),
        }
    }

    fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        match self {
            Self::Enc(context) => context.verify(candidates),
            Self::Zip(context) => context.verify(candidates),
            Self::Rar(context) => context.verify(candidates),
            Self::SevenZip(context) => context.verify(candidates),
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

    fn verification(&self) -> PasswordVerification {
        match self {
            Self::ReadFault(fault) => super::password_read_fault_status(fault),
            Self::Status(status, message) => PasswordVerification::status(status, message.as_str()),
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
    value: CancellableOnce<Prepared>,
    retired: AtomicBool,
}
type Entry = (InputKey, Arc<PreparedSlot>);

fn cache() -> &'static Mutex<VecDeque<Entry>> {
    static CACHE: OnceLock<Mutex<VecDeque<Entry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Initialize once per input, outside the cache lock.
/// Unrelated archives and all candidate calculations remain concurrent.
pub(crate) fn verify_prepared(
    key: InputKey,
    candidates: &[Arc<str>],
    prepare: impl FnOnce() -> Prepared + Send,
) -> std::io::Result<PasswordVerification> {
    let cancellation = crate::io::cancellation::Cancellation::current();
    cancellation.check()?;
    // The key comes from the already opened physical readers. Their generation
    // is validated when the input is acquired, and the caller's lifecycle borrow
    // covers this probe. Reopening every path here would repeat that admission
    // three times per password batch, including immutable prepared-cache hits.
    let mut prepare = Some(prepare);
    let slot = loop {
        let slot = {
            let _retired_entries;
            let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
            let entry = if let Some(index) = entries.iter().position(|(old, _)| *old == key) {
                // Insertion already retired conflicting generations. A current
                // exact hit only refreshes the existing slot's LRU position.
                entries.remove(index).unwrap()
            } else {
                // Index once per miss, not once per cached member or password batch.
                let generations: HashMap<_, _> = key
                    .members
                    .iter()
                    .map(|member| (&member.generation.path, &member.generation))
                    .collect();
                _retired_entries = retire_where(&mut entries, |old| {
                    // Concurrent discovery snapshots may contain different
                    // volume sets. Their exact keys keep facts independent;
                    // only a changed physical generation invalidates a borrower.
                    old.members.iter().any(|left| {
                        generations
                            .get(&left.generation.path)
                            .is_some_and(|right| left.generation != **right)
                    })
                });
                (key.clone(), Arc::new(PreparedSlot::default()))
            };
            let slot = Arc::clone(&entry.1);
            entries.push_back(entry);
            slot
        };
        let ready = slot
            .value
            .get_or_init(&cancellation, || {
                prepare
                    .take()
                    .expect("only the initializer consumes prepare")()
            })
            .is_some();
        if ready {
            break slot;
        }
        // Do not mark the input generation retired: only this initializer stopped.
        {
            let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
            entries.retain(|(old, current)| *old != key || !Arc::ptr_eq(current, &slot));
            crate::collections::trim_deque(&mut entries);
        }
        cancellation.check()?;
    };
    let prepared = slot.value.get().expect("completed password material");
    if slot.retired.load(Ordering::Acquire) {
        cancellation.check()?;
        return Err(input_changed());
    }
    let result = cancellation.check().and_then(|()| match prepared {
        Ok(context) => context.verify(candidates),
        Err(status) => Ok(status.verification()),
    });
    // Destruction of large contexts and their keys follows unlock. A slot
    // removed by a concurrent invalidation may have only this borrower left.
    let _retired_slot;
    let mut evicted = Vec::new();
    let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
    let retired = slot.retired.load(Ordering::Acquire);
    // Physical failures may be transient; do not memoize them as archive facts.
    // Keep oversized material discoverable by concurrent borrowers until
    // the final borrower returns. It never consumes the idle cache budget.
    if retired
        || matches!(prepared, Err(PreparedStatus::ReadFault(fault)) if fault.code == "io_error")
        || matches!(prepared, Err(PreparedStatus::Status(_,message)) if message.starts_with("resource_unavailable:"))
        || (Arc::strong_count(&slot) == 2
            && matches!(prepared, Ok(context) if context.retained_bytes() > MAX_CONTEXT_BYTES))
    {
        if let Some(index) = entries.iter().position(|(_, current)| Arc::ptr_eq(current, &slot)) {
            evicted.push(entries.remove(index).unwrap());
        }
        _retired_slot = slot;
    } else {
        // A finished borrower must be invisible to eviction before another
        // borrower can acquire the lock and check the cache limits.
        drop(slot);
    }
    let mut bytes: usize = entries
        .iter()
        .filter_map(|(_, slot)| slot.value.get())
        .filter_map(|result| result.as_ref().ok())
        .map(PasswordContext::retained_bytes)
        .filter(|&size| size <= MAX_CONTEXT_BYTES)
        .sum();
    while entries.len() > MAX_CONTEXTS || bytes > MAX_CONTEXT_BYTES {
        let Some(index) = entries
            .iter()
            .position(|(_, slot)| Arc::strong_count(slot) == 1 && slot.value.get().is_some())
        else {
            break;
        };
        let entry = entries.remove(index).unwrap();
        bytes = bytes.saturating_sub(
            entry.1.value
                .get()
                .and_then(|result| result.as_ref().ok())
                .map_or(0, PasswordContext::retained_bytes),
        );
        evicted.push(entry);
    }
    crate::collections::trim_deque(&mut entries);
    if retired {
        return Err(input_changed());
    }
    cancellation.check()?;
    result
}

#[derive(Debug)]
struct InputChanged;

impl std::fmt::Display for InputChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "password verification input changed; Rust archive analysis must be refreshed",
        )
    }
}

impl std::error::Error for InputChanged {}

fn input_changed() -> std::io::Error {
    std::io::Error::other(InputChanged)
}

pub(crate) fn clear() {
    let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
    for (_, slot) in entries.iter() {
        slot.retired.store(true, Ordering::Release);
    }
    let retired = std::mem::take(&mut *entries);
    drop(entries);
    drop(retired);
}

pub(crate) fn release_under_roots(roots: &[PathBuf]) {
    let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
    let retired = retire_where(&mut entries, |key| {
        key.members.iter().any(|member| {
            roots
                .iter()
                .any(|root| member.generation.path.starts_with(root))
        })
    });
    crate::collections::trim_deque(&mut entries);
    drop(entries);
    drop(retired);
}

fn retire_where(
    entries: &mut VecDeque<Entry>,
    mut remove: impl FnMut(&InputKey) -> bool,
) -> Vec<Entry> {
    let mut retired = Vec::new();
    for _ in 0..entries.len() {
        let entry = entries.pop_front().unwrap();
        if remove(&entry.0) {
            entry.1.retired.store(true, Ordering::Release);
            retired.push(entry);
        } else {
            entries.push_back(entry);
        }
    }
    retired
}

#[cfg(test)]
#[path = "../../tests/unit/password/context/tests.rs"]
mod tests;
