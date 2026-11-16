//! Immutable password material for the logical input selected by Rust analysis.
//! Physical generations and logical boundaries are part of the identity; no
//! archive detection or member discovery is performed by this cache.
use super::PasswordVerification;
use crate::io::cancellation::CancellableOnce;
use crate::io::read_fault::ReadFault;
use crate::io::reader::{FileIdentity, ManagedReader};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
struct PreparedSlot {
    key: InputKey,
    value: CancellableOnce<Prepared>,
    retired: AtomicBool,
}

static ACTIVE: Mutex<Vec<Arc<PreparedSlot>>> = Mutex::new(Vec::new());

/// Keep one preparation across all candidate batches in a password plan.
/// Overlapping plans share initialization, and the last plan frees its slot.
#[derive(Default)]
pub(crate) struct Preparation(Option<Arc<PreparedSlot>>);

impl Preparation {
    pub(crate) fn verify(
        &mut self,
        key: InputKey,
        candidates: &[Arc<str>],
        prepare: impl FnOnce() -> Prepared + Send,
    ) -> std::io::Result<PasswordVerification> {
        let cancellation = crate::io::cancellation::Cancellation::current();
        cancellation.check()?;
        let mut prepare = Some(prepare);
        loop {
            if self.0.as_ref().is_none_or(|slot| slot.key != key) {
                self.release(false);
                self.0 = Some(borrow(&key));
            }
            let slot = self.0.as_ref().unwrap();
            let Some(prepared) = slot.value.get_or_init(&cancellation, || prepare.take().unwrap()()) else {
                // The initializing borrower was cancelled. Waiters can take
                // over without retiring a still-current file generation.
                self.release(true);
                cancellation.check()?;
                continue;
            };
            if slot.retired.load(Ordering::Acquire) {
                cancellation.check()?;
                return Err(input_changed());
            }
            let result = cancellation.check().and_then(|()| match prepared {
                Ok(context) => context.verify(candidates),
                Err(status) => Ok(status.verification()),
            });
            let retired = slot.retired.load(Ordering::Acquire);
            if matches!(prepared, Err(PreparedStatus::ReadFault(fault)) if fault.code == "io_error")
                || matches!(prepared, Err(PreparedStatus::Status(_, message)) if message.starts_with("resource_unavailable:"))
            {
                self.release(true);
            }
            cancellation.check()?;
            return if retired { Err(input_changed()) } else { result };
        }
    }

    fn release(&mut self, detach: bool) {
        let Some(slot) = self.0.take() else { return; };
        let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
        if detach || Arc::strong_count(&slot) <= 2 {
            if let Some(index) = active.iter().position(|current| Arc::ptr_eq(current, &slot)) {
                active.swap_remove(index);
            }
            if active.capacity() > 256.max(active.len().saturating_mul(4)) {
                active.shrink_to_fit();
            }
        } else {
            // Serialize the decrement with other plan drops, so one of them
            // always sees that the table and its own borrow are the last owners.
            drop(slot);
        }
        // The slot can own large probe buffers. Free outside the registry lock.
        drop(active);
    }
}

impl Drop for Preparation {
    fn drop(&mut self) { self.release(false); }
}

fn borrow(key: &InputKey) -> Arc<PreparedSlot> {
    let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(slot) = active.iter().find(|slot| slot.key == *key) {
        return Arc::clone(slot);
    }
    let generations: HashMap<_, _> = key.members.iter()
        .map(|member| (&member.generation.path, &member.generation))
        .collect();
    let retired = retire_where(&mut active, |old| {
        // Different volume snapshots can share unchanged members. Only
        // (re)opening a changed member invalidates its existing preparations.
        old.members.iter().any(|left| {
            generations.get(&left.generation.path)
                .is_some_and(|right| left.generation != **right)
        })
    });
    let slot = Arc::new(PreparedSlot {
        key: key.clone(), value: CancellableOnce::default(), retired: AtomicBool::new(false),
    });
    active.push(Arc::clone(&slot));
    drop(active);
    drop(retired);
    slot
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

pub(crate) fn release_under_roots(roots: &[PathBuf]) {
    let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
    let retired = retire_where(&mut active, |key| {
        key.members.iter().any(|member| {
            roots.iter().any(|root| member.generation.path.starts_with(root))
        })
    });
    drop(active);
    drop(retired);
}

fn retire_where(
    active: &mut Vec<Arc<PreparedSlot>>,
    mut remove: impl FnMut(&InputKey) -> bool,
) -> Vec<Arc<PreparedSlot>> {
    let mut retired = Vec::new();
    let mut i = 0;
    while i < active.len() {
        if remove(&active[i].key) {
            let slot = active.swap_remove(i);
            slot.retired.store(true, Ordering::Release);
            retired.push(slot);
        } else {
            i += 1;
        }
    }
    retired
}

#[cfg(test)]
#[path = "../../tests/unit/password/context/tests.rs"]
mod tests;
