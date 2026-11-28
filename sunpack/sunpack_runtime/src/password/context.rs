//! Immutable password material for the logical input selected by Rust analysis.
//! Physical generations and logical boundaries are part of the identity; no
//! archive detection or member discovery is performed by this cache.
use super::PasswordVerification;
use crate::io::cancellation::{CancellableOnce, Cancellation};
use crate::io::read_fault::ReadFault;
use crate::io::reader::{FileIdentity, ManagedReader};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct InputMember {
    generation: FileIdentity,
    view: Option<Arc<crate::io::view::ReadView>>,
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
            view: reader.read_view().cloned(),
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
    zip_eocd_offset: Option<u64>,
}

impl InputKey {
    pub(crate) fn new(format: &'static str, mode: &'static str, members: Vec<InputMember>) -> Self {
        Self {
            format,
            mode,
            members,
            zip_eocd_offset: None,
        }
    }

    pub(crate) fn file(format: &'static str, reader: &ManagedReader) -> std::io::Result<Self> {
        Ok(Self::new(
            format,
            "file",
            vec![InputMember::new(reader, 0, None, 0)?],
        ))
    }

    pub(crate) fn with_zip_eocd(mut self, offset: Option<u64>) -> Self {
        self.zip_eocd_offset = offset;
        self
    }
}

pub(crate) enum PasswordContext {
    Evidence(super::evidence::EvidenceContext),
    ReducedZip(
        super::zip::ZipPasswordContext,
        Arc<crate::io::archive_state::VolumeAttemptPlan>,
    ),
    Enc(super::enc::EncPasswordContext),
    Zip(super::zip::ZipPasswordContext),
    Rar(Arc<super::rar::RarPasswordContext>),
    SevenZip(super::seven_zip::SevenZipPasswordContext),
}

impl PasswordContext {
    pub(crate) fn verify(
        &self,
        candidates: &[Arc<str>],
        rar_key: Option<&mut Option<super::rar::RarProvenKey>>,
    ) -> std::io::Result<PasswordVerification> {
        match self {
            Self::ReducedZip(context, plan) => {
                let mut result = context.verify(candidates)?;
                result.volume_attempts = Some(plan.clone());
                Ok(result)
            }
            Self::Evidence(context) => context.verify(candidates),
            Self::Enc(context) => context.verify(candidates),
            Self::Zip(context) => context.verify(candidates),
            Self::Rar(context) => context.verify(candidates, rar_key),
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

    pub(super) fn transient(&self) -> bool {
        match self {
            Self::ReadFault(fault) => fault.code == "io_error",
            Self::Status(_, message) => message.starts_with("resource_unavailable:"),
        }
    }

    pub(super) fn verification(&self) -> PasswordVerification {
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
pub(crate) struct Preparation<'a> {
    pub(super) fixed_password: bool,
    pub(crate) other_password_batches: bool,
    slot: Option<Arc<PreparedSlot>>,
    local: Option<Box<Prepared>>,
    pub(super) zip_anchor: Option<Box<super::zip::ZipAnchor>>,
    rar_key: Option<&'a mut Option<super::rar::RarProvenKey>>,
}

impl<'a> Preparation<'a> {
    #[cfg(test)]
    pub(crate) fn benchmark_methods(&self) -> Vec<&'static str> {
        fn collect(context: &PasswordContext, methods: &mut Vec<&'static str>) {
            let method = match context {
                PasswordContext::Evidence(evidence) => {
                    for (context, _) in &evidence.alternatives {
                        collect(context, methods);
                    }
                    return;
                }
                PasswordContext::Zip(context) | PasswordContext::ReducedZip(context, _) => context.benchmark_method(),
                PasswordContext::Rar(context) => context.benchmark_method(),
                PasswordContext::SevenZip(context) => context.benchmark_method(),
                PasswordContext::Enc(_) => "enc_v4_quick_block",
            };
            if !methods.contains(&method) {
                methods.push(method);
            }
        }
        let mut methods = Vec::new();
        if let Some(Ok(context)) = self.local.as_deref().or_else(|| self.slot.as_ref()?.value.get()) {
            collect(context, &mut methods);
        }
        methods
    }

    pub(crate) fn prepare_volume_candidates(
        &mut self,
        prepared: Prepared,
    ) -> std::io::Result<Option<Arc<crate::io::archive_state::VolumeAttemptPlan>>> {
        let reduced = match &prepared {
            Ok(PasswordContext::Evidence(evidence)) => evidence.public_plan()?,
            _ => None,
        };
        self.local = Some(Box::new(prepared));
        Ok(reduced)
    }

    pub(crate) fn fix_password(&mut self) {
        self.fixed_password = true;
    }

    /// A volume plan owns its projected evidence for all password batches.
    /// Building a global identity would reopen unrelated sources just for the key.
    pub(crate) fn verify_local(
        &mut self,
        prepared: Prepared,
        candidates: &[Arc<str>],
    ) -> std::io::Result<PasswordVerification> {
        self.verify_local_with(prepared, |prepared, fixed, other_batches, rar_key| Self::verify_material(
            None,
            prepared,
            candidates,
            rar_key,
            &Cancellation::current(),
            fixed,
            other_batches,
        ))
    }

    pub(super) fn verify_local_with(
        &mut self,
        prepared: Prepared,
        verify: impl FnOnce(&Prepared, bool, bool, Option<&mut Option<super::rar::RarProvenKey>>)
            -> std::io::Result<PasswordVerification>,
    ) -> std::io::Result<PasswordVerification> {
        let reusable = !prepared.as_ref().is_err_and(|error| error.transient());
        let result = verify(&prepared, self.fixed_password, self.other_password_batches, self.rar_key.as_deref_mut());
        if reusable && result.is_ok() {
            self.local = Some(Box::new(prepared));
        }
        result
    }

    pub(crate) fn evidence(&self) -> Option<&super::evidence::EvidenceContext> {
        let context = self
            .local
            .as_deref()
            .or_else(|| self.slot.as_ref()?.value.get())?
            .as_ref()
            .ok()?;
        match context {
            PasswordContext::Evidence(evidence) => Some(evidence),
            _ => None,
        }
    }

    pub(crate) fn capturing_rar_key(key: &'a mut Option<super::rar::RarProvenKey>) -> Self {
        Self {
            fixed_password: false,
            other_password_batches: false,
            slot: None,
            local: None,
            zip_anchor: None,
            rar_key: Some(key),
        }
    }

    /// Reuse the layout for a later batch of the same plan's input and readers.
    pub(super) fn verify_prepared(
        &mut self,
        candidates: &[Arc<str>],
    ) -> std::io::Result<Option<PasswordVerification>> {
        let slot = self.slot.as_deref();
        let Some(prepared) = self.local.as_deref().or_else(|| slot?.value.get()) else {
            return Ok(None);
        };
        let cancellation = Cancellation::current();
        Self::verify_material(
            slot,
            prepared,
            candidates,
            self.rar_key.as_deref_mut(),
            &cancellation,
            self.fixed_password,
            self.other_password_batches,
        )
        .map(Some)
    }

    pub(crate) fn verify(
        &mut self,
        key: InputKey,
        candidates: &[Arc<str>],
        prepare: impl FnOnce() -> Prepared + Send,
    ) -> std::io::Result<PasswordVerification> {
        let cancellation = Cancellation::current();
        cancellation.check_io()?;
        let mut prepare = Some(prepare);
        loop {
            if self.slot.as_ref().is_none_or(|slot| slot.key != key) {
                self.release(false);
                self.slot = Some(borrow(&key));
            }
            let slot = self.slot.as_ref().unwrap();
            let Some(prepared) = slot
                .value
                .get_or_init(&cancellation, || prepare.take().unwrap()())
            else {
                // The initializing borrower was cancelled. Waiters can take
                // over without retiring a still-current file generation.
                self.release(true);
                cancellation.check_io()?;
                continue;
            };
            let result = Self::verify_material(
                Some(slot),
                prepared,
                candidates,
                self.rar_key.as_deref_mut(),
                &cancellation,
                self.fixed_password,
                self.other_password_batches,
            );
            if prepared.as_ref().is_err_and(|error| error.transient()) {
                self.release(true);
            }
            return result;
        }
    }

    fn verify_material(
        slot: Option<&PreparedSlot>,
        prepared: &Prepared,
        candidates: &[Arc<str>],
        rar_key: Option<&mut Option<super::rar::RarProvenKey>>,
        cancellation: &Cancellation,
        fixed_password: bool,
        other_password_batches: bool,
    ) -> std::io::Result<PasswordVerification> {
        cancellation.check_io()?;
        if slot.is_some_and(|slot| slot.retired.load(Ordering::Acquire)) {
            return Err(input_changed());
        }
        let result = match prepared {
            Ok(PasswordContext::Evidence(context)) => {
                context.verify_batch(candidates, fixed_password, !other_password_batches)
            }
            Ok(context) => context.verify(candidates, rar_key),
            Err(status) => Ok(status.verification()),
        };
        cancellation.check_io()?;
        if slot.is_some_and(|slot| slot.retired.load(Ordering::Acquire)) {
            return Err(input_changed());
        }
        result
    }

    fn release(&mut self, detach: bool) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
        if detach || Arc::strong_count(&slot) <= 2 {
            if let Some(index) = active
                .iter()
                .position(|current| Arc::ptr_eq(current, &slot))
            {
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

impl Drop for Preparation<'_> {
    fn drop(&mut self) {
        self.release(false);
    }
}

fn borrow(key: &InputKey) -> Arc<PreparedSlot> {
    let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(slot) = active.iter().find(|slot| slot.key == *key) {
        return Arc::clone(slot);
    }
    // Different volume snapshots can share unchanged members. Only reopening
    // a changed member invalidates its existing preparations.
    let retired = if active.is_empty() {
        Vec::new()
    } else if let [member] = key.members.as_slice() {
        retire_where(&mut active, |old| old.members.iter().any(|left| {
            left.generation.path == member.generation.path && left.generation != member.generation
        }))
    } else {
        let generations: HashMap<_, _> = key.members.iter()
            .map(|member| (&member.generation.path, &member.generation))
            .collect();
        retire_where(&mut active, |old| old.members.iter().any(|left| {
            generations.get(&left.generation.path).is_some_and(|right| left.generation != **right)
        }))
    };
    let slot = Arc::new(PreparedSlot {
        key: key.clone(),
        value: CancellableOnce::default(),
        retired: AtomicBool::new(false),
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
            roots
                .iter()
                .any(|root| member.generation.path.starts_with(root))
        })
    });
    if active.capacity() > 256.max(active.len().saturating_mul(4)) {
        active.shrink_to_fit();
    }
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
