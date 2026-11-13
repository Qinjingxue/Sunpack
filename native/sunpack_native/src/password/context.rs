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

/// Initialize once per input, outside the cache lock and without the GIL.
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
                retain(&mut entries, |old, _| {
                    // Concurrent discovery snapshots may contain different
                    // volume sets. Their exact keys keep facts independent;
                    // only a changed physical generation invalidates a borrower.
                    !old.members.iter().any(|left| {
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
        let ready = (|| {
            slot.value.get_or_init(&cancellation, || {
                prepare
                    .take()
                    .expect("only the initializer consumes prepare")()
            })
        })()
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
    let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
    let retired = slot.retired.load(Ordering::Acquire);
    // Physical failures may be transient; do not memoize them as archive facts.
    // Keep oversized material discoverable by concurrent borrowers until
    // the final borrower returns. It never consumes the idle cache budget.
    if matches!(prepared, Err(PreparedStatus::ReadFault(fault)) if fault.code == "io_error")
        || matches!(prepared, Err(PreparedStatus::Status(_,message)) if message.starts_with("resource_unavailable:"))
        || (Arc::strong_count(&slot) == 2
            && matches!(prepared, Ok(context) if context.retained_bytes() > MAX_CONTEXT_BYTES))
    {
        entries.retain(|(_, current)| !Arc::ptr_eq(current, &slot));
    }
    // A finished borrower must be invisible to eviction before another
    // borrower can acquire the lock and check the cache limits.
    drop(slot);
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
        let (_, slot) = entries.remove(index).unwrap();
        bytes = bytes.saturating_sub(
            slot.value
                .get()
                .and_then(|result| result.as_ref().ok())
                .map_or(0, PasswordContext::retained_bytes),
        );
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
    retain(&mut entries, |_, _| false);
    crate::collections::trim_deque(&mut entries);
}

pub(crate) fn release_under_roots(roots: &[PathBuf]) {
    let mut entries = cache().lock().unwrap_or_else(|error| error.into_inner());
    retain(&mut entries, |key, _| {
        !key.members.iter().any(|member| {
            roots
                .iter()
                .any(|root| member.generation.path.starts_with(root))
        })
    });
    crate::collections::trim_deque(&mut entries);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn replaced_password_snapshot_returns_typed_retirement() {
        let path = crate::test_support::temp_file("retired_password_snapshot", b"old");
        let reader = ManagedReader::open(&path).unwrap();
        let old = InputKey::file("rar", &reader).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let borrower = std::thread::spawn(move || {
            verify_prepared(old, &[], move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(PreparedStatus::new("damaged", "obsolete verdict"))
            })
        });
        entered_rx.recv().unwrap();
        std::fs::write(&path, b"new physical generation").unwrap();
        let current = ManagedReader::open(&path).unwrap();
        let key = InputKey::file("rar", &current).unwrap();
        let new = verify_prepared(key, &[], || {
            Err(PreparedStatus::new("not_required", "current verdict"))
        });
        release_tx.send(()).unwrap();
        let error = borrower.join().unwrap().unwrap_err();
        assert!(error.get_ref().is_some_and(|error| error.is::<InputChanged>()));
        assert!(!std::io::Error::other(error.to_string()).get_ref().is_some_and(|error| error.is::<InputChanged>()));
        assert_eq!(new.unwrap().status, "not_required");

        let canonical = current.file_identity().unwrap().path.to_path_buf();
        release_under_roots(&[canonical]);
        drop((reader, current));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cancelled_initializer_does_not_publish_damage_to_shared_password_input() {
        use crate::io::cancellation::Cancellation;
        let path = crate::test_support::temp_file("cancel_prepare", b"physical generation");
        let reader = ManagedReader::open(&path).unwrap();
        let key = InputKey::file("rar", &reader).unwrap();
        let owner_key = key.clone();
        let borrower_key = key.clone();
        let signal = Cancellation::new();
        let owner_signal = signal.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            owner_signal.run(|| {
                verify_prepared(owner_key, &[], move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Err(PreparedStatus::new("damaged", "abandoned initializer"))
                })
                .unwrap_err()
                .to_string()
            })
        });
        entered_rx.recv().unwrap();
        // Acquire the owner's exact slot before revoking it. A waiter on
        // this generation must see an abandoned initialization even if
        // the slot is already removed from the map when it resumes.
        let borrowed = {
            let entries = cache().lock().unwrap_or_else(|error| error.into_inner());
            Arc::clone(&entries.iter().find(|(entry, _)| *entry == key).unwrap().1)
        };
        let borrower = std::thread::spawn(move || {
            assert!(borrowed
                .value
                .get_or_init(&Cancellation::default(), || {
                    panic!("the owner must settle its slot")
                })
                .is_none());
            verify_prepared(borrower_key, &[], || {
                Err(PreparedStatus::new("not_required", "surviving initializer"))
            })
            .unwrap()
            .status
        });
        signal.cancel();
        release_tx.send(()).unwrap();
        assert_eq!(owner.join().unwrap(), "native operation cancelled");
        assert_eq!(borrower.join().unwrap(), "not_required");
        let reused =
            verify_prepared(key, &[], || panic!("successful facts must be reused")).unwrap();
        assert_eq!(reused.status, "not_required");
        release_under_roots(std::slice::from_ref(&path));
        drop(reader);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_volume_snapshots_preserve_independent_password_facts() {
        // Arrival tests hit this overlap only by chance; cancellation tests use
        // one identical key. Block one initializer while a larger snapshot
        // completes, then check both cached verdicts without KDF/payload work.
        let root = std::env::temp_dir().join(format!(
            "sunpack_password_snapshots_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let readers: Vec<_> = (1..=4)
            .map(|number| {
                let path = root.join(format!("part{number}.bin"));
                std::fs::write(&path, b"unchanged physical generation").unwrap();
                ManagedReader::open(path).unwrap()
            })
            .collect();
        let members: Vec<_> = readers
            .iter()
            .enumerate()
            .map(|(index, reader)| InputMember::new(reader, 0, None, index as u32 + 1).unwrap())
            .collect();
        let partial = InputKey::new("rar", "volumes", members[..2].to_vec());
        let complete = InputKey::new("rar", "volumes", members);
        let owner_key = partial.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            verify_prepared(owner_key, &[], move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(PreparedStatus::new("missing_volume", "partial snapshot"))
            })
            .map(|value| value.status)
        });
        entered_rx.recv().unwrap();
        let newer = verify_prepared(complete.clone(), &[], || {
            Err(PreparedStatus::new("not_required", "complete snapshot"))
        })
        .map(|value| value.status);
        release_tx.send(()).unwrap();
        let older = owner.join().unwrap();
        let reused = [partial, complete].map(|key| {
            verify_prepared(key, &[], || {
                Err(PreparedStatus::new(
                    "damaged",
                    "unexpected reinitialization",
                ))
            })
            .map(|value| value.status)
        });
        release_under_roots(std::slice::from_ref(&root));
        drop(readers);
        std::fs::remove_dir_all(root).unwrap();

        assert_eq!(older.unwrap(), "missing_volume");
        assert_eq!(newer.unwrap(), "not_required");
        assert_eq!(
            reused.map(Result::unwrap),
            ["missing_volume", "not_required"]
        );
    }
}
