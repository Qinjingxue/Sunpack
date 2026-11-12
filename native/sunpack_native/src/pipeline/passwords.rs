use super::{Failure, FailureKind};
use crate::core::passwords::PasswordSnapshot;
use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::cancellation::Cancellation;
use crate::io::reader::NativeArchiveSession;
use crate::password;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

const BATCH_SIZE: usize = 256;
const MAX_CONTEXTS: usize = 128;
const MAX_REJECTIONS: usize = 8192;
const MAX_RECENT_PASSWORDS: usize = 64;

// Compact exact identities, not hash-only fingerprints: a collision must never
// skip a password. Single files stay allocation-free; compound keys reuse the
// existing binary serializer and are shared between plans and cache entries.
const MAX_KEY_BYTES: usize = 1024 * 1024;
const MAX_CACHE_KEY_BYTES: usize = 8 * MAX_KEY_BYTES;

#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    generation: u64,
    format: &'static str,
    start: u64,
    end: Option<u64>,
    eocd: Option<u64>,
    zip_spanned: bool,
    compound: Option<Arc<[u8]>>,
}

impl Key {
    fn for_input(input: &ArchiveInput, sessions: &[NativeArchiveSession]) -> Option<Self> {
        let format = match input.format_hint.as_str() {
            "zip" => "zip", "rar" => "rar", "7z" => "7z", "enc" => "enc",
            _ => return None,
        };
        let (path, start, end) = match input.mode {
            OpenMode::File => (input.entry_path.as_str(), 0, None),
            OpenMode::FileRange => {
                let extent = &input.parts.first()?.extent;
                (extent.path.as_str(), extent.start, extent.end)
            }
            _ => (input.entry_path.as_str(), 0, None),
        };
        let generation = sessions.iter().find_map(|session| {
            let (source, generation) = session.generation().ok()?;
            (source == path).then_some(generation)
        })?;
        let compound = if input.volume_attempts.is_some()
            || !matches!(input.mode, OpenMode::File | OpenMode::FileRange)
        {
            // Iteration follows the descriptor, not HashMap order. Binding all
            // candidate sources prevents stale proof reuse after a volume edit.
            let generations = sessions.iter().map(NativeArchiveSession::generation)
                .collect::<io::Result<HashMap<_, _>>>().ok()?;
            let members = input.physical_paths().chain(std::iter::once(input.entry_path.as_str()))
                .map(|path| Some((path, *generations.get(path)?)))
                .collect::<Option<Vec<_>>>()?;
            let mut bytes = KeyBytes(Vec::new());
            serde::Serialize::serialize(&(
                input.mode, &members, &input.parts, &input.ranges,
                &input.volume_attempts,
            ), &mut rmp_serde::Serializer::new(&mut bytes).with_struct_map()).ok()?;
            Some(Arc::from(bytes.0))
        } else { None };
        Some(Self { generation, format, start, end,
            eocd: input.analysis.zip_eocd_offset, zip_spanned: input.analysis.zip_spanned, compound })
    }

    fn bytes(&self) -> usize { self.compound.as_ref().map_or(0, |key| key.len()) }
}

struct KeyBytes(Vec<u8>);
impl io::Write for KeyBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_KEY_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("password cache key exceeds budget"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[derive(Default)]
pub(super) struct AttemptCache(Mutex<AttemptCacheState>);

#[derive(Default)]
struct AttemptCacheState {
    entries: HashMap<Key, Attempts>,
    clock: u64,
    rejections: usize,
    key_bytes: usize,
    recent: VecDeque<Arc<str>>,
}

#[derive(Default)]
struct Attempts {
    proof: Option<Option<Arc<str>>>,
    rejected: HashSet<Arc<str>>,
    used: u64,
}

impl AttemptCache {
    pub(super) fn clear(&self) {
        let mut state = self.0.lock().unwrap();
        state.entries = HashMap::new();
        state.clock = 0;
        state.rejections = 0;
        state.key_bytes = 0;
    }

    pub(super) fn recent(&self) -> Vec<Arc<str>> {
        self.0.lock().unwrap().recent.iter().cloned().collect()
    }

    fn remember_recent(&self, password: Arc<str>) {
        if password.is_empty() {
            return;
        }
        let mut state = self.0.lock().unwrap();
        if let Some(index) = state.recent.iter().position(|old| *old == password) {
            state.recent.remove(index);
        }
        state.recent.push_front(password);
        state.recent.truncate(MAX_RECENT_PASSWORDS);
    }

    fn proof(&self, key: &Key) -> Option<Option<Arc<str>>> {
        let mut state = self.0.lock().unwrap();
        let used = state.tick();
        let entry = state.entries.get_mut(key)?;
        entry.used = used;
        entry.proof.clone()
    }

    fn remove_rejected(&self, key: &Key, candidates: &mut Vec<Arc<str>>) -> bool {
        let mut state = self.0.lock().unwrap();
        let used = state.tick();
        let Some(entry) = state.entries.get_mut(key) else {
            return false;
        };
        entry.used = used;
        let before = candidates.len();
        candidates.retain(|password| !entry.rejected.contains(password));
        candidates.len() != before
    }

    fn update(&self, key: Key, operation: impl FnOnce(&mut Attempts)) {
        let mut state = self.0.lock().unwrap();
        let used = state.tick();
        if !state.entries.contains_key(&key) { state.key_bytes += key.bytes(); }
        let entry = state.entries.entry(key).or_default();
        let previous = entry.rejected.len();
        entry.used = used;
        operation(entry);
        let next = entry.rejected.len();
        state.rejections = state.rejections - previous + next;
        while state.entries.len() > MAX_CONTEXTS || state.rejections > MAX_REJECTIONS
            || state.key_bytes > MAX_CACHE_KEY_BYTES {
            let oldest = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .unwrap()
                .0.clone();
            state.key_bytes -= oldest.bytes();
            state.rejections -= state.entries.remove(&oldest).unwrap().rejected.len();
        }
    }

    fn reject(&self, key: Key, candidates: &[Arc<str>]) {
        self.update(key, |entry| {
            let room = MAX_REJECTIONS.saturating_sub(entry.rejected.len());
            entry.rejected.extend(candidates.iter().take(room).cloned());
        });
    }
}

impl AttemptCacheState {
    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }
}

pub(super) struct CandidateSet<'a> {
    explicit: Arc<[Arc<str>]>,
    snapshot: Option<&'a PasswordSnapshot>,
    cache: &'a AttemptCache,
    inherited_scope: Option<&'a Path>,
}

impl<'a> CandidateSet<'a> {
    pub(super) fn new(
        explicit: Arc<[Arc<str>]>,
        snapshot: Option<&'a PasswordSnapshot>,
        cache: &'a AttemptCache,
        inherited_scope: Option<&'a Path>,
    ) -> Self {
        Self {
            explicit,
            snapshot,
            cache,
            inherited_scope,
        }
    }

    pub(super) fn with_scope<'b>(&'b self, scope: Option<&'b Path>) -> CandidateSet<'b> {
        CandidateSet {
            explicit: Arc::clone(&self.explicit),
            snapshot: self.snapshot,
            cache: self.cache,
            inherited_scope: self.inherited_scope.or(scope),
        }
    }

    fn configured<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        let scope = self
            .inherited_scope
            .unwrap_or_else(|| Path::new(path).parent().unwrap_or_else(|| Path::new(path)));
        self.snapshot
            .into_iter()
            .flat_map(move |snapshot| snapshot.scoped(scope).flatten())
            .chain(self.explicit.iter())
            .chain(
                self.snapshot
                    .into_iter()
                    .flat_map(|snapshot| snapshot.global().iter()),
            )
    }

    fn for_path<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        let recent = self.cache.recent();
        let mut eligible = HashMap::with_capacity(recent.len());
        if !recent.is_empty() {
            let wanted: HashSet<&str> = recent.iter().map(Arc::as_ref).collect();
            for password in self.configured(path) {
                if wanted.contains(password.as_ref()) {
                    eligible.insert(password.as_ref(), password);
                    if eligible.len() == wanted.len() {
                        break;
                    }
                }
            }
        }
        let priority: Vec<_> = recent
            .iter()
            .filter_map(|password| eligible.get(password.as_ref()).copied())
            .collect();
        let mut seen: HashSet<&str> = HashSet::new();
        priority
            .into_iter()
            .chain(self.configured(path))
            .filter(move |value| {
                let value: &'b Arc<str> = *value;
                seen.insert(value.as_ref())
            })
    }

    pub(super) fn for_embedded(&self, path: &str) -> Vec<Arc<str>> {
        self.for_path(path).cloned().collect()
    }

    pub(super) fn plan(
        &self,
        input: &ArchiveInput,
        known: Option<Arc<str>>,
        cancellation: &Cancellation,
    ) -> io::Result<Result<PasswordPlan, Failure>> {
        if let Some(password) = known {
            self.cache.remember_recent(password.clone());
            return Ok(Ok(PasswordPlan::verified(password)));
        }
        if matches!(
            input.format_hint.as_str(),
            "tar" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4"
        ) {
            return Ok(Ok(PasswordPlan::clear()));
        }
        let mut check_single_enc = input.format_hint == "enc";
        let needs_password = input.analysis.password_required || check_single_enc;
        // Discovery already identifies inputs that require a password. For the
        // rest, an empty candidate can be confirmed by the ordinary worker
        // open. With no other candidates, a Rust probe only repeats that I/O.
        if self.configured(&input.entry_path).next().is_none() {
            return Ok(if needs_password {
                Err(Failure::password_required())
            } else {
                Ok(PasswordPlan::empty_fallback())
            });
        }
        let sessions = if matches!(input.format_hint.as_str(), "zip" | "rar" | "7z" | "enc") {
            open_sessions(input)?
        } else {
            Vec::new()
        };
        let key = Key::for_input(input, &sessions);
        if let Some(proof) = key.as_ref().and_then(|key| self.cache.proof(key)) {
            match proof {
                None => return Ok(Ok(PasswordPlan::clear())),
                Some(password)
                    if (!needs_password && password.is_empty())
                        || self
                            .configured(&input.entry_path)
                            .any(|candidate| candidate == &password) =>
                {
                    self.cache.remember_recent(password.clone());
                    return Ok(Ok(PasswordPlan::verified(password)));
                }
                _ => {}
            }
        }
        let mut candidates = self
            .for_path(&input.entry_path)
            .filter(|value| needs_password || !value.is_empty())
            .peekable();
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let mut pending = Vec::new();
        let mut evidence = None;
        let mut password_rejected = false;
        let mut has_candidates = false;
        // The empty password has priority only when Rust has not already
        // established encryption. A backend proof may still be necessary.
        let mut empty_probe = !needs_password;
        if empty_probe {
            batch.push(Arc::from(""));
        }
        if batch.is_empty() && candidates.peek().is_none() {
            return Ok(Err(Failure::password_required()));
        }
        loop {
            cancellation.check_io()?;
            if !std::mem::take(&mut empty_probe) {
                batch.extend(candidates.by_ref().take(BATCH_SIZE - batch.len()).cloned());
                has_candidates |= !batch.is_empty();
            }
            if batch.is_empty() {
                break;
            }
            if let Some(key) = key.as_ref() {
                password_rejected |= self.cache.remove_rejected(key, &mut batch);
                if batch.is_empty() {
                    continue;
                }
            }
            if check_single_enc && batch.len() == 1 {
                if candidates.peek().is_some() {
                    // More configured candidates may survive the rejection cache.
                    continue;
                }
                // The worker authenticates the sole ENC candidate when opening
                // the archive. A host probe would repeat the same Argon2 work.
                pending.append(&mut batch);
                break;
            }
            check_single_enc = false;
            let result = password::verify(input, &batch, &sessions, None)?;
            match result.status {
                "not_required" => {
                    if let Some(key) = key.as_ref() {
                        self.cache.update(key.clone(), |entry| entry.proof = Some(None));
                    }
                    return Ok(Ok(PasswordPlan::clear()));
                }
                "match" => {
                    let Some(index) = result.matched_index.filter(|&i| i < batch.len()) else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Rust password match",
                        ));
                    };
                    if !result.final_confirmation_required.unwrap_or(true) {
                        let password = Arc::clone(&batch[index]);
                        self.cache.remember_recent(password.clone());
                        if let Some(key) = key.as_ref() {
                            self.cache
                                .update(key.clone(), |entry| entry.proof = Some(Some(password.clone())));
                        }
                        return Ok(Ok(PasswordPlan::verified(password)));
                    }
                    let tested = result.attempts.min(batch.len());
                    let mut rejected = Vec::new();
                    for (index, value) in batch.iter().enumerate() {
                        if result.matched_index == Some(index)
                            || result.matched_indices.contains(&index)
                            || index >= tested
                        {
                            pending.push(value.clone());
                        } else if key.is_some() {
                            rejected.push(value.clone());
                        }
                    }
                    if let Some(key) = key.as_ref().filter(|_| !rejected.is_empty()) {
                        self.cache.reject(key.clone(), &rejected);
                    }
                    evidence = match (evidence, result.match_evidence) {
                        (None, next) => next,
                        (old, next) if old == next => old,
                        _ => Some("mixed"),
                    };
                }
                "no_match" => {
                    password_rejected |= result.attempts != 0;
                    if let Some(key) = key.as_ref().filter(|_| result.attempts != 0) {
                        self.cache
                            .reject(key.clone(), &batch[..result.attempts.min(batch.len())]);
                    }
                    pending.extend(batch.iter().skip(result.attempts).cloned());
                }
                "damaged" | "needs_volume_or_tail_damaged" | "missing_volume"
                    if input.volume_attempts.is_none() =>
                {
                    let kind = if result.status == "missing_volume"
                        || input.analysis.missing_volume_evidence.is_some()
                    {
                        FailureKind::MissingVolume
                    } else if result.message.starts_with("resource_unavailable:") {
                        FailureKind::ResourceUnavailable
                    } else if result
                        .read_fault
                        .as_ref()
                        .is_some_and(|fault| fault.code == "io_error")
                    {
                        FailureKind::FilesystemError
                    } else {
                        FailureKind::Damaged
                    };
                    return Ok(Err(Failure::new(kind, result.message)));
                }
                _ => pending.extend(batch.iter().cloned()),
            }
            batch.clear();
        }
        if pending.is_empty() {
            if password_rejected && has_candidates {
                return Ok(Err(Failure::password()));
            }
            if password_rejected || needs_password {
                return Ok(Err(Failure::password_required()));
            }
            pending.push(Arc::from(""));
        }
        if evidence.is_none() && pending.len() == 1 && pending[0].is_empty() {
            evidence = Some("empty_password_direct");
        }
        let plan = PasswordPlan {
            selected: Some(pending[0].clone()),
            candidates: pending,
            encrypted: needs_password.then_some(true),
            verified: false,
            evidence,
            has_candidates,
            cache_key: key,
        };
        Ok(Ok(plan))
    }
}

fn open_sessions(input: &ArchiveInput) -> io::Result<Vec<NativeArchiveSession>> {
    let mut seen = HashSet::new();
    let mut sessions = input.physical_extents().map(|extent| extent.path.as_str())
        .chain(std::iter::once(input.entry_path.as_str()))
        .filter(|path| seen.insert(*path))
        .map(|path| NativeArchiveSession::new(path.to_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    // Candidate-only members bind attempt-cache identity, but a disappeared
    // alternative must not turn an otherwise viable volume plan into an I/O
    // failure. A missing generation simply disables result caching this time.
    if let Some(plan) = &input.volume_attempts {
        for source in &plan.sources {
            if seen.insert(source.path.as_str()) {
                if let Ok(session) = NativeArchiveSession::new(source.path.clone()) {
                    sessions.push(session);
                }
            }
        }
    }
    Ok(sessions)
}

pub(super) struct PasswordPlan {
    pub selected: Option<Arc<str>>,
    pub candidates: Vec<Arc<str>>,
    pub encrypted: Option<bool>,
    pub verified: bool,
    pub evidence: Option<&'static str>,
    pub has_candidates: bool,
    cache_key: Option<Key>,
}

impl PasswordPlan {
    fn empty_fallback() -> Self {
        let empty = Arc::from("");
        Self {
            selected: Some(Arc::clone(&empty)),
            candidates: vec![empty],
            encrypted: None,
            verified: false,
            evidence: Some("empty_password_direct"),
            has_candidates: false,
            cache_key: None,
        }
    }

    fn clear() -> Self {
        Self {
            selected: None,
            candidates: Vec::new(),
            encrypted: Some(false),
            verified: false,
            evidence: None,
            has_candidates: false,
            cache_key: None,
        }
    }

    fn verified(password: Arc<str>) -> Self {
        // A verified empty password is still a real candidate, not the
        // no-candidate fallback used before encryption is known.
        let has_candidates = true;
        Self {
            selected: Some(password),
            candidates: Vec::new(),
            encrypted: Some(true),
            verified: true,
            evidence: None,
            has_candidates,
            cache_key: None,
        }
    }

    pub(super) fn remember_confirmation(
        &self,
        index: Option<usize>,
        cache: &AttemptCache,
    ) -> Option<&str> {
        let password = match index {
            Some(index) => self.candidates.get(index)?,
            None if self.candidates.len() <= 1 => self.selected.as_ref()?,
            None => return None,
        };
        cache.remember_recent(Arc::clone(password));
        if let Some(key) = self.cache_key.as_ref() {
            cache.update(key.clone(), |entry| entry.proof = Some(Some(Arc::clone(password))));
        }
        Some(password)
    }

    pub(super) fn remember_rejections(&self, cache: &AttemptCache) {
        if let Some(key) = self.cache_key.as_ref().filter(|_| !self.candidates.is_empty()) {
            cache.reject(key.clone(), &self.candidates);
        }
    }
}

impl Failure {
    pub(super) fn password() -> Self {
        Self::new(
            FailureKind::WrongPassword,
            "Password not found in the password list",
        )
    }

    pub(super) fn password_required() -> Self {
        Self::new(
            FailureKind::PasswordRequired,
            "Password not found in the password list",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sole_enc_candidate_after_cached_rejections_uses_worker_confirmation() {
        // A host ENC probe would fail on this header. Planning can proceed
        // because the worker will confirm the sole remaining candidate.
        let path = crate::test_support::temp_file("enc_single_candidate_plan", b"short");
        let name = path.to_string_lossy().into_owned();
        let input = ArchiveInput::file(name.clone(), "enc".into(), "archive".into());
        let sessions = [NativeArchiveSession::new(name).unwrap()];
        let cache = AttemptCache::default();
        cache.reject(
            Key::for_input(&input, &sessions).unwrap(),
            &[Arc::from("rejected")],
        );
        let candidates = CandidateSet::new(
            Arc::from(["rejected".into(), "confirm-in-worker".into()]),
            None,
            &cache,
            None,
        );
        let plan = candidates
            .plan(&input, None, &Cancellation::new())
            .unwrap()
            .unwrap();
        assert_eq!(plan.selected.as_deref(), Some("confirm-in-worker"));
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.encrypted, Some(true));
        assert!(!plan.verified);

        drop(sessions);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn explicit_empty_enc_candidate_is_not_absent_or_implicit() {
        let path = crate::test_support::temp_file("enc_empty_candidate_plan", b"short");
        let name = path.to_string_lossy().into_owned();
        let input = ArchiveInput::file(name, "enc".into(), "archive".into());
        let cache = AttemptCache::default();
        let empty = CandidateSet::new(Arc::from([Arc::from("")]), None, &cache, None);
        let plan = empty.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
        assert_eq!(plan.selected.as_deref(), Some(""));
        assert_eq!(plan.candidates, [Arc::<str>::from("")]);
        assert!(plan.has_candidates);
        let absent = CandidateSet::new(Arc::from([]), None, &cache, None);
        assert_eq!(absent.plan(&input, None, &Cancellation::new()).unwrap()
            .err().unwrap().kind, FailureKind::PasswordRequired);
        let sessions = open_sessions(&input).unwrap();
        cache.reject(Key::for_input(&input, &sessions).unwrap(), &[Arc::from("wrong")]);
        let mixed = CandidateSet::new(Arc::from([Arc::from("wrong"), Arc::from("")]), None, &cache, None);
        let plan = mixed.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
        assert_eq!(plan.selected.as_deref(), Some(""));
        assert_eq!(plan.candidates.len(), 1);
        let key = Key::for_input(&input, &sessions).unwrap();
        cache.update(key, |entry| entry.proof = Some(Some(Arc::from(""))));
        let cached = empty.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
        assert!(cached.verified && cached.has_candidates);
        assert_eq!(cached.selected.as_deref(), Some(""));
        let known = empty.plan(&input, Some(Arc::from("")), &Cancellation::new()).unwrap().unwrap();
        assert!(known.verified && known.has_candidates);
        assert!(!PasswordPlan::empty_fallback().has_candidates);
        drop(sessions);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compound_attempts_reuse_exact_layout_and_generation_only() {
        use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan,
            VolumeLayout, VolumeSlot, VolumeDomain};
        let head = crate::test_support::temp_file("password_compound_head", b"head");
        let tail = crate::test_support::temp_file("password_compound_tail", b"tail");
        let mut input = ArchiveInput::file(head.to_string_lossy().into_owned(), "rar".into(), "archive".into());
        input.parts = vec![head.clone(), tail.clone()].into_iter().enumerate().map(|(index, path)| InputPart {
            extent: InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: Some(4) },
            volume_number: Some(index as u32 + 1), canonical_name: format!("part{}.rar", index + 1),
        }).collect();
        let cache = AttemptCache::default();
        for mode in [OpenMode::NativeVolumes, OpenMode::ConcatRanges, OpenMode::SfxWithVolumes] {
            input.mode = mode;
            let sessions = open_sessions(&input).unwrap();
            let key = Key::for_input(&input, &sessions).unwrap();
            cache.reject(key.clone(), &[Arc::from("old-wrong")]);
            let mut candidates = vec![Arc::from("old-wrong"), Arc::from("new")];
            assert!(cache.remove_rejected(&Key::for_input(&input, &sessions).unwrap(), &mut candidates));
            assert_eq!(candidates, [Arc::<str>::from("new")]);
            cache.update(key.clone(), |entry| entry.proof = Some(Some(Arc::from("right"))));
            assert_eq!(cache.proof(&key).unwrap().as_deref(), Some("right"));
            // The invalid header would fail a fresh verifier call; a stored
            // proof must return before parsing/KDF for every compound layout.
            let configured = CandidateSet::new(Arc::from([Arc::from("right")]), None, &cache, None);
            let plan = configured.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
            assert_eq!(plan.selected.as_deref(), Some("right"));
            assert!(plan.verified);
            let mut changed = input.clone();
            changed.parts[1].extent.start = 1;
            assert!(cache.proof(&Key::for_input(&changed, &sessions).unwrap()).is_none());
            changed = input.clone();
            changed.parts.swap(0, 1);
            assert!(cache.proof(&Key::for_input(&changed, &sessions).unwrap()).is_none());
        }
        input.volume_attempts = Some(Box::new(VolumeAttemptPlan {
            sources: input.parts.iter().map(|part| part.extent.clone()).collect(),
            layouts: vec![VolumeLayout { slots: vec![VolumeSlot {
                number: 1, canonical_name: "a.rar".into(), domain: 0,
            }].into(), minimum_slots: 1 }].into(),
            domains: vec![VolumeDomain { choices: Arc::new(vec![0, 1]) }].into(),
            head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
        }));
        let sessions = open_sessions(&input).unwrap();
        let planned = Key::for_input(&input, &sessions).unwrap();
        cache.reject(planned.clone(), &[Arc::from("old-wrong")]);
        let mut changed = input.clone();
        changed.volume_attempts.as_mut().unwrap().domains[0].choices = Arc::new(vec![1, 0]);
        assert!(Key::for_input(&changed, &sessions).unwrap() != planned);
        // Optional struct fields must retain their names: compact positional
        // serialization aliases these distinct constraints when values match.
        let mut head_constraint = input.clone();
        head_constraint.volume_attempts.as_mut().unwrap().head_size_from_total = Some(4);
        let mut minimum_constraint = input.clone();
        minimum_constraint.volume_attempts.as_mut().unwrap().minimum_size = Some(4);
        let head_key = Key::for_input(&head_constraint, &sessions).unwrap();
        let minimum_key = Key::for_input(&minimum_constraint, &sessions).unwrap();
        assert!(head_key != minimum_key);
        cache.reject(head_key, &[Arc::from("wrong-for-head")]);
        let mut candidates = vec![Arc::from("wrong-for-head")];
        cache.remove_rejected(&minimum_key, &mut candidates);
        assert_eq!(candidates.len(), 1);
        // This flag chooses ZIP volume verification rather than range verification.
        let mut zip = input.clone();
        zip.format_hint = "zip".into();
        zip.analysis.zip_spanned = false;
        let range_key = Key::for_input(&zip, &sessions).unwrap();
        cache.update(range_key.clone(), |entry| entry.proof = Some(Some(Arc::from("right"))));
        zip.analysis.zip_spanned = true;
        let volume_key = Key::for_input(&zip, &sessions).unwrap();
        assert!(range_key != volume_key);
        assert!(cache.proof(&volume_key).is_none());
        drop(sessions);
        crate::io::reader::invalidate_reader_path(&tail);
        let sessions = open_sessions(&input).unwrap();
        assert!(Key::for_input(&input, &sessions).unwrap() != planned);
        let mut oversized = input.clone();
        oversized.parts[0].canonical_name = "x".repeat(MAX_KEY_BYTES + 1);
        assert!(Key::for_input(&oversized, &sessions).is_none());
        // The byte budget complements the context count for large layouts.
        let bytes: Arc<[u8]> = vec![0; MAX_KEY_BYTES].into();
        for generation in 0..10 {
            let mut key = planned.clone();
            key.generation = generation;
            key.compound = Some(bytes.clone());
            cache.reject(key, &[Arc::from("old-wrong")]);
        }
        assert!(cache.0.lock().unwrap().key_bytes <= MAX_CACHE_KEY_BYTES);
        cache.clear();
        assert!(cache.0.lock().unwrap().entries.is_empty());
        assert_eq!(cache.0.lock().unwrap().key_bytes, 0);
        drop(sessions);
        let _ = std::fs::remove_file(head);
        let _ = std::fs::remove_file(tail);
    }

}
