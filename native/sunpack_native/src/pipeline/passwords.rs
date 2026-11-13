use super::{Failure, FailureKind};
use crate::core::passwords::PasswordSnapshot;
use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::cancellation::Cancellation;
use crate::io::reader::NativeArchiveSession;
use crate::password;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

const BATCH_SIZE: usize = 256;
const MAX_SUCCESSES: usize = 1024;
const MAX_REJECTIONS: usize = 8192;
const MAX_RECENT_PASSWORDS: usize = 64;

// Compact exact identities, not hash-only fingerprints: a collision must never
// skip a password. Single files stay allocation-free; compound keys reuse the
// existing binary serializer and are shared between plans and cache entries.

#[derive(Clone, PartialEq, Eq)]
struct Key {
    generation: u64,
    format: &'static str,
    start: u64,
    end: Option<u64>,
    eocd: Option<u64>,
    zip_spanned: bool,
    compound: Option<Arc<[u8]>>,
    compound_hash: u64,
}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Negative entries are keyed per candidate. Hash a compound layout
        // once when planning, not once per password; Eq still checks the full
        // identity, so a fast-hash collision cannot reuse another proof.
        std::hash::Hash::hash(&(
            self.generation, self.format, self.start, self.end, self.eocd,
            self.zip_spanned, self.compound.is_some(), self.compound_hash,
        ), state);
    }
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
        let compound: Option<Arc<[u8]>> = if input.volume_attempts.is_some()
            || !matches!(input.mode, OpenMode::File | OpenMode::FileRange)
        {
            // Iteration follows the descriptor, not HashMap order. Binding all
            // candidate sources prevents stale proof reuse after a volume edit.
            let generations = sessions.iter().map(NativeArchiveSession::generation)
                .collect::<io::Result<HashMap<_, _>>>().ok()?;
            let members = input.physical_paths().chain(std::iter::once(input.entry_path.as_str()))
                .map(|path| Some((path, *generations.get(path)?)))
                .collect::<Option<Vec<_>>>()?;
            let bytes = rmp_serde::to_vec_named(&(
                input.mode, &members, &input.parts, &input.ranges,
                &input.volume_attempts,
            )).ok()?;
            Some(Arc::from(bytes))
        } else { None };
        let compound_hash = compound.as_deref().map_or(0, |bytes| crate::fast_hash_core::xxh64(bytes, 0));
        Some(Self { generation, format, start, end,
            eocd: input.analysis.zip_eocd_offset, zip_spanned: input.analysis.zip_spanned,
            compound, compound_hash })
    }

}

#[derive(Clone, Default)]
pub(super) struct AttemptCache(Arc<Mutex<AttemptCacheState>>);

#[derive(Default)]
struct AttemptCacheState {
    successes: CacheOrder<Key, Option<Arc<str>>>,
    negative: CacheOrder<(Key, Arc<str>), ()>,
    recent: VecDeque<Arc<str>>,
}

// main keeps independent LRU budgets for successful contexts and individual
// rejected (context, password) pairs. A batch of contexts must not evict all
// proofs or rejections just because it crosses an unrelated context limit.
// Slots form an intrusive oldest-to-newest list. A hit changes only links,
// with no key clone, allocation, ordered-tree operation, or growing timestamp.
// Each cache has a fixed positive budget; eviction reuses the oldest slot.
struct CacheOrder<K, V> {
    entries: HashMap<K, usize>,
    slots: Vec<CacheEntry<K, V>>,
    oldest: Option<usize>,
    newest: Option<usize>,
}

struct CacheEntry<K, V> {
    key: K,
    value: V,
    previous: Option<usize>,
    next: Option<usize>,
}

impl<K, V> Default for CacheOrder<K, V> {
    fn default() -> Self {
        Self { entries: HashMap::new(), slots: Vec::new(), oldest: None, newest: None }
    }
}

impl<K: Eq + std::hash::Hash + Clone, V> CacheOrder<K, V> {
    fn touch(&mut self, index: usize) {
        if self.newest == Some(index) {
            return;
        }
        let previous = self.slots[index].previous;
        let next = self.slots[index].next;
        if let Some(previous) = previous {
            self.slots[previous].next = next;
        } else {
            self.oldest = next;
        }
        if let Some(next) = next {
            self.slots[next].previous = previous;
        }
        if let Some(newest) = self.newest {
            self.slots[newest].next = Some(index);
        }
        self.slots[index].previous = self.newest;
        self.slots[index].next = None;
        self.newest = Some(index);
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        let index = *self.entries.get(key)?;
        self.touch(index);
        Some(&self.slots[index].value)
    }

    fn insert(&mut self, key: K, value: V, limit: usize) {
        if let Some(&index) = self.entries.get(&key) {
            self.slots[index].value = value;
            self.touch(index);
            return;
        }
        let index = if self.slots.len() == limit {
            let index = self.oldest.unwrap();
            self.entries.remove(&self.slots[index].key);
            self.slots[index].key = key.clone();
            self.slots[index].value = value;
            self.touch(index);
            index
        } else {
            let index = self.slots.len();
            self.slots.push(CacheEntry { key: key.clone(), value,
                previous: self.newest, next: None });
            if let Some(newest) = self.newest {
                self.slots[newest].next = Some(index);
            } else {
                self.oldest = Some(index);
            }
            self.newest = Some(index);
            index
        };
        self.entries.insert(key, index);
    }
}

impl AttemptCache {
    pub(super) fn clear(&self) {
        let mut state = self.0.lock().unwrap();
        state.successes = CacheOrder::default();
        state.negative = CacheOrder::default();
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
        self.0.lock().unwrap().successes.get(key).cloned()
    }

    fn remove_rejected(&self, key: &Key, candidates: &mut Vec<Arc<str>>) -> bool {
        let mut state = self.0.lock().unwrap();
        let before = candidates.len();
        candidates.retain(|password| state.negative.get(&(key.clone(), password.clone())).is_none());
        candidates.len() != before
    }

    fn remember_proof(&self, key: Key, proof: Option<Arc<str>>) {
        self.0.lock().unwrap().successes.insert(key, proof, MAX_SUCCESSES);
    }

    fn reject(&self, key: Key, candidates: &[Arc<str>]) {
        let mut state = self.0.lock().unwrap();
        for password in candidates {
            state.negative.insert((key.clone(), password.clone()), (), MAX_REJECTIONS);
        }
    }
}

#[derive(Clone)]
pub(super) struct CandidateSet {
    explicit: Arc<[Arc<str>]>,
    snapshot: Arc<PasswordSnapshot>,
    explicit_signature: Arc<OnceLock<String>>,
    cache: AttemptCache,
    inherited_scope: Option<Arc<Path>>,
}

impl CandidateSet {
    pub(super) fn new(
        explicit: Arc<[Arc<str>]>,
        snapshot: Option<Arc<PasswordSnapshot>>,
        cache: &AttemptCache,
        inherited_scope: Option<&Path>,
    ) -> Self {
        Self {
            explicit,
            snapshot: snapshot.unwrap_or_default(),
            explicit_signature: Arc::new(OnceLock::new()),
            cache: cache.clone(),
            inherited_scope: inherited_scope.map(Arc::from),
        }
    }

    pub(super) fn with_scope(&self, scope: Option<&Path>) -> CandidateSet {
        CandidateSet {
            explicit: Arc::clone(&self.explicit),
            snapshot: self.snapshot.clone(),
            explicit_signature: self.explicit_signature.clone(),
            cache: self.cache.clone(),
            inherited_scope: self.inherited_scope.clone().or_else(|| scope.map(Arc::from)),
        }
    }

    pub(super) fn signature(&self, path: &str) -> String {
        // Only password-failure receipts ask for this. Pin the explicit digest
        // once per request and share it with nested scopes; builtin snapshots
        // already cache each bucket, so rechecking N failures never rehashes P
        // password strings for every entry.
        let explicit = self.explicit_signature.get_or_init(|| {
            let mut hash = crate::fast_hash_core::Hash128::new();
            hash.update(&(self.explicit.len() as u64).to_le_bytes());
            for password in self.explicit.iter() {
                hash.update(&(password.len() as u64).to_le_bytes());
                hash.update(password.as_bytes());
            }
            hash.hexdigest()
        });
        let mut hash = crate::fast_hash_core::Hash128::new();
        hash.update(explicit.as_bytes());
        hash.update(self.snapshot.scope_signature(self.scope(path)).as_bytes());
        hash.hexdigest()
    }

    fn scope<'b>(&'b self, path: &'b str) -> &'b Path {
        self.inherited_scope.as_deref()
            .unwrap_or_else(|| Path::new(path).parent().unwrap_or_else(|| Path::new(path)))
    }

    fn configured<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        self.snapshot.scoped(self.scope(path)).flatten()
            .chain(self.explicit.iter())
            .chain(self.snapshot.global().iter())
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
                        self.cache.remember_proof(key.clone(), None);
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
                            self.cache.remember_proof(key.clone(), Some(password.clone()));
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
                        || input.execution_evidence().is_some()
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
                    let mut failure = Failure::new(kind, result.message);
                    failure.evidence = Some(Box::new(super::FailureEvidence {
                        stage: Some("password_preflight".into()),
                        native_kind: Some(result.status.into()),
                        archive_read_fault: result.read_fault.as_ref().map(Into::into),
                        ..Default::default()
                    }));
                    return Ok(Err(failure));
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
            cache.remember_proof(key.clone(), Some(Arc::clone(password)));
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
    fn cache_order_reuses_slots_and_matches_lru_on_hits_and_replacements() {
        // Compare mixed middle/head/tail touches and overwritten values with a
        // simple ordered-list model; also catch leaked eviction slots.
        for limit in [1, 3, 17] {
            let mut cache = CacheOrder::default();
            let mut expected = VecDeque::new();
            for step in 0..512 {
                let key = (step * 7 + step / 3) % (limit * 2 + 1);
                let previous = expected.iter().position(|(old, _)| *old == key)
                    .and_then(|index| expected.remove(index));
                if step % 3 == 0 {
                    assert_eq!(cache.get(&key).copied(), previous.map(|(_, value)| value));
                    if let Some(previous) = previous {
                        expected.push_back(previous);
                    }
                } else {
                    cache.insert(key, step, limit);
                    expected.push_back((key, step));
                    if expected.len() > limit { expected.pop_front(); }
                }
                let mut actual = Vec::new();
                let mut position = cache.oldest;
                let mut previous = None;
                while let Some(index) = position {
                    assert!(actual.len() < limit, "cyclic LRU links");
                    let entry = &cache.slots[index];
                    assert_eq!(entry.previous, previous);
                    assert_eq!(cache.entries.get(&entry.key), Some(&index));
                    actual.push((entry.key, entry.value));
                    previous = position;
                    position = entry.next;
                }
                assert_eq!(cache.newest, previous);
                assert_eq!(actual, expected.iter().copied().collect::<Vec<_>>());
                assert_eq!(cache.entries.len(), expected.len());
                assert_eq!(cache.slots.len(), expected.len());
            }
        }
    }

    #[test]
    fn attempt_cache_keeps_batch_proofs_and_individual_negative_lru() {
        // More than 128 live inputs must retain results through a hot retry.
        // Independently exercise the real limits, so raising one context cap
        // cannot hide whole-context eviction of negatives or proofs.
        let cache = AttemptCache::default();
        let key = |generation| Key { generation, format: "zip", start: 0, end: None,
            eocd: None, zip_spanned: false, compound: None, compound_hash: 0 };
        let passwords: Vec<Arc<str>> = (0..4).map(|n| Arc::from(n.to_string())).collect();
        for n in 0..129 {
            cache.reject(key(n), &passwords);
            cache.remember_proof(key(n), Some(Arc::from("good")));
        }
        for n in 0..129 {
            let mut candidates = passwords.clone();
            assert!(cache.remove_rejected(&key(n), &mut candidates));
            assert!(candidates.is_empty());
            assert_eq!(cache.proof(&key(n)).unwrap().as_deref(), Some("good"));
        }
        cache.clear();
        for n in 0..MAX_REJECTIONS as u64 {
            cache.reject(key(n), &[Arc::from("bad")]);
        }
        // Touch one entry and exceed the negative limit: only the oldest pair
        // is removed, not the rest of a context or the independent proof.
        cache.remember_proof(key(1), Some(Arc::from("good")));
        assert!(cache.remove_rejected(&key(0), &mut vec![Arc::from("bad")]));
        cache.reject(key(0), &[Arc::from("another")]);
        assert!(!cache.remove_rejected(&key(1), &mut vec![Arc::from("bad")]));
        assert!(cache.remove_rejected(&key(0), &mut vec![Arc::from("bad")]));
        assert!(cache.proof(&key(1)).is_some());
        for n in 2..=MAX_SUCCESSES as u64 + 1 {
            cache.remember_proof(key(n), Some(Arc::from("good")));
        }
        assert!(cache.proof(&key(1)).is_none());
        assert!(cache.remove_rejected(&key(0), &mut vec![Arc::from("another")]));

        // Force equal hash summaries for different exact layouts. Neither
        // successful nor negative results may leak across the collision.
        let mut left = key(0);
        left.compound = Some(Arc::from([1u8]));
        let mut right = left.clone();
        right.compound = Some(Arc::from([2u8]));
        let hash = |key: &Key| {
            use std::hash::{Hash, Hasher};
            let mut hash = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hash);
            hash.finish()
        };
        assert_eq!(hash(&left), hash(&right));
        cache.remember_proof(left.clone(), Some(Arc::from("left")));
        cache.reject(left, &[Arc::from("wrong")]);
        assert!(cache.proof(&right).is_none());
        assert!(!cache.remove_rejected(&right, &mut vec![Arc::from("wrong")]));
    }

    #[test]
    fn failure_signatures_share_lazy_explicit_digest_without_changing_candidates() {
        let cache = AttemptCache::default();
        let values = Arc::from([Arc::from(""), Arc::from("first"), Arc::from("second")]);
        let candidates = CandidateSet::new(values, None, &cache, None);
        let inherited = candidates.with_scope(Some(Path::new(r"C:\root")));
        // Successful planning/display does not compute receipt fingerprints.
        assert_eq!(candidates.for_embedded(r"C:\root\input.zip"),
            [Arc::<str>::from(""), Arc::from("first"), Arc::from("second")]);
        assert!(candidates.explicit_signature.get().is_none());
        assert!(Arc::ptr_eq(&candidates.explicit_signature, &inherited.explicit_signature));
        let signature = candidates.signature(r"C:\root\input.zip");
        let digest = candidates.explicit_signature.get().unwrap().as_ptr();
        for index in 0..256 {
            assert_eq!(inherited.signature(&format!(r"C:\nested\{index}.zip")), signature);
            assert_eq!(inherited.explicit_signature.get().unwrap().as_ptr(), digest);
        }
        let reordered = CandidateSet::new(
            Arc::from([Arc::from(""), Arc::from("second"), Arc::from("first")]), None, &cache, None);
        assert_ne!(signature, reordered.signature(r"C:\root\input.zip"));
        let empty = CandidateSet::new(Arc::from([Arc::from("")]), None, &cache, None);
        let absent = CandidateSet::new(Arc::from([]), None, &cache, None);
        assert_ne!(empty.signature("input.zip"), absent.signature("input.zip"));
        let empty_snapshot = CandidateSet::new(Arc::from([]), Some(Arc::default()), &cache, None);
        assert_eq!(absent.signature("input.zip"), empty_snapshot.signature("input.zip"));
    }

    #[test]
    fn preflight_read_failure_retains_machine_readable_evidence() {
        // Two passwords force the Rust probe, unlike single-candidate worker
        // confirmation. This exercises the terminal planning projection.
        let path = crate::test_support::temp_file("enc_read_fault_evidence", b"short");
        let input = ArchiveInput::file(path.to_string_lossy().into_owned(), "enc".into(), "archive".into());
        let cache = AttemptCache::default();
        let candidates = CandidateSet::new(Arc::from(["first".into(), "second".into()]), None, &cache, None);
        let failure = candidates.plan(&input, None, &Cancellation::new()).unwrap().err().unwrap();
        assert_eq!(failure.kind, FailureKind::Damaged);
        let json = serde_json::to_value(&failure).unwrap();
        let evidence = &json["evidence"];
        assert_eq!(evidence["stage"], "password_preflight");
        let fault = &evidence["archive_read_fault"];
        assert_eq!(fault["field"], "enc.password_proof");
        assert_eq!(fault["offset"], 0);
        assert_eq!(fault["requested"], 72);
        assert_eq!(fault["actual"], 5);
        assert_eq!(fault["possible_missing_volume"], false);
        assert!(!failure.message.is_empty());
        // An advisory tail hint does not turn this same damaged file into a
        // confirmed missing volume. Relation discovery may confirm it.
        let mut hinted = input.clone();
        hinted.analysis.planning_applied = true;
        hinted.analysis.missing_volume_evidence = Some("seven_zip_start_header_length".into());
        assert_eq!(candidates.plan(&hinted, None, &Cancellation::new()).unwrap().err().unwrap().kind,
            FailureKind::Damaged);
        hinted.analysis.planning_applied = false;
        hinted.analysis.origin = crate::io::archive_state::AnalysisOrigin::Relations;
        assert_eq!(candidates.plan(&hinted, None, &Cancellation::new()).unwrap().err().unwrap().kind,
            FailureKind::MissingVolume);
        let _ = std::fs::remove_file(path);
    }

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
        cache.remember_proof(key, Some(Arc::from("")));
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
            role: if index == 0 { crate::io::archive_state::InputRole::First } else { crate::io::archive_state::InputRole::Member },
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
            cache.remember_proof(key.clone(), Some(Arc::from("right")));
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
        cache.remember_proof(range_key.clone(), Some(Arc::from("right")));
        zip.analysis.zip_spanned = true;
        let volume_key = Key::for_input(&zip, &sessions).unwrap();
        assert!(range_key != volume_key);
        assert!(cache.proof(&volume_key).is_none());
        drop(sessions);
        crate::io::reader::invalidate_reader_path(&tail);
        let sessions = open_sessions(&input).unwrap();
        assert!(Key::for_input(&input, &sessions).unwrap() != planned);
        cache.clear();
        assert!(cache.0.lock().unwrap().successes.entries.is_empty());
        assert!(cache.0.lock().unwrap().negative.entries.is_empty());
        drop(sessions);
        let _ = std::fs::remove_file(head);
        let _ = std::fs::remove_file(tail);
    }

}
