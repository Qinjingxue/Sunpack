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

/// Exact, generation-bound identities for the common single-source layouts.
/// Compound layouts continue to share their native prepared verifier state.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    generation: u64,
    format: &'static str,
    start: u64,
    end: Option<u64>,
    eocd: Option<u64>,
}

impl Key {
    fn for_input(input: &ArchiveInput, sessions: &[NativeArchiveSession]) -> Option<Self> {
        let format = match input.format_hint.as_str() {
            "zip" => "zip",
            "rar" => "rar",
            "7z" => "7z",
            "enc" => "enc",
            _ => return None,
        };
        let (path, start, end) = match input.mode {
            OpenMode::File => (input.entry_path.as_str(), 0, None),
            OpenMode::FileRange => {
                let extent = &input.parts.first()?.extent;
                (extent.path.as_str(), extent.start, extent.end)
            }
            _ => return None,
        };
        let generation = sessions.iter().find_map(|session| {
            let (source, generation) = session.generation().ok()?;
            (source == path).then_some(generation)
        })?;
        Some(Self {
            generation,
            format,
            start,
            end,
            eocd: input.analysis.zip_eocd_offset,
        })
    }
}

#[derive(Default)]
pub(super) struct AttemptCache(Mutex<AttemptCacheState>);

#[derive(Default)]
struct AttemptCacheState {
    entries: HashMap<Key, Attempts>,
    clock: u64,
    rejections: usize,
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

    fn proof(&self, key: Key) -> Option<Option<Arc<str>>> {
        let mut state = self.0.lock().unwrap();
        let used = state.tick();
        let entry = state.entries.get_mut(&key)?;
        entry.used = used;
        entry.proof.clone()
    }

    fn remove_rejected(&self, key: Key, candidates: &mut Vec<Arc<str>>) -> bool {
        let mut state = self.0.lock().unwrap();
        let used = state.tick();
        let Some(entry) = state.entries.get_mut(&key) else {
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
        let entry = state.entries.entry(key).or_default();
        let previous = entry.rejected.len();
        entry.used = used;
        operation(entry);
        let next = entry.rejected.len();
        state.rejections = state.rejections - previous + next;
        while state.entries.len() > MAX_CONTEXTS || state.rejections > MAX_REJECTIONS {
            let oldest = *state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .unwrap()
                .0;
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
        if !self
            .configured(&input.entry_path)
            .any(|value| !value.is_empty())
        {
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
        if let Some(proof) = key.and_then(|key| self.cache.proof(key)) {
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
            .filter(|value| !value.is_empty())
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
            if let Some(key) = key {
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
                    if let Some(key) = key {
                        self.cache.update(key, |entry| entry.proof = Some(None));
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
                        if let Some(key) = key {
                            self.cache
                                .update(key, |entry| entry.proof = Some(Some(password.clone())));
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
                    if let Some(key) = key.filter(|_| !rejected.is_empty()) {
                        self.cache.reject(key, &rejected);
                    }
                    evidence = match (evidence, result.match_evidence) {
                        (None, next) => next,
                        (old, next) if old == next => old,
                        _ => Some("mixed"),
                    };
                }
                "no_match" => {
                    password_rejected |= result.attempts != 0;
                    if let Some(key) = key.filter(|_| result.attempts != 0) {
                        self.cache
                            .reject(key, &batch[..result.attempts.min(batch.len())]);
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
    input
        .physical_extents()
        .map(|extent| extent.path.as_str())
        .chain(std::iter::once(input.entry_path.as_str()))
        .filter(|path| seen.insert(*path))
        .map(|path| NativeArchiveSession::new(path.to_owned()))
        .collect()
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
        let has_candidates = !password.is_empty();
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
        if let Some(key) = self.cache_key {
            cache.update(key, |entry| entry.proof = Some(Some(Arc::clone(password))));
        }
        Some(password)
    }

    pub(super) fn remember_rejections(&self, cache: &AttemptCache) {
        if let Some(key) = self.cache_key.filter(|_| !self.candidates.is_empty()) {
            cache.reject(key, &self.candidates);
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
}
