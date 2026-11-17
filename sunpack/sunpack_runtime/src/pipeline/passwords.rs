use super::{Failure, FailureKind};
use crate::core::passwords::PasswordSnapshot;
use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::cancellation::Cancellation;
use crate::io::reader::NativeArchiveSession;
use crate::password::{self, attempts::Key};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

const BATCH_SIZE: usize = password::VERIFICATION_BATCH_SIZE;
const MAX_RECENT_PASSWORDS: usize = 64;

#[derive(Clone, Default)]
pub(super) struct RecentPasswords(Arc<Mutex<VecDeque<Arc<str>>>>);

impl RecentPasswords {
    pub(super) fn recent(&self) -> Vec<Arc<str>> {
        self.0.lock().unwrap().iter().cloned().collect()
    }

    pub(super) fn clear(&self) {
        let recent = std::mem::take(&mut *self.0.lock().unwrap());
        drop(recent);
    }

    fn remember_recent(&self, password: Arc<str>) {
        if password.is_empty() {
            return;
        }
        let mut recent = self.0.lock().unwrap();
        if let Some(index) = recent.iter().position(|old| *old == password) {
            recent.remove(index);
        }
        recent.push_front(password);
        recent.truncate(MAX_RECENT_PASSWORDS);
    }

}

#[derive(Clone)]
pub(super) struct CandidateSet {
    sources: Arc<CandidateSources>,
    inherited_scope: Option<Arc<Path>>,
}

struct CandidateSources {
    explicit: Arc<[Arc<str>]>,
    snapshot: Arc<PasswordSnapshot>,
    explicit_signature: OnceLock<String>,
    recent: RecentPasswords,
}

impl CandidateSet {
    pub(super) fn new(
        explicit: Arc<[Arc<str>]>,
        snapshot: Option<Arc<PasswordSnapshot>>,
        recent: &RecentPasswords,
        inherited_scope: Option<&Path>,
    ) -> Self {
        Self {
            sources: Arc::new(CandidateSources {
                explicit,
                snapshot: snapshot.unwrap_or_default(),
                explicit_signature: OnceLock::new(),
                recent: recent.clone(),
            }),
            inherited_scope: inherited_scope.map(Arc::from),
        }
    }

    pub(super) fn with_scope(&self, scope: Option<&Path>) -> CandidateSet {
        CandidateSet {
            sources: Arc::clone(&self.sources),
            inherited_scope: self.inherited_scope.clone().or_else(|| scope.map(Arc::from)),
        }
    }

    pub(super) fn signature(&self, path: &str) -> String {
        // Only password-failure receipts ask for this. Pin the explicit digest
        // once per request and share it with nested scopes; builtin snapshots
        // already cache each bucket, so rechecking N failures never rehashes P
        // password strings for every entry.
        let explicit = self.sources.explicit_signature.get_or_init(|| {
            let mut hash = crate::fast_hash_core::Hash128::new();
            hash.update(&(self.sources.explicit.len() as u64).to_le_bytes());
            for password in self.sources.explicit.iter() {
                hash.update(&(password.len() as u64).to_le_bytes());
                hash.update(password.as_bytes());
            }
            hash.hexdigest()
        });
        let mut hash = crate::fast_hash_core::Hash128::new();
        hash.update(explicit.as_bytes());
        hash.update(self.sources.snapshot.scope_signature(self.scope(path)).as_bytes());
        hash.hexdigest()
    }

    fn scope<'b>(&'b self, path: &'b str) -> &'b Path {
        self.inherited_scope.as_deref()
            .unwrap_or_else(|| Path::new(path).parent().unwrap_or_else(|| Path::new(path)))
    }

    fn configured<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        self.sources.snapshot.scoped(self.scope(path)).flatten()
            .chain(self.sources.explicit.iter())
            .chain(self.sources.snapshot.global().iter())
    }

    fn for_path<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        let recent = self.sources.recent.recent();
        let mut seen: HashSet<&str> = HashSet::new();
        let priority = if recent.is_empty() {
            Vec::new()
        } else {
            let mut positions: HashMap<_, _> = recent.iter().enumerate()
                .map(|(index, password)| (password.as_ref(), index)).collect();
            let mut priority = vec![None; recent.len()];
            for password in self.configured(path) {
                if let Some(index) = positions.remove(password.as_ref()) {
                    priority[index] = Some(password);
                    seen.insert(password.as_ref());
                    if positions.is_empty() {
                        break;
                    }
                }
            }
            priority
        };
        priority
            .into_iter()
            .flatten()
            .chain(self.configured(path).filter(move |value| {
                let value: &'b Arc<str> = *value;
                seen.insert(value.as_ref())
            }))
    }

    pub(super) fn for_embedded(&self, path: &str) -> Vec<Arc<str>> {
        self.for_path(path).cloned().collect()
    }

    pub(super) fn remember_verified(&self, password: Arc<str>) {
        self.sources.recent.remember_recent(password);
    }

    /// Relations uses the same generation-bound proofs, bounded batches and
    /// candidate parallelism as extraction. Only unresolved structure is read
    /// afterwards; ordinary single volumes do not need an ENDARC walk.
    pub(super) fn resolve_relation(
        &self,
        anchor: &crate::analysis_native::volume_anchor::VolumeAnchor,
        session: &NativeArchiveSession,
        cancellation: &Cancellation,
    ) -> io::Result<(crate::analysis_native::volume_anchor::VolumeAnchor, Option<Arc<str>>)> {
        use crate::io::archive_state::{InputExtent, InputPart};
        let mut input = ArchiveInput::file(anchor.path.clone(), "rar".into(), String::new());
        let offset = anchor.structure_offset.unwrap_or(0);
        if offset != 0 || anchor.carrier_limit.is_some() {
            input.mode = OpenMode::FileRange;
            input.parts = vec![InputPart::range(InputExtent {
                path: anchor.path.clone(), start: offset, end: anchor.carrier_limit,
            })].into();
        }
        input.analysis.password_required = true;
        let mut key = None;
        let plan = match self.plan_inner(&input, None, cancellation, Some(std::slice::from_ref(session)),
            &mut password::context::Preparation::capturing_rar5_key(&mut key))? {
            Ok(plan) => plan,
            Err(failure) => {
                let mut out = anchor.clone();
                out.wrong_password = failure.kind == FailureKind::WrongPassword;
                return Ok((out, None));
            }
        };
        let passwords = plan.verified_password.as_ref().map(std::slice::from_ref)
            .unwrap_or(&plan.candidates);
        let (_, reader) = session.borrowed_reader();
        let (out, matched) = crate::analysis_native::volume_anchor::resolve_encrypted_relation_anchor(
            anchor, &reader, passwords, offset != 0 || anchor.carrier_limit.is_some(), key.as_ref(),
        )?;
        Ok((out, matched.map(|index| passwords[index].clone())))
    }

    pub(super) fn plan(
        &self,
        input: &ArchiveInput,
        known: Option<Arc<str>>,
        cancellation: &Cancellation,
    ) -> io::Result<Result<PasswordPlan, Failure>> {
        self.plan_inner(input, known, cancellation, None, &mut password::context::Preparation::default())
    }

    fn plan_inner(
        &self,
        input: &ArchiveInput,
        known: Option<Arc<str>>,
        cancellation: &Cancellation,
        sessions: Option<&[NativeArchiveSession]>,
        preparation: &mut password::context::Preparation<'_>,
    ) -> io::Result<Result<PasswordPlan, Failure>> {
        let recent = &self.sources.recent;
        if let Some(password) = known {
            recent.remember_recent(password.clone());
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
        let borrowed = sessions.is_some();
        let opened;
        let sessions = match sessions {
            Some(sessions) => sessions,
            None if matches!(input.format_hint.as_str(), "zip" | "rar" | "7z" | "enc") => {
                opened = open_sessions(input)?;
                &opened
            }
            None => &[],
        };
        // An independently opened source vanishes with this plan. Memoize
        // only when another caller already owns the source or supplied it.
        let attempts = (borrowed || sessions.iter().any(NativeArchiveSession::shares_source))
            .then(|| Key::for_input(input, sessions)).flatten();
        if let Some(proof) = attempts.as_ref().and_then(|(key, cache)| cache.proof(key)) {
            match proof {
                None => return Ok(Ok(PasswordPlan::clear())),
                Some(password)
                    if (!needs_password && password.is_empty())
                        || self
                            .configured(&input.entry_path)
                            .any(|candidate| candidate == &password) =>
                {
                    recent.remember_recent(password.clone());
                    return Ok(Ok(PasswordPlan::verified(password)));
                }
                _ => {}
            }
        }
        let candidates = self
            .for_path(&input.entry_path)
            .filter(|value| needs_password || !value.is_empty());
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let mut pending = Vec::new();
        let mut evidence = None;
        let mut password_rejected = false;
        let mut has_candidates = false;
        let mut candidates = candidates.inspect(|_| has_candidates = true);
        // Empty has first-candidate priority, not a separate verification phase.
        // Fill the same batch so the native verifier retains its parallel threshold.
        if !needs_password {
            let empty = Arc::from("");
            password_rejected = attempts.as_ref().is_some_and(|(key, cache)| cache.rejected(key, &empty));
            if !password_rejected { batch.push(empty); }
        }
        loop {
            cancellation.check_io()?;
            // Fill after skipping cached negatives; sparse survivors must still
            // reach the native parallel paths.
            if let Some((key, cache)) = attempts.as_ref() {
                cache.fill_available(key, &mut batch, &mut candidates, cancellation)?;
            } else {
                batch.extend(candidates.by_ref().take(BATCH_SIZE - batch.len()).cloned());
            }
            if batch.is_empty() {
                password_rejected |= has_candidates;
                break;
            }
            if check_single_enc && batch.len() == 1 {
                // The worker authenticates the sole ENC candidate when opening
                // the archive. A host probe would repeat the same Argon2 work.
                pending.append(&mut batch);
                break;
            }
            check_single_enc = false;
            #[cfg(test)]
            PLANNED_BATCHES.with(|capture| {
                if let Some(batches) = capture.borrow_mut().as_mut() { batches.push(batch.clone()); }
            });
            let result = password::verify(preparation, input, &batch, sessions, None)?;
            match result.status {
                "not_required" => {
                    if let Some((key, cache)) = attempts.as_ref() {
                        cache.remember_proof(key.clone(), None);
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
                        recent.remember_recent(password.clone());
                        if let Some((key, cache)) = attempts.as_ref() {
                            cache.remember_proof(key.clone(), Some(password.clone()));
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
                        } else if attempts.is_some() {
                            rejected.push(value.clone());
                        }
                    }
                    if let Some((key, cache)) = attempts.as_ref().filter(|_| !rejected.is_empty()) {
                        cache.reject(key.clone(), &rejected);
                    }
                    evidence = match (evidence, result.match_evidence) {
                        (None, next) => next,
                        (old, next) if old == next => old,
                        _ => Some("mixed"),
                    };
                }
                "no_match" => {
                    password_rejected |= result.attempts != 0;
                    if let Some((key, cache)) = attempts.as_ref().filter(|_| result.attempts != 0) {
                        cache
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
            verified_password: None,
            candidates: Arc::new(pending),
            encrypted: needs_password.then_some(true),
            evidence,
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
    pub verified_password: Option<Arc<str>>,
    pub candidates: Arc<Vec<Arc<str>>>,
    pub encrypted: Option<bool>,
    pub evidence: Option<&'static str>,
}

impl PasswordPlan {
    fn empty_fallback() -> Self {
        Self {
            verified_password: None,
            candidates: Arc::new(vec![Arc::from("")]),
            encrypted: None,
            evidence: Some("empty_password_direct"),
        }
    }

    fn clear() -> Self {
        Self {
            verified_password: None,
            candidates: Arc::default(),
            encrypted: Some(false),
            evidence: None,
        }
    }

    fn verified(password: Arc<str>) -> Self {
        Self {
            verified_password: Some(password),
            candidates: Arc::default(),
            encrypted: Some(true),
            evidence: None,
        }
    }

    pub(super) fn remember_confirmation(
        &self,
        index: Option<usize>,
        recent: &RecentPasswords,
    ) -> Option<&str> {
        let password = match index {
            Some(index) => self.candidates.get(index)?,
            None if self.candidates.len() <= 1 => {
                self.verified_password.as_ref().or_else(|| self.candidates.first())?
            }
            None => return None,
        };
        recent.remember_recent(Arc::clone(password));
        Some(password)
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
thread_local! {
    static PLANNED_BATCHES: std::cell::RefCell<Option<Vec<Vec<Arc<str>>>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
#[path = "../../tests/unit/pipeline/passwords/tests.rs"]
mod tests;
