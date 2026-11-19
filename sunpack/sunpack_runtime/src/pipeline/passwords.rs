use super::{Failure, FailureKind, Mode};
use crate::core::passwords::PasswordSnapshot;
use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::cancellation::Cancellation;
use crate::io::reader::NativeArchiveSession;
use crate::password::{self, attempts::Key, evidence::SurvivingCandidates};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

const BATCH_SIZE: usize = password::VERIFICATION_BATCH_SIZE;
const MAX_RECENT_PASSWORDS: usize = 64;

type RecentOrder = Arc<VecDeque<Arc<str>>>;

#[derive(Clone, Default)]
pub(super) struct RecentPasswords(Arc<Mutex<RecentOrder>>);

impl RecentPasswords {
    pub(super) fn recent(&self) -> Vec<Arc<str>> {
        self.snapshot().iter().cloned().collect()
    }

    fn snapshot(&self) -> RecentOrder {
        Arc::clone(&self.0.lock().unwrap())
    }

    pub(super) fn clear(&self) {
        let recent = std::mem::take(&mut *self.0.lock().unwrap());
        drop(recent);
    }

    fn remember_recent(&self, password: Arc<str>) {
        if password.is_empty() {
            return;
        }
        let mut current = self.0.lock().unwrap();
        if current.front() == Some(&password) {
            return;
        }
        let recent = Arc::make_mut(&mut current);
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
    recent_priority: Mutex<Option<RecentPriority>>,
}

struct RecentPriority {
    recent: RecentOrder,
    indices: Arc<[(usize, usize)]>,
}

impl CandidateSources {
    fn base_password(&self, index: usize) -> &Arc<str> {
        if index < self.explicit.len() {
            &self.explicit[index]
        } else {
            &self.snapshot.global()[index - self.explicit.len()]
        }
    }

    fn recent_indices(&self, recent: &RecentOrder) -> Arc<[(usize, usize)]> {
        if let Some(cached) = self.recent_priority.lock().unwrap().as_ref()
            .filter(|cached| Arc::ptr_eq(&cached.recent, recent))
        {
            return Arc::clone(&cached.indices);
        }
        // One request can have many inputs sharing these immutable sources.
        // Store only the recent matches, including an empty answer, and keep
        // a dictionary-sized search outside the lock shared by these inputs.
        let configured = self.explicit.iter().chain(self.snapshot.global()).enumerate();
        let indices: Arc<[_]> = prioritize(recent, configured).into();
        let cached = RecentPriority { recent: Arc::clone(recent), indices: Arc::clone(&indices) };
        let displaced = self.recent_priority.lock().unwrap().replace(cached);
        drop(displaced);
        indices
    }
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
                recent_priority: Mutex::default(),
            }),
            inherited_scope: inherited_scope.map(Arc::from),
        }
    }

    pub(super) fn with_scope(&self, scope: Option<&Path>) -> CandidateSet {
        CandidateSet {
            sources: Arc::clone(&self.sources),
            inherited_scope: self
                .inherited_scope
                .clone()
                .or_else(|| scope.map(Arc::from)),
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
        hash.update(
            self.sources
                .snapshot
                .scope_signature(self.scope(path))
                .as_bytes(),
        );
        hash.hexdigest()
    }

    fn scope<'b>(&'b self, path: &'b str) -> &'b Path {
        self.inherited_scope
            .as_deref()
            .unwrap_or_else(|| Path::new(path).parent().unwrap_or_else(|| Path::new(path)))
    }

    fn configured<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        self.sources
            .snapshot
            .scoped(self.scope(path))
            .flatten()
            .chain(self.sources.explicit.iter())
            .chain(self.sources.snapshot.global().iter())
    }

    fn for_path<'b>(&'b self, path: &'b str) -> impl Iterator<Item = &'b Arc<str>> + 'b {
        let recent = self.sources.recent.snapshot();
        let scoped: Vec<_> = self.sources.snapshot.scoped(self.scope(path)).collect();
        let global = self.sources.snapshot.global();
        let explicit = &self.sources.explicit;
        let priority = if recent.is_empty() {
            Vec::new()
        } else if explicit.len() + global.len() >= BATCH_SIZE {
            let base = self.sources.recent_indices(&recent);
            let mut ranked: Vec<_> = if scoped.is_empty() {
                Vec::new()
            } else {
                prioritize(&recent, scoped.iter().flat_map(|bucket| bucket.iter()).map(|value| (value, value)))
            };
            // An applicable scoped entry has precedence over the shared base.
            // Only merge recent entries, regardless of dictionary size.
            ranked.extend(base.iter().map(|&(rank, index)| (rank, self.sources.base_password(index))));
            if !scoped.is_empty() {
                ranked.sort_by_key(|&(rank, _)| rank);
                ranked.dedup_by_key(|entry| entry.0);
            }
            ranked
        } else {
            let values = scoped.iter().flat_map(|bucket| bucket.iter()).chain(explicit.iter()).chain(global);
            prioritize(&recent, values.map(|value| (value, value)))
        };
        let mut seen: HashSet<&str> = priority.iter().map(|&(_, value)| value.as_ref()).collect();
        let prefix = scoped.into_iter().flatten().chain(explicit.iter()).map(|value| (value, true));
        priority
            .into_iter()
            .map(|(_, value)| value)
            .chain(prefix.chain(global.iter().map(|value| (value, false))).filter_map(move |(value, track)| {
                // Global entries are already unique. Only earlier sources can
                // duplicate them, so the set never grows with this dictionary.
                let unique = if track { seen.insert(value.as_ref()) } else { !seen.contains(value.as_ref()) };
                unique.then_some(value)
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
    ) -> io::Result<(
        crate::analysis_native::volume_anchor::VolumeAnchor,
        Option<Arc<str>>,
    )> {
        use crate::io::archive_state::{InputExtent, InputPart};
        let mut input = ArchiveInput::file(anchor.path.clone(), "rar".into(), String::new());
        let offset = anchor.structure_offset.unwrap_or(0);
        if offset != 0 || anchor.carrier_limit.is_some() {
            input.mode = OpenMode::FileRange;
            input.parts = vec![InputPart::range(InputExtent {
                path: anchor.path.clone(),
                start: offset,
                end: anchor.carrier_limit,
            })]
            .into();
        }
        input.analysis.password_required = true;
        let mut key = None;
        let plan = match self.plan_inner(
            &mut input,
            None,
            cancellation,
            Mode::Scan,
            Some(std::slice::from_ref(session)),
            &mut password::context::Preparation::capturing_rar_key(&mut key),
            &mut None,
        )? {
            Ok(plan) => plan,
            Err(failure) => {
                let mut out = anchor.clone();
                out.wrong_password = failure.evidence.as_deref().is_some_and(|evidence| {
                    evidence.classification_evidence.as_deref()
                        == Some("password_candidates_all_rejected")
                });
                return Ok((out, None));
            }
        };
        let passwords = plan
            .verified_password
            .as_ref()
            .map(std::slice::from_ref)
            .unwrap_or(&plan.candidates);
        let (_, reader) = session.borrowed_reader();
        let (out, matched) =
            crate::analysis_native::volume_anchor::resolve_encrypted_relation_anchor(
                anchor,
                &reader,
                passwords,
                offset != 0 || anchor.carrier_limit.is_some(),
                key.as_ref(),
            )?;
        Ok((out, matched.map(|index| passwords[index].clone())))
    }

    pub(super) fn plan(
        &self,
        input: &mut ArchiveInput,
        known: Option<Arc<str>>,
        cancellation: &Cancellation,
        mode: Mode,
    ) -> io::Result<Result<PasswordPlan, Failure>> {
        let mut remaining = None;
        let result = self.plan_inner(
            input,
            known,
            cancellation,
            mode,
            None,
            &mut password::context::Preparation::default(),
            &mut remaining,
        )?;
        if remaining.is_some() {
            input.volume_attempts = remaining;
        }
        Ok(result)
    }

    fn plan_inner(
        &self,
        input: &mut ArchiveInput,
        known: Option<Arc<str>>,
        cancellation: &Cancellation,
        mode: Mode,
        sessions: Option<&[NativeArchiveSession]>,
        preparation: &mut password::context::Preparation<'_>,
        remaining: &mut Option<Arc<crate::io::archive_state::VolumeAttemptPlan>>,
    ) -> io::Result<Result<PasswordPlan, Failure>> {
        let recent = &self.sources.recent;
        if input.volume_attempts.is_none() {
            if let Some(password) = &known {
                recent.remember_recent(password.clone());
                return Ok(Ok(PasswordPlan::verified(password.clone())));
            }
        }
        if matches!(
            input.format_hint.as_str(),
            "tar" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4"
        ) {
            return Ok(Ok(PasswordPlan::clear()));
        }
        let single_enc_can_defer = mode == Mode::Extract && input.format_hint == "enc" && input.volume_attempts.is_none();
        let needs_password = input.analysis.password_required || input.format_hint == "enc";
        // Discovery already identifies inputs that require a password. For the
        // rest, an empty candidate can be confirmed by the ordinary worker
        // open. With no other candidates, a Rust probe only repeats that I/O.
        if known.is_none()
            && input.volume_attempts.is_none()
            && self.configured(&input.entry_path).next().is_none()
        {
            return Ok(if needs_password {
                Err(Failure::password())
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
        crate::relations::prepare_volume_candidates(input, sessions, preparation)?;
        let needs_password = input.analysis.password_required || input.format_hint == "enc";
        if input.volume_attempts.as_ref().is_some_and(|plan| plan.layouts.is_empty()) {
            return Ok(Err(Failure::new(
                FailureKind::MissingVolume,
                "no supplied volume candidate satisfies the archive evidence",
            )));
        }
        let mut fixed_plan = |password: Arc<str>,
                              preparation: &mut password::context::Preparation<'_>|
         -> io::Result<Result<PasswordPlan, Failure>> {
            recent.remember_recent(password.clone());
            let plan = PasswordPlan::verified(password.clone());
            if input.volume_attempts.is_some() {
                preparation.fix_password();
                let result = password::verify(
                    preparation,
                    input,
                    std::slice::from_ref(&password),
                    sessions,
                    None,
                )?;
                *remaining = result.volume_attempts;
                if remaining.as_ref().is_some_and(|p| p.layouts.is_empty())
                    || result.status == "no_match"
                {
                    return Ok(Err(Failure::new(
                        FailureKind::MissingVolume,
                        "no supplied volume candidate satisfies the confirmed password evidence",
                    )));
                }
            }
            Ok(Ok(plan))
        };
        if let Some(password) = known {
            return fixed_plan(password, preparation);
        }
        // An independently opened source vanishes with this plan. Memoize
        // only when another caller already owns the source or supplied it.
        let attempts = (borrowed || sessions.iter().any(NativeArchiveSession::shares_source))
            .then(|| Key::for_input(input, sessions))
            .flatten();
        if let Some(proof) = attempts.as_ref().and_then(|(key, cache)| cache.proof(key)) {
            match proof {
                None => return Ok(Ok(PasswordPlan::clear())),
                Some(password)
                    if (!needs_password && password.is_empty())
                        || self
                            .configured(&input.entry_path)
                            .any(|candidate| candidate == &password) =>
                {
                    return fixed_plan(password, preparation);
                }
                _ => {}
            }
        }
        let candidates = self
            .for_path(&input.entry_path)
            .filter(|value| needs_password || !value.is_empty());
        let projected = input.volume_attempts.is_some();
        let mut batch = Vec::with_capacity(BATCH_SIZE + usize::from(projected));
        let mut pending = Vec::new();
        let mut evidence = None;
        let mut domains = password::evidence::CandidateDomains::default();
        let mut password_rejected = false;
        let mut uncertain_volumes = false;
        let mut deferred_from = None;
        let mut has_candidates = false;
        let mut candidates = candidates.inspect(|_| has_candidates = true);
        // Empty has first-candidate priority, not a separate verification phase.
        // Fill the same batch so the native verifier retains its parallel threshold.
        if !needs_password {
            let empty = Arc::from("");
            password_rejected = attempts
                .as_ref()
                .is_some_and(|(key, cache)| cache.rejected(key, &empty));
            if !password_rejected {
                batch.push(empty);
            }
        }
        loop {
            cancellation.check_io()?;
            // A full batch may also be the last. A single buffered candidate
            // distinguishes these cases without sending a larger KDF batch.
            let limit = BATCH_SIZE + usize::from(projected && pending.is_empty() && deferred_from.is_none());
            // Fill after skipping cached negatives; sparse survivors must still
            // reach the native parallel paths.
            if let Some((key, cache)) = attempts.as_ref() {
                cache.fill_available(key, &mut batch, &mut candidates, limit, cancellation)?;
            } else {
                batch.extend(candidates.by_ref().take(limit - batch.len()).cloned());
            }
            if batch.is_empty() {
                if !has_candidates && needs_password && input.volume_attempts.is_some()
                    && input.format_hint == "zip"
                {
                    let public = password::verify(preparation, input, &[], sessions, None)?;
                    *remaining = public.volume_attempts;
                    if remaining
                        .as_ref()
                        .is_some_and(|plan| plan.layouts.is_empty())
                    {
                        return Ok(Err(Failure::new(
                            FailureKind::MissingVolume,
                            "no supplied volume candidate satisfies the archive evidence",
                        )));
                    }
                }
                password_rejected |= has_candidates;
                break;
            }
            if deferred_from.is_some() {
                pending.append(&mut batch);
                continue;
            }
            if single_enc_can_defer && pending.is_empty() && batch.len() == 1 {
                // Real extraction can reuse this key for payload authentication.
                pending.append(&mut batch);
                break;
            }
            let next = (batch.len() > BATCH_SIZE).then(|| batch.pop().unwrap());
            #[cfg(test)]
            PLANNED_BATCHES.with(|capture| {
                if let Some(batches) = capture.borrow_mut().as_mut() {
                    batches.push(batch.clone());
                }
            });
            preparation.other_password_batches = !pending.is_empty() || next.is_some();
            let mut result = password::verify(preparation, input, &batch, sessions, None)?;
            if let Some(reduced) = result.volume_attempts.take() {
                let exhausted = reduced.layouts.is_empty();
                *remaining = Some(reduced);
                if exhausted {
                    return Ok(Err(Failure::new(
                        FailureKind::MissingVolume,
                        "no supplied volume candidate satisfies the archive evidence",
                    )));
                }
            }
            let offset = pending.len();
            let (tested, cache_rejections) = match result.status {
                "not_required" => {
                    if let Some((key, cache)) = attempts
                        .as_ref()
                        .filter(|_| input.volume_attempts.is_none())
                    {
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
                        // A different candidate list can satisfy another tail of the same plan.
                        if let Some((key, cache)) = attempts
                            .as_ref()
                            .filter(|_| input.volume_attempts.is_none())
                        {
                            cache.remember_proof(key.clone(), Some(password.clone()));
                        }
                        return Ok(Ok(PasswordPlan::verified(password)));
                    }
                    evidence = match (evidence, result.match_evidence) {
                        (None, next) => next,
                        (old, next) if old == next => old,
                        _ => Some("mixed"),
                    };
                    (result.attempts.min(batch.len()), true)
                }
                "no_match" => {
                    password_rejected |= result.attempts != 0;
                    let uncertain =
                        result.match_evidence == Some("password_or_volume_inconclusive");
                    uncertain_volumes |= uncertain;
                    (result.attempts.min(batch.len()), !uncertain)
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
                _ => {
                    // This is a preparation result, independent of the
                    // passwords in this batch. Forward the eligible suffix
                    // without retrying the same unavailable verifier.
                    deferred_from = Some(offset);
                    pending.append(&mut batch);
                    batch.extend(next);
                    continue;
                }
            };
            let cache = attempts.as_ref().filter(|_| cache_rejections);
            let scoped = std::mem::take(&mut result.scoped_rejections);
            if scoped.is_empty() && (tested == 0 || result.status == "no_match") {
                if tested != 0 {
                    if let Some((key, cache)) = cache {
                        cache.reject(key.clone(), &batch[..tested]);
                    }
                    batch.drain(..tested);
                }
                pending.append(&mut batch);
            } else {
                let mut rejected = Vec::new();
                let mut ordinals = (!scoped.is_empty()).then(|| [usize::MAX; BATCH_SIZE]);
                let viable = SurvivingCandidates::new(&result, batch.len());
                let mut survivors = viable.iter().peekable();
                for (index, value) in batch.drain(..).enumerate() {
                    if survivors.next_if_eq(&index).is_some() {
                        if let Some(ordinals) = &mut ordinals { ordinals[index] = pending.len() - offset; }
                        pending.push(value);
                    } else if cache.is_some() {
                        rejected.push(value);
                    }
                }
                if let Some((key, cache)) = cache.filter(|_| !rejected.is_empty()) {
                    cache.reject(key.clone(), &rejected);
                }
                if let Some(ordinals) = &ordinals {
                    domains.append_scoped(scoped, offset, ordinals);
                }
            }
            domains.append(result.password_domains, offset, pending.len() - offset);
            batch.extend(next);
        }
        if let Some(offset) = deferred_from {
            domains.append(Vec::new(), offset, pending.len() - offset);
        }
        if pending.is_empty() {
            if uncertain_volumes {
                let mut failure = Failure::new(
                    FailureKind::PasswordInconclusive,
                    "no password matched the supplied volume candidates",
                );
                failure.password_retry = true;
                failure.evidence = Some(Box::new(super::FailureEvidence {
                    classification_evidence: Some("password_or_volume_inconclusive".into()),
                    ..Default::default()
                }));
                return Ok(Err(failure));
            }
            if password_rejected && has_candidates {
                let mut failure = Failure::password();
                failure.evidence = Some(Box::new(super::FailureEvidence {
                    classification_evidence: Some("password_candidates_all_rejected".into()),
                    ..Default::default()
                }));
                return Ok(Err(failure));
            }
            if password_rejected || needs_password {
                return Ok(Err(Failure::password()));
            }
            pending.push(Arc::from(""));
        }
        if evidence.is_none() && pending.len() == 1 && pending[0].is_empty() {
            evidence = Some("empty_password_direct");
        }
        let mut layout_passwords = Default::default();
        if let Some(context) = preparation.evidence() {
            if let Some((reduced, groups)) = domains.finish(context, pending.len())? {
                let exhausted = reduced.layouts.is_empty();
                *remaining = Some(Arc::new(reduced));
                if exhausted {
                    return Ok(Err(Failure::new(
                        FailureKind::MissingVolume,
                        "no supplied volume candidate satisfies the archive evidence",
                    )));
                }
                layout_passwords = groups;
            }
        }
        let plan = PasswordPlan {
            layout_passwords,
            verified_password: None,
            candidates: Arc::new(pending),
            encrypted: needs_password.then_some(true),
            evidence,
        };
        Ok(Ok(plan))
    }
}

fn prioritize<'a, T: Copy>(
    recent: &VecDeque<Arc<str>>,
    configured: impl Iterator<Item = (T, &'a Arc<str>)>,
) -> Vec<(usize, T)> {
    let mut positions: HashMap<_, _> = recent.iter().enumerate()
        .map(|(index, password)| (password.as_ref(), index)).collect();
    let mut priority = vec![None; recent.len()];
    for (id, password) in configured {
        #[cfg(test)]
        PRIORITY_CANDIDATES.with(|count| count.set(count.get() + 1));
        if let Some(index) = positions.remove(password.as_ref()) {
            priority[index] = Some(id);
            if positions.is_empty() { break; }
        }
    }
    priority.into_iter().enumerate().filter_map(|(rank, value)| value.map(|value| (rank, value))).collect()
}

fn open_sessions(input: &ArchiveInput) -> io::Result<Vec<NativeArchiveSession>> {
    let head = input
        .parts
        .first()
        .map_or(&input.entry_path, |part| &part.extent.path);
    let session = NativeArchiveSession::new(head.clone())?;
    // A private head's attempt cache disappears at the end of planning.
    // Only a surviving owner can benefit from opening the other generations.
    if input.format_hint == "enc" || !session.shares_source() {
        return Ok(vec![session]);
    }
    Ok(member_sessions(input, session))
}

fn member_sessions(input: &ArchiveInput, head: NativeArchiveSession) -> Vec<NativeArchiveSession> {
    let mut sessions = Vec::new();
    let mut seen = HashSet::from([head.path()]);
    for path in input
        .physical_paths()
        .chain(std::iter::once(input.entry_path.as_str()))
    {
        if seen.insert(path) {
            if let Ok(session) = NativeArchiveSession::new(path.to_owned()) {
                sessions.push(session);
            }
        }
    }
    sessions.push(head);
    sessions
}

pub(super) struct PasswordPlan {
    pub layout_passwords: password::evidence::LayoutPasswords,
    pub verified_password: Option<Arc<str>>,
    pub candidates: Arc<Vec<Arc<str>>>,
    pub encrypted: Option<bool>,
    pub evidence: Option<&'static str>,
}

impl PasswordPlan {
    fn empty_fallback() -> Self {
        Self {
            layout_passwords: Default::default(),
            verified_password: None,
            candidates: Arc::new(vec![Arc::from("")]),
            encrypted: None,
            evidence: Some("empty_password_direct"),
        }
    }

    fn clear() -> Self {
        Self {
            layout_passwords: Default::default(),
            verified_password: None,
            candidates: Arc::default(),
            encrypted: Some(false),
            evidence: None,
        }
    }

    fn verified(password: Arc<str>) -> Self {
        Self {
            layout_passwords: Default::default(),
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
            None if self.candidates.len() <= 1 => self
                .verified_password
                .as_ref()
                .or_else(|| self.candidates.first())?,
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
}

#[cfg(test)]
thread_local! {
    static PLANNED_BATCHES: std::cell::RefCell<Option<Vec<Vec<Arc<str>>>>> = const { std::cell::RefCell::new(None) };
    static PRIORITY_CANDIDATES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[path = "../../tests/unit/pipeline/passwords/tests.rs"]
mod tests;
