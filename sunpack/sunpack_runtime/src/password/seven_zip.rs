use super::PasswordVerification;
use crate::formats::seven_zip::{
    seven_zip_aes_properties, RelationNextHeader, SevenZipAesKey, SevenZipEvidenceReads,
    SevenZipPayloadSource, SevenZipPrefixCheck, SEVEN_Z_HEADER_SIZE, SEVEN_Z_MAGIC,
};
use crate::io::archive_state::{InputExtent, VolumeAttemptPlan};
use crate::io::cancellation::Cancellation;
use crate::io::read_fault::{read_exact_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{InputKey, PasswordContext, Preparation, PreparedStatus};
use crate::password::input::{parse_ranges, ranges_key, RangeSpec, VirtualRangeReader};
use rayon::prelude::*;
use sevenz_rust2::{Archive, EncoderMethod, Error as SevenZipError, Password};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::sync::OnceLock;

const PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const MAX_PASSWORD_WORKERS: usize = 64;

fn seven_zip_password_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let available = std::thread::available_parallelism().ok()?.get();
        let workers = std::env::var("SUNPACK_7Z_PASSWORD_WORKERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_else(|| available.saturating_add(available / 4))
            .clamp(1, MAX_PASSWORD_WORKERS);
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .thread_name(|index| format!("sunpack-7z-password-{index}"))
            .build()
            .ok()
    })
    .as_ref()
}

pub(crate) fn seven_zip_fast_verify_passwords_with_reader(
    preparation: &mut Preparation,
    reader: &ManagedReader,
    candidates: &[Arc<str>],
) -> std::io::Result<PasswordVerification> {
    preparation.verify(InputKey::file("7z", reader)?, candidates, || {
        let evidence = FixedSevenZipEvidence(Arc::new([RangeSpec::entire(reader)]));
        prepare_seven_zip(reader.stream_cursor(), reader.len(), &evidence)
            .map(PasswordContext::SevenZip)
    })
}

pub(crate) fn seven_zip_fast_verify_passwords_from_ranges(
    preparation: &mut Preparation,
    ranges: &[&InputExtent],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let parsed = parse_ranges(ranges.iter().copied(), sessions)?;
    preparation.verify(ranges_key("7z", &parsed)?, candidates, || {
        let evidence = FixedSevenZipEvidence(parsed.into());
        let reader = VirtualRangeReader::streaming(&evidence.0);
        let total_len = reader.len();
        prepare_seven_zip(reader, total_len, &evidence).map(PasswordContext::SevenZip)
    })
}

struct FixedSevenZipEvidence(Arc<[RangeSpec]>);

impl<R> SevenZipEvidenceReads<R> for FixedSevenZipEvidence {
    fn payload_source(&self, _: &R) -> Option<SevenZipPayloadSource> {
        Some(SevenZipPayloadSource::Fixed(Arc::clone(&self.0)))
    }
    fn has_deferred_source(&self) -> bool {
        true
    }
}

include!("seven_zip_attempts.rs");

pub(crate) use crate::formats::seven_zip::SevenZipPasswordContext;

type SevenZipKeyCache<'a> =
    super::evidence::SharedCandidateKeys<(u8, &'a [u8]), Result<SevenZipAesKey, String>>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SevenZipVolumeScope {
    Unique,
    SharedProjection,
    SeparateProjections,
}

impl SevenZipPasswordContext {
    pub(super) fn kdf_parameters(&self) -> impl Iterator<Item = (u8, &[u8])> + '_ {
        let (header, payload) = match self {
            Self::Header(probe) => (Some(probe), None),
            Self::Prefix { probe, .. } => (None, Some(probe)),
            Self::MemberOnly => (None, None),
        };
        header
            .into_iter()
            .flat_map(|probe| probe.key_properties())
            .chain(payload.into_iter().flat_map(|probe| probe.key_properties()))
            .filter_map(|properties| seven_zip_aes_properties(properties))
            .map(|(cycles, salt, _)| (cycles, salt))
    }

    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        self.verify_cached(candidates, None, SevenZipVolumeScope::Unique)
    }

    pub(super) fn verify_cached<'a>(
        &'a self,
        candidates: &[Arc<str>],
        cache: Option<&SevenZipKeyCache<'a>>,
        volume_scope: SevenZipVolumeScope,
    ) -> std::io::Result<PasswordVerification> {
        if matches!(self, Self::MemberOnly) {
            return Ok(PasswordVerification::status(
                "unknown_needs_final_verifier", "7z payload requires member verification",
            ));
        }
        let local: SevenZipKeyCache<'a>;
        let cache = match cache {
            Some(cache) => cache,
            None => {
                local = SevenZipKeyCache::from_parameters(self.kdf_parameters());
                &local
            }
        };
        let key = |index: usize, password: &str, properties: &'a [u8]| {
            let (cycles, salt, iv) = seven_zip_aes_properties(properties).unwrap();
            match cache.cells(&(cycles, salt), candidates.len()) {
                Some(cells) => cells[index]
                    .get_or_init(|| SevenZipAesKey::derive(properties, password))
                    .as_ref()
                    .map(|key| key.with_iv(iv))
                    .map_err(Clone::clone),
                None => SevenZipAesKey::derive(properties, password),
            }
        };
        let Self::Prefix { probe, header } = self else {
            let Self::Header(probe) = self else { unreachable!() };
            let ambiguous = probe.has_ambiguous_material();
            let evidence = (ambiguous || !probe.has_crc()).then_some("7z_header_structure");
            let matches = collect_candidates(candidates, evidence.is_none(), |index, password| {
                if password.is_empty() {
                    return Ok((SevenZipPrefixCheck::Reject, (None, Vec::new())));
                }
                let mut rejected = Vec::new();
                let check = probe.verify_header(
                    |properties| key(index, password, properties),
                    |projection| rejected.push((projection, index)),
                );
                let verdict = check.as_ref().copied().unwrap_or(SevenZipPrefixCheck::Weak);
                Ok((verdict, (check.err(), rejected)))
            })?;
            let mut result = candidate_result(&matches, candidates.len(), evidence, !ambiguous || matches.len() == 1);
            let mut message = None;
            for (_, checked) in matches {
                if let Ok((_, (fault, rejected))) = checked {
                    result.scoped_rejections.extend(rejected);
                    if let Some(fault) = fault { message.get_or_insert(fault); }
                }
            }
            if let Some(message) = message { result.message = message; }
            return Ok(result);
        };
        let evidence = Some(if *header { "7z_header_prefix" } else { "7z_payload_prefix" });
        let properties = probe.key_properties().next().unwrap();
        if !probe.has_followup() {
            let matches = collect_candidates(candidates, false, |index, password| {
                let prefix = probe.prescreen(&key(index, password, properties)?,
                    |inner| key(index, password, inner))?;
                Ok((prefix.check, ()))
            })?;
            return Ok(candidate_result(&matches, candidates.len(), evidence, true));
        }
        let matches = collect_candidates(candidates, false, |index, password| {
            let first_key = key(index, password, properties)?;
            let prefix = probe.prescreen(&first_key, |inner| key(index, password, inner))?;
            Ok((prefix.check, (first_key, prefix)))
        })?;
        let mut result = candidate_result(&matches, candidates.len(), evidence, true);
        let narrow_volumes_only = result.matched_indices.len() == 1;
        let stop_at_one = volume_scope == SevenZipVolumeScope::Unique;
        if narrow_volumes_only && stop_at_one {
            return Ok(result);
        }
        let followups = matches.iter().filter(|(_, check)| check.is_ok())
            .take(PARALLEL_PASSWORD_THRESHOLD).count();
        if followups == 0 {
            return Ok(result);
        }
        let cancellation = Cancellation::current();
        let mut outcomes = Vec::new();
        let mut remaining = matches.into_iter();
        let mut viable = result.matched_indices.len();
        if stop_at_one && probe.can_stage_followup() {
            let mut pending = Vec::with_capacity(2);
            while let Some((index, check)) = remaining.next() {
                if let Ok((_, (first_key, prefix))) = check {
                    let staged = cancellation.run(|| probe.prepare_followup(|properties| {
                        key(index, &candidates[index], properties)
                    }));
                    match staged {
                        Ok(Some(prepared)) => {
                            pending.push((index, first_key, prefix, prepared));
                        }
                        Ok(None) => {
                            viable -= 1;
                            outcomes.push((index, Ok(SevenZipPrefixCheck::Reject), Vec::new()));
                        }
                        Err(error) => outcomes.push((index, Err(error), Vec::new())),
                    }
                }
                // Buffer at most two states. As soon as another candidate
                // remains viable, the successor checks can narrow the result.
                if viable - remaining.len() >= 2 && !pending.is_empty() {
                    break;
                }
            }
            for (index, first_key, prefix, prepared) in pending {
                let proof = if viable == 1 {
                    prepared.prefix_result(prefix.check)
                } else {
                    cancellation.run(|| probe.verify_prepared_followup(&first_key, prefix, prepared))
                };
                if proof == Ok(SevenZipPrefixCheck::Reject) {
                    viable -= 1;
                }
                let at = outcomes.partition_point(|(checked, _, _)| *checked < index);
                outcomes.insert(at, (index, proof, Vec::new()));
            }
        }
        let test = |(index, check): CheckedCandidate<_>| {
            let (_, (first_key, prefix)) = check.ok()?;
            Some(cancellation.run(|| {
                let mut rejected = Vec::new();
                let proof = probe.verify_followup(&first_key, prefix, narrow_volumes_only,
                    volume_scope == SevenZipVolumeScope::SharedProjection, |properties| {
                    key(index, &candidates[index], properties)
                }, |projection| rejected.push((projection, index)));
                (index, proof, rejected)
            }))
        };
        // Both collections follow input order. The candidate item carries its
        // own follow-up data across the two phases.
        if followups >= PARALLEL_PASSWORD_THRESHOLD && remaining.len() >= PARALLEL_PASSWORD_THRESHOLD {
            let mut remaining: Vec<_> = remaining.collect();
            // Keep the last candidate outside the wave when extraction can
            // confirm it against the only remaining layout.
            let last = if stop_at_one { remaining.pop() } else { None };
            let first = outcomes.len();
            outcomes.par_extend(remaining.into_par_iter().filter_map(test));
            if let Some(last) = last {
                let rejected = outcomes[first..].iter()
                    .filter(|(_, proof, _)| *proof == Ok(SevenZipPrefixCheck::Reject)).count();
                if viable - rejected > 1 {
                    outcomes.extend(test(last));
                }
            }
        } else if stop_at_one {
            for candidate in remaining {
                if viable == 1 {
                    break;
                }
                if let Some(outcome) = test(candidate) {
                    viable -= usize::from(outcome.1 == Ok(SevenZipPrefixCheck::Reject));
                    outcomes.push(outcome);
                }
            }
        } else {
            outcomes.extend(remaining.filter_map(test));
        }
        cancellation.check_io()?;
        let mut outcomes = outcomes.into_iter().peekable();
        let mut message = None;
        result.matched_indices.retain(|&index| {
            if outcomes.peek().is_none_or(|(tested, _, _)| *tested != index) {
                return true;
            }
            let (_, outcome, scoped) = outcomes.next().unwrap();
            result.scoped_rejections.extend(scoped);
            match outcome {
                Ok(SevenZipPrefixCheck::Reject) => false,
                Err(error) => {
                    message.get_or_insert(error);
                    true
                }
                _ => true,
            }
        });
        result.matched_index = result.matched_indices.first().copied();
        if result.matched_index.is_none() {
            return Ok(PasswordVerification {
                attempts: candidates.len(),
                ..PasswordVerification::status("no_match", "7z follow-up rejected candidates")
            });
        }
        if let Some(message) = message {
            result.message = message;
        }
        Ok(result)
    }
}

type CheckedCandidate<T> = (usize, Result<(SevenZipPrefixCheck, T), String>);

fn collect_candidates<T: Send>(
    candidates: &[Arc<str>],
    strong: bool,
    check: impl Fn(usize, &str) -> Result<(SevenZipPrefixCheck, T), String> + Sync,
) -> std::io::Result<Vec<CheckedCandidate<T>>> {
    let cancellation = Cancellation::current();
    cancellation.check_io()?;
    let test = |(index, password): (usize, &Arc<str>)| {
        cancellation.run(|| match check(index, password) {
            Ok((SevenZipPrefixCheck::Reject, _)) => None,
            outcome => Some((index, outcome)),
        })
    };
    let unresolved = std::sync::Mutex::new(Vec::new());
    let confirm = |candidate| {
        let matched = test(candidate)?;
        if matches!(matched.1, Ok((SevenZipPrefixCheck::Confirmed, _))) {
            Some(matched)
        } else {
            unresolved.lock().unwrap().push(matched);
            None
        }
    };
    let search = || {
        if strong {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(confirm)
                .find_first(|_| true)
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(test)
                .collect::<Vec<_>>()
        }
    };
    let matches = if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        match seven_zip_password_pool() {
            Some(pool) => pool.install(search),
            None => search(),
        }
    } else if strong {
        candidates
            .iter()
            .enumerate()
            .find_map(confirm)
            .into_iter()
            .collect()
    } else {
        candidates.iter().enumerate().filter_map(test).collect()
    };
    cancellation.check_io()?;
    if strong && matches.is_empty() {
        let mut unresolved = unresolved.into_inner().unwrap();
        unresolved.sort_unstable_by_key(|(index, _)| *index);
        return Ok(unresolved);
    }
    Ok(matches)
}

fn candidate_result<T>(
    matches: &[CheckedCandidate<T>], count: usize, prefix_evidence: Option<&'static str>,
    allow_confirmation: bool,
) -> PasswordVerification {
    let strong = prefix_evidence.is_none();
    if let Some((index, _)) = matches
        .iter()
        .find(|(_, value)| allow_confirmation && matches!(value, Ok((SevenZipPrefixCheck::Confirmed, _))))
    {
        return PasswordVerification {
            matched_index: Some(*index),
            matched_indices: vec![*index],
            attempts: if strong { index + 1 } else { count },
            final_confirmation_required: Some(false),
            match_evidence: Some("7z_encrypted_header"),
            ..PasswordVerification::status("match", "7z password confirmed by complete evidence")
        };
    }
    let Some((first, _)) = matches.first() else {
        return PasswordVerification {
            attempts: count,
            ..PasswordVerification::status("no_match", "7z prescreen rejected candidates")
        };
    };
    // Unavailable candidates survive without terminating the search for a
    // CRC-confirmed candidate.
    let uncertainty = matches.iter().find_map(|(_, value)| value.as_ref().err());
    PasswordVerification {
        matched_index: Some(*first),
        matched_indices: matches.iter().map(|(index, _)| *index).collect(),
        attempts: count,
        final_confirmation_required: Some(true),
        match_evidence: prefix_evidence,
        ..PasswordVerification::status("match", uncertainty.map_or(
            "7z payload candidates require extraction confirmation", String::as_str,
        ))
    }
}

fn prepare_seven_zip<R: Read + Seek>(
    mut reader: R,
    total_len: u64,
    evidence: &impl SevenZipEvidenceReads<R>,
) -> Result<SevenZipPasswordContext, PreparedStatus> {
    let mut signature = [0u8; SEVEN_Z_MAGIC.len()];
    read_exact_field(
        &mut reader,
        &mut signature,
        total_len,
        "7z.signature",
        FieldLocation::Head,
    )?;
    if signature != SEVEN_Z_MAGIC {
        return Err(PreparedStatus::new(
            "unsupported_method",
            "7z signature not found",
        ));
    }
    let mut start_header = [0u8; SEVEN_Z_HEADER_SIZE];
    start_header[..SEVEN_Z_MAGIC.len()].copy_from_slice(&signature);
    read_exact_field(
        &mut reader,
        &mut start_header[SEVEN_Z_MAGIC.len()..],
        total_len,
        "7z.start_header",
        FieldLocation::Head,
    )?;
    let next = seven_zip_tail_requirement(&start_header, total_len)?;
    let enabled = start_header[6] == 0 && seven_zip_start_header_crc_matches(&start_header);
    prepare_seven_zip_descriptor(&mut reader, total_len, next, enabled, evidence)
        .map_err(seven_zip_fixed_input_status)
}

fn seven_zip_start_header_crc_matches(start: &[u8; SEVEN_Z_HEADER_SIZE]) -> bool {
    crc32fast::hash(&start[12..32]) == u32::from_le_bytes(start[8..12].try_into().unwrap())
}

fn seven_zip_fixed_input_status(error: PreparedStatus) -> PreparedStatus {
    match error {
        PreparedStatus::Status("invalid_volume_evidence", message) => {
            PreparedStatus::new("damaged", message)
        }
        other => other,
    }
}

fn prepare_seven_zip_descriptor<R: Read + Seek>(
    reader: &mut R,
    total_len: u64,
    next: RelationNextHeader,
    supported: bool,
    evidence: &impl SevenZipEvidenceReads<R>,
) -> Result<SevenZipPasswordContext, PreparedStatus> {
    let probe_error = if supported {
        let enabled = std::env::var_os("SUNPACK_DISABLE_7Z_PASSWORD_PROBE").is_none();
        match SevenZipPasswordContext::from_next_header(reader, total_len, next, enabled, evidence)
        {
            Ok(Some(context)) => return Ok(context),
            Ok(None) => {
                return Err(PreparedStatus::new(
                    "not_required",
                    "7z header is readable without password",
                ))
            }
            Err(message)
                if matches!(
                    message.as_ref(),
                    "7z next header crc mismatch" | "7z packed stream crc mismatch"
                        | "7z external folder metadata crc mismatch"
                ) =>
            {
                return Err(PreparedStatus::new("invalid_volume_evidence", message));
            }
            Err(message) if message.starts_with("resource_unavailable:") =>
            {
                return Err(PreparedStatus::new("unknown_needs_final_verifier", message));
            }
            Err(message) => message,
        }
    } else {
        "7z password probe start header is unsupported".into()
    };
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        ReadFault::from_io(error, "seek", 0, 0, 0, total_len)
            .with_field("7z.start_header", FieldLocation::Head)
    })?;
    match read_archive_header_from_reader(reader, "") {
        HeaderRead::Ok {
            payload_encrypted: false,
        } => {
            return Err(PreparedStatus::new(
                "not_required",
                "7z header is readable without password",
            ))
        }
        HeaderRead::Ok {
            payload_encrypted: true,
        } => {
            return Err(PreparedStatus::new(
                "unknown_needs_final_verifier",
                "7z header is readable but payload uses AES encryption",
            ))
        }
        HeaderRead::WrongPasswordOrPasswordRequired => {}
        HeaderRead::Unsupported(message) => {
            return Err(PreparedStatus::new("unknown_needs_final_verifier", message))
        }
        HeaderRead::Damaged(message) => return Err(PreparedStatus::new("damaged", message)),
    }
    Err(PreparedStatus::new(
        "unknown_needs_final_verifier",
        probe_error,
    ))
}

enum HeaderRead {
    Ok { payload_encrypted: bool },
    WrongPasswordOrPasswordRequired,
    Unsupported(String),
    Damaged(String),
}

fn seven_zip_tail_requirement(
    header: &[u8; SEVEN_Z_HEADER_SIZE],
    length: u64,
) -> Result<RelationNextHeader, ReadFault> {
    let next = RelationNextHeader::checked_fields(header).ok_or_else(|| {
        ReadFault::short_read("range", SEVEN_Z_HEADER_SIZE as u64, usize::MAX, 0, length)
            .with_field("7z.next_header.offset_size", FieldLocation::Tail)
    })?;
    if next.end() > length {
        let requested = usize::try_from(next.size).unwrap_or(usize::MAX);
        let actual = length.saturating_sub(next.offset).min(next.size) as usize;
        return Err(ReadFault::short_read(
            "read_declared_range",
            next.offset,
            requested,
            actual,
            length,
        )
        .with_field("7z.next_header", FieldLocation::Tail));
    }
    Ok(next)
}

fn read_archive_header_from_reader<R: Read + Seek>(mut reader: R, password: &str) -> HeaderRead {
    match Archive::read(&mut reader, &Password::from(password)) {
        Ok(archive) => HeaderRead::Ok {
            payload_encrypted: archive.blocks.iter().any(|block| {
                block
                    .coders
                    .iter()
                    .any(|coder| coder.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
            }),
        },
        Err(SevenZipError::PasswordRequired) | Err(SevenZipError::MaybeBadPassword(_)) => {
            HeaderRead::WrongPasswordOrPasswordRequired
        }
        Err(SevenZipError::BadSignature(_))
        | Err(SevenZipError::UnsupportedVersion { .. })
        | Err(SevenZipError::NextHeaderCrcMismatch) => {
            HeaderRead::Damaged("7z header is damaged".to_string())
        }
        Err(SevenZipError::Unsupported(message)) => HeaderRead::Unsupported(message.to_string()),
        Err(SevenZipError::UnsupportedCompressionMethod(message)) => {
            HeaderRead::Unsupported(message)
        }
        Err(SevenZipError::ExternalUnsupported) => {
            HeaderRead::Unsupported("7z external compression method is unsupported".to_string())
        }
        Err(error) => HeaderRead::Unsupported(format!(
            "7z header-only verifier could not classify error: {error}"
        )),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/password/seven_zip/tests.rs"]
mod tests;
