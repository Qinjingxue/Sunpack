use super::PasswordVerification;
use crate::formats::seven_zip::{
    seven_zip_aes_properties, RelationNextHeader, SevenZipAesKey, SevenZipEvidenceReads,
    SevenZipPrefixCheck, SEVEN_Z_HEADER_SIZE, SEVEN_Z_MAGIC,
};
use crate::io::archive_state::{InputExtent, VolumeAttemptPlan};
use crate::io::cancellation::Cancellation;
use crate::io::read_fault::{read_exact_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{InputKey, PasswordContext, Preparation, PreparedStatus};
use crate::password::input::{parse_ranges, ranges_key, VirtualRangeReader};
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
        prepare_seven_zip(reader.stream_cursor(), reader.len()).map(PasswordContext::SevenZip)
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
        let reader = VirtualRangeReader::streaming(&parsed);
        let total_len = reader.len();
        prepare_seven_zip(reader, total_len).map(PasswordContext::SevenZip)
    })
}

include!("seven_zip_attempts.rs");

pub(crate) use crate::formats::seven_zip::SevenZipPasswordContext;

type SevenZipKeyCache<'a> =
    super::evidence::SharedCandidateKeys<(u8, &'a [u8]), Result<SevenZipAesKey, String>>;

impl SevenZipPasswordContext {
    fn properties(&self) -> &[u8] {
        match self {
            Self::Header(probe) => probe.key_properties(),
            Self::Prefix { probe, .. } => probe.key_properties(),
        }
    }

    pub(super) fn kdf_parameters(&self) -> Option<(u8, &[u8])> {
        seven_zip_aes_properties(self.properties()).map(|(cycles, salt, _)| (cycles, salt))
    }

    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        self.verify_cached(candidates, None)
    }

    pub(super) fn verify_cached(
        &self,
        candidates: &[Arc<str>],
        cache: Option<&SevenZipKeyCache>,
    ) -> std::io::Result<PasswordVerification> {
        let properties = self.properties();
        let prefix_evidence = match self {
            Self::Header(_) => None,
            Self::Prefix { header, .. } => Some(if *header {
                "7z_header_prefix"
            } else {
                "7z_payload_prefix"
            }),
        };
        let shared = cache.and_then(|cache| {
            let (cycles, salt, iv) = seven_zip_aes_properties(properties)?;
            Some((cache.cells(&(cycles, salt), candidates.len())?, iv))
        });
        collect_candidates(candidates, prefix_evidence, |index, password| {
            if prefix_evidence.is_none() && password.is_empty() {
                return Ok(SevenZipPrefixCheck::Reject);
            }
            let key = match shared {
                Some((cells, iv)) => cells[index]
                    .get_or_init(|| SevenZipAesKey::derive(properties, password))
                    .as_ref()
                    .map_err(Clone::clone)?
                    .with_iv(iv),
                None => SevenZipAesKey::derive(properties, password)?,
            };
            match self {
                Self::Header(probe) => probe.check_header(&key).map(|matched| {
                    if matched {
                        SevenZipPrefixCheck::Confirmed
                    } else {
                        SevenZipPrefixCheck::Reject
                    }
                }),
                Self::Prefix { probe, .. } => probe.test_with_key(&key),
            }
        })
    }
}

fn collect_candidates(
    candidates: &[Arc<str>],
    prefix_evidence: Option<&'static str>,
    check: impl Fn(usize, &str) -> Result<SevenZipPrefixCheck, String> + Sync,
) -> std::io::Result<PasswordVerification> {
    let cancellation = Cancellation::current();
    cancellation.check_io()?;
    let strong = prefix_evidence.is_none();
    let test = |(index, password): (usize, &Arc<str>)| {
        cancellation.run(|| match check(index, password) {
            Ok(SevenZipPrefixCheck::Reject) => None,
            outcome => Some((index, outcome)),
        })
    };
    let search = || {
        if strong {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(test)
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
            .find_map(test)
            .into_iter()
            .collect()
    } else {
        candidates.iter().enumerate().filter_map(test).collect()
    };
    cancellation.check_io()?;
    if let Some((index, _)) = matches
        .iter()
        .find(|(_, value)| matches!(value, Ok(SevenZipPrefixCheck::Confirmed)))
    {
        return Ok(PasswordVerification {
            matched_index: Some(*index),
            matched_indices: vec![*index],
            attempts: if strong { index + 1 } else { candidates.len() },
            final_confirmation_required: Some(false),
            match_evidence: Some("7z_encrypted_header"),
            ..PasswordVerification::status("match", "7z password confirmed by complete evidence")
        });
    }
    // An I/O/resource failure is not password evidence. Hand the entire batch
    // to the existing worker fallback rather than caching false rejections.
    if let Some(message) = matches.iter().find_map(|(_, value)| value.as_ref().err()) {
        return Ok(PasswordVerification::status(
            "unknown_needs_final_verifier",
            message,
        ));
    }
    let Some((first, _)) = matches.first() else {
        return Ok(PasswordVerification {
            attempts: candidates.len(),
            ..PasswordVerification::status("no_match", "7z prescreen rejected candidates")
        });
    };
    Ok(PasswordVerification {
        matched_index: Some(*first),
        matched_indices: matches.iter().map(|(index, _)| *index).collect(),
        attempts: if strong { first + 1 } else { candidates.len() },
        final_confirmation_required: Some(true),
        match_evidence: prefix_evidence,
        ..PasswordVerification::status(
            "match",
            "7z payload candidates require extraction confirmation",
        )
    })
}

fn prepare_seven_zip<R: Read + Seek>(
    mut reader: R,
    total_len: u64,
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
    let enabled = start_header[6] == 0
        && crc32fast::hash(&start_header[12..32])
            == u32::from_le_bytes(start_header[8..12].try_into().unwrap());
    prepare_seven_zip_descriptor(&mut reader, total_len, next, enabled, &()).map_err(|error| {
        match error {
            PreparedStatus::Status("invalid_volume_evidence", message) => {
                PreparedStatus::new("damaged", message)
            }
            other => other,
        }
    })
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
                ) =>
            {
                return Err(PreparedStatus::new("invalid_volume_evidence", message));
            }
            Err(message)
                if message.starts_with("resource_unavailable:")
                    || message == "7z payload has no supported prescreen evidence" =>
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
