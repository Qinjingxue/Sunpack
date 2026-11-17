use super::PasswordVerification;
use crate::formats::seven_zip::{
    predecoded_seven_zip_header_is_supported, RelationNextHeader, SevenZipPasswordProbe,
    SevenZipPayloadProbe, SevenZipPrefixCheck,
    SEVEN_Z_HEADER_SIZE, SEVEN_Z_MAGIC,
};
use crate::io::archive_state::InputExtent;
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

pub(crate) enum SevenZipPasswordContext {
    Header(SevenZipPasswordProbe),
    Payload(SevenZipPayloadProbe),
}

impl SevenZipPasswordContext {
    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        let Self::Header(probe) = self else {
            let Self::Payload(probe) = self else { unreachable!() };
            return verify_payload_candidates(candidates, probe);
        };
        if let Some((index, outcome)) =
            find_first_conclusive_header_with_probe(candidates, probe)
        {
            return conclusive_status(index, outcome);
        }
        status(
            "no_match",
            -1,
            candidates.len() as i32,
            "7z encrypted header did not open",
        )
    }
}

fn verify_payload_candidates(
    candidates: &[Arc<str>],
    probe: &SevenZipPayloadProbe,
) -> std::io::Result<PasswordVerification> {
    collect_payload_candidates(candidates, probe.is_strong(), |password| probe.test(password))
}

fn collect_payload_candidates(
    candidates: &[Arc<str>],
    strong: bool,
    check: impl Fn(&str) -> Result<SevenZipPrefixCheck, String> + Sync,
) -> std::io::Result<PasswordVerification> {
    let cancellation = Cancellation::current();
    cancellation.check_io()?;
    let test = |(index, password): (usize, &Arc<str>)| {
        cancellation.run(|| match check(password) {
            Ok(SevenZipPrefixCheck::Reject) => None,
            outcome => Some((index, outcome)),
        })
    };
    let search = || {
        if strong {
            candidates.par_iter().enumerate().filter_map(test).find_first(|_| true)
                .into_iter().collect::<Vec<_>>()
        } else {
            candidates.par_iter().enumerate().filter_map(test).collect::<Vec<_>>()
        }
    };
    let matches = if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        match seven_zip_password_pool() {
            Some(pool) => pool.install(search),
            None => search(),
        }
    } else if strong {
        candidates.iter().enumerate().find_map(test).into_iter().collect()
    } else {
        candidates.iter().enumerate().filter_map(test).collect()
    };
    cancellation.check_io()?;
    // An I/O/resource failure is not password evidence. Hand the entire batch
    // to the existing worker fallback rather than caching false rejections.
    if let Some(message) = matches.iter().find_map(|(_, value)| value.as_ref().err()) {
        return status("unknown_needs_final_verifier", -1, 0, message);
    }
    let Some((first, _)) = matches.first() else {
        return status("no_match", -1, candidates.len() as i32, "7z payload prescreen rejected candidates");
    };
    Ok(PasswordVerification {
        matched_index: Some(*first),
        matched_indices: matches.iter().map(|(index, _)| *index).collect(),
        attempts: if strong { first + 1 } else { candidates.len() },
        final_confirmation_required: Some(true),
        defer_remaining: strong,
        match_evidence: Some(if strong { "7z_payload_strong_prescreen" } else { "7z_payload_prefix" }),
        ..PasswordVerification::status("match", "7z payload candidates require extraction confirmation")
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
    // Reuse the start header for the existing bounded descriptor. Encrypted headers
    // need no preliminary Archive::read (which reparses the same coder graph).
    // Keep the original parser only for plaintext and unsupported graphs.
    let probe_error = if std::env::var_os("SUNPACK_DISABLE_7Z_PASSWORD_PROBE").is_some() {
        "7z password probe is disabled".into()
    } else if start_header[6] == 0 {
        match SevenZipPasswordProbe::from_header(&mut reader, total_len, &start_header, next) {
            Ok(probe) => return Ok(SevenZipPasswordContext::Header(probe)),
            Err(message) => message,
        }
    } else {
        "7z password probe signature or version is unsupported".into()
    };
    if probe_error.starts_with("resource_unavailable:") {
        return Err(PreparedStatus::new(
            "unknown_needs_final_verifier",
            probe_error,
        ));
    }
    if std::env::var_os("SUNPACK_DISABLE_7Z_PASSWORD_PROBE").is_none() && start_header[6] == 0 {
        match SevenZipPayloadProbe::from_header(&mut reader, total_len, &start_header, next) {
            Ok(probe) => return Ok(SevenZipPasswordContext::Payload(probe)),
            Err(message) if message.starts_with("resource_unavailable:") => {
                return Err(PreparedStatus::new("unknown_needs_final_verifier", message));
            }
            Err(_) => {}
        }
    }
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        ReadFault::from_io(error, "seek", 0, 0, 0, total_len)
            .with_field("7z.start_header", FieldLocation::Head)
    })?;
    match read_archive_header_from_reader(&mut reader, "") {
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

fn find_first_conclusive_header_with_probe(
    candidates: &[Arc<str>],
    probe: &SevenZipPasswordProbe,
) -> Option<(usize, Result<(), String>)> {
    let cancellation = Cancellation::current();
    if cancellation.cancelled() {
        return None;
    }
    let test = |(index, password): (usize, &Arc<str>)| {
        cancellation.run(
            || match probe.decoded_header_if_password_matches(password) {
                Ok(Some(decoded)) => Some((index, Ok(decoded))),
                Ok(None) => None,
                Err(error) => Some((index, Err(error))),
            },
        )
    };
    let possible = if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        let search = || {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(test)
                .find_first(|_| true)
        };
        match seven_zip_password_pool() {
            Some(pool) => pool.install(search),
            None => search(),
        }
    } else {
        candidates.iter().enumerate().find_map(test)
    }?;
    Some((
        possible.0,
        possible.1.and_then(|decoded| {
            predecoded_seven_zip_header_is_supported(&decoded)
                .then_some(())
                .ok_or_else(|| "7z decoded header requires extraction confirmation".into())
        }),
    ))
}

fn conclusive_status(index: usize, outcome: Result<(), String>) -> std::io::Result<PasswordVerification> {
    match outcome {
        Ok(()) => status_with_details(
            "match",
            index as i32,
            (index + 1) as i32,
            "7z encrypted header opened",
            Some(false),
            Some("7z_encrypted_header"),
        ),
        Err(message) => {
            status("unknown_needs_final_verifier", -1, index as i32, &message)
        }
    }
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

fn status(
    status: &'static str,
    matched_index: i32,
    attempts: i32,
    message: &str,
) -> std::io::Result<PasswordVerification> {
    status_with_details(status, matched_index, attempts, message, None, None)
}

fn status_with_details(
    status: &'static str,
    matched_index: i32,
    attempts: i32,
    message: &str,
    final_confirmation_required: Option<bool>,
    match_evidence: Option<&'static str>,
) -> std::io::Result<PasswordVerification> {
    Ok(PasswordVerification {
        matched_index: usize::try_from(matched_index).ok(),
        attempts: attempts as usize,
        final_confirmation_required,
        match_evidence,
        ..PasswordVerification::status(status, message)
    })
}

#[cfg(test)]
#[path = "../../tests/unit/password/seven_zip/tests.rs"]
mod tests;
