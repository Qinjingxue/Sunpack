use super::PasswordVerification;
use crate::formats::seven_zip::{
    seven_zip_encryption_facts_from_next_header, RelationNextHeader, SevenZipPasswordProbe,
    SEVEN_Z_HEADER_SIZE, SEVEN_Z_MAGIC,
};
use crate::io::archive_state::InputExtent;
use crate::io::cancellation::Cancellation;
use crate::io::read_fault::{read_exact_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{verify_prepared, InputKey, PasswordContext, PreparedStatus};
use crate::password::input::{parse_ranges, ranges_key, ranges_total_len, VirtualRangeReader};
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
    reader: &ManagedReader,
    candidates: &[Arc<str>],
) -> std::io::Result<PasswordVerification> {
    verify_prepared(InputKey::file("7z", reader)?, candidates, || {
        prepare_seven_zip(reader.cursor(), reader.len()).map(PasswordContext::SevenZip)
    })
}

pub(crate) fn seven_zip_fast_verify_passwords_from_ranges(
    ranges: &[&InputExtent],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let parsed = parse_ranges(ranges, sessions)?;
    let total_len = ranges_total_len(&parsed);
    verify_prepared(ranges_key("7z", &parsed)?, candidates, || {
        prepare_seven_zip(VirtualRangeReader::new(parsed.into()), total_len)
            .map(PasswordContext::SevenZip)
    })
}

pub(crate) struct SevenZipPasswordContext {
    probe: SevenZipPasswordProbe,
}

impl SevenZipPasswordContext {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.probe.retained_bytes()
    }

    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        if let Some((index, outcome)) =
            find_first_conclusive_header_with_probe(candidates, &self.probe)
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
            Ok(probe) => return Ok(SevenZipPasswordContext { probe }),
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
) -> Option<(usize, HeaderRead)> {
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
        match possible.1 {
            Ok(decoded) => read_predecoded_header(&decoded),
            Err(error) => HeaderRead::Unsupported(error),
        },
    ))
}

fn read_predecoded_header(decoded_header: &[u8]) -> HeaderRead {
    // The decoder already proved the header CRC. Reuse the analysis parser:
    // FilesInfo properties are skipped in place, without per-file objects or
    // another whole-header copy. Unhandled trees retain extraction fallback.
    let facts = seven_zip_encryption_facts_from_next_header(decoded_header);
    if facts.scan_complete {
        HeaderRead::Ok {
            payload_encrypted: facts.encrypted_payload,
        }
    } else {
        HeaderRead::Unsupported("7z decoded header requires extraction confirmation".into())
    }
}

fn conclusive_status(index: usize, outcome: HeaderRead) -> std::io::Result<PasswordVerification> {
    match outcome {
        HeaderRead::Ok { .. } => status_with_details(
            "match",
            index as i32,
            (index + 1) as i32,
            "7z encrypted header opened",
            Some(false),
            Some("7z_encrypted_header"),
        ),
        HeaderRead::Unsupported(message) => {
            status("unknown_needs_final_verifier", -1, index as i32, &message)
        }
        HeaderRead::Damaged(message) => status("damaged", -1, index as i32, &message),
        HeaderRead::WrongPasswordOrPasswordRequired => unreachable!("filtered outcome"),
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
mod tests {
    use super::*;

    #[test]
    fn analysis_parser_confirms_predecoded_header() {
        assert!(matches!(
            read_predecoded_header(&[0x01, 0x00]),
            HeaderRead::Ok { .. }
        ));
        assert!(!matches!(
            read_predecoded_header(&[0x01, 0xff]),
            HeaderRead::Ok { .. }
        ));
    }

    #[test]
    fn declared_next_header_beyond_input_requires_a_volume_or_has_damaged_offsets() {
        let mut bytes = [0u8; SEVEN_Z_HEADER_SIZE];
        bytes[..6].copy_from_slice(SEVEN_Z_MAGIC);
        bytes[12..20].copy_from_slice(&64u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&16u64.to_le_bytes());
        assert_eq!(
            seven_zip_tail_requirement(&bytes, 64).unwrap_err().field,
            "7z.next_header"
        );
    }
}
