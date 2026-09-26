use crate::formats::seven_zip::SevenZipPasswordProbe;
use crate::io::read_fault::{read_exact_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::password::context::{verify_prepared, InputKey, PasswordContext, PreparedStatus};
use crate::password::input::{parse_ranges, ranges_key, ranges_total_len, VirtualRangeReader};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;
use sevenz_rust2::{Archive, Error as SevenZipError, Password};
use std::io::{Read, Seek, SeekFrom};
use std::sync::OnceLock;

const SEVEN_Z_SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const SEVEN_Z_AES256_SHA256_METHOD: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
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

#[pyfunction]
pub(crate) fn seven_zip_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let reader = match py.detach(|| ManagedReader::open(&archive_path)) {
        Ok(reader) => reader,
        Err(_) => return status(py, "damaged", -1, 0, "7z archive could not be opened"),
    };
    seven_zip_fast_verify_passwords_with_reader(py, &reader, passwords)
}

pub(crate) fn seven_zip_fast_verify_passwords_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    verify_prepared(py, InputKey::file("7z", reader)?, &candidates, || {
        prepare_seven_zip(reader.cursor(), reader.len()).map(PasswordContext::SevenZip)
    })
}

#[pyfunction]
pub(crate) fn seven_zip_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;
    let total_len = ranges_total_len(&parsed);
    verify_prepared(py, ranges_key("7z", &parsed)?, &candidates, || {
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

    pub(crate) fn verify(&self, py: Python<'_>, candidates: &[String]) -> PyResult<Py<PyAny>> {
        if let Some((index, outcome)) =
            py.detach(|| find_first_conclusive_header_with_probe(candidates, &self.probe))
        {
            return conclusive_status(py, index, outcome);
        }
        status(
            py,
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
    let mut signature = [0u8; 6];
    read_exact_field(
        &mut reader,
        &mut signature,
        total_len,
        "7z.signature",
        FieldLocation::Head,
    )?;
    if signature != SEVEN_Z_SIGNATURE {
        return Err(PreparedStatus::new(
            "unsupported_method",
            "7z signature not found",
        ));
    }
    seven_zip_tail_requirement(&mut reader)?;
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
    if std::env::var_os("SUNPACK_DISABLE_7Z_PASSWORD_PROBE").is_some() {
        return Err(PreparedStatus::new(
            "unknown_needs_final_verifier",
            "7z password probe is disabled",
        ));
    }
    // An unsupported coder graph goes to the existing final verifier. Reopening
    // and reparsing the physical archive for each candidate defeats preparation.
    let probe = SevenZipPasswordProbe::from_seekable(&mut reader)
        .map_err(|message| PreparedStatus::new("unknown_needs_final_verifier", message))?;
    Ok(SevenZipPasswordContext { probe })
}

enum HeaderRead {
    Ok { payload_encrypted: bool },
    WrongPasswordOrPasswordRequired,
    Unsupported(String),
    Damaged(String),
}

fn seven_zip_tail_requirement<R: Read + Seek>(mut reader: R) -> Result<(), ReadFault> {
    let length = reader.seek(SeekFrom::End(0)).map_err(|error| {
        ReadFault::from_io(error, "seek_end", 0, 0, 0, 0)
            .with_field("7z.archive_length", FieldLocation::Body)
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        ReadFault::from_io(error, "seek", 0, 0, 0, length)
            .with_field("7z.start_header", FieldLocation::Head)
    })?;
    let mut header = [0u8; 32];
    read_exact_field(
        &mut reader,
        &mut header,
        length,
        "7z.start_header",
        FieldLocation::Head,
    )?;
    if &header[..6] != SEVEN_Z_SIGNATURE {
        return Ok(());
    }
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let required_length = 32u64
        .checked_add(next_offset)
        .and_then(|start| start.checked_add(next_size))
        .ok_or_else(|| {
            ReadFault::short_read("range", 32, usize::MAX, 0, length)
                .with_field("7z.next_header.offset_size", FieldLocation::Tail)
        })?;
    if required_length > length {
        let start = 32u64.saturating_add(next_offset);
        let requested = usize::try_from(next_size).unwrap_or(usize::MAX);
        let actual = length.saturating_sub(start).min(next_size) as usize;
        return Err(
            ReadFault::short_read("read_declared_range", start, requested, actual, length)
                .with_field("7z.next_header", FieldLocation::Tail),
        );
    }
    Ok(())
}

fn find_first_conclusive_header_with_probe(
    candidates: &[String],
    probe: &SevenZipPasswordProbe,
) -> Option<(usize, HeaderRead)> {
    let mut start = 0usize;
    while start < candidates.len() {
        let possible = if candidates.len() - start >= PARALLEL_PASSWORD_THRESHOLD {
            let search = || {
                candidates[start..]
                    .par_iter()
                    .enumerate()
                    .filter_map(|(relative, password)| {
                        probe
                            .decoded_header_if_password_matches(password)
                            .map(|decoded| (relative, decoded))
                    })
                    .find_first(|_| true)
            };
            match seven_zip_password_pool() {
                Some(pool) => pool.install(search),
                None => search(),
            }
        } else {
            candidates[start..]
                .iter()
                .enumerate()
                .find_map(|(relative, password)| {
                    probe
                        .decoded_header_if_password_matches(password)
                        .map(|decoded| (relative, decoded))
                })
        }?;
        let index = start + possible.0;
        let outcome = read_predecoded_header_with_original_parser(&possible.1);
        if !matches!(outcome, HeaderRead::WrongPasswordOrPasswordRequired) {
            return Some((index, outcome));
        }
        // A custom decoder false positive must never hide a later real password.
        start = index + 1;
    }
    None
}

fn read_predecoded_header_with_original_parser(decoded_header: &[u8]) -> HeaderRead {
    let Ok(next_header_size) = u64::try_from(decoded_header.len()) else {
        return HeaderRead::Unsupported("7z decoded header is too large".to_string());
    };
    let mut synthetic = Vec::with_capacity(32 + decoded_header.len());
    synthetic.extend_from_slice(SEVEN_Z_SIGNATURE);
    synthetic.extend_from_slice(&[0, 4]);
    synthetic.extend_from_slice(&[0; 4]);
    let mut start_header = [0u8; 20];
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..20].copy_from_slice(&crc32fast::hash(decoded_header).to_le_bytes());
    synthetic[8..12].copy_from_slice(&crc32fast::hash(&start_header).to_le_bytes());
    synthetic.extend_from_slice(&start_header);
    synthetic.extend_from_slice(decoded_header);
    read_archive_header_from_reader(std::io::Cursor::new(synthetic), "")
}

fn conclusive_status(py: Python<'_>, index: usize, outcome: HeaderRead) -> PyResult<Py<PyAny>> {
    match outcome {
        HeaderRead::Ok { .. } => status_with_details(
            py,
            "match",
            index as i32,
            (index + 1) as i32,
            "7z encrypted header opened",
            Some(false),
            Some("7z_encrypted_header"),
        ),
        HeaderRead::Unsupported(message) => status(
            py,
            "unknown_needs_final_verifier",
            -1,
            index as i32,
            &message,
        ),
        HeaderRead::Damaged(message) => status(py, "damaged", -1, index as i32, &message),
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
                    .any(|coder| coder.encoder_method_id() == SEVEN_Z_AES256_SHA256_METHOD)
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
    py: Python<'_>,
    status: &str,
    matched_index: i32,
    attempts: i32,
    message: &str,
) -> PyResult<Py<PyAny>> {
    status_with_details(py, status, matched_index, attempts, message, None, None)
}

fn status_with_details(
    py: Python<'_>,
    status: &str,
    matched_index: i32,
    attempts: i32,
    message: &str,
    final_confirmation_required: Option<bool>,
    match_evidence: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("matched_index", matched_index)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", message)?;
    if let Some(value) = final_confirmation_required {
        result.set_item("final_confirmation_required", value)?;
    }
    if let Some(value) = match_evidence {
        result.set_item("match_evidence", value)?;
    }
    Ok(result.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_parser_confirms_predecoded_header() {
        assert!(matches!(
            read_predecoded_header_with_original_parser(&[0x01, 0x00]),
            HeaderRead::Ok { .. }
        ));
        assert!(!matches!(
            read_predecoded_header_with_original_parser(&[0x01, 0xff]),
            HeaderRead::Ok { .. }
        ));
    }

    #[test]
    fn declared_next_header_beyond_input_requires_a_volume_or_has_damaged_offsets() {
        let mut bytes = vec![0u8; 64];
        bytes[..6].copy_from_slice(SEVEN_Z_SIGNATURE);
        bytes[12..20].copy_from_slice(&64u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&16u64.to_le_bytes());
        assert_eq!(
            seven_zip_tail_requirement(std::io::Cursor::new(bytes))
                .unwrap_err()
                .field,
            "7z.next_header"
        );
    }
}
