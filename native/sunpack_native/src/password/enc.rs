//! ENC's quick block is a strong, bounded password proof. Authentication belongs
//! to extraction. Reuse the existing generation-aware prepared-context cache.
use super::context::{verify_prepared, InputKey, PasswordContext, PreparedStatus};
use super::input::{parse_ranges, ranges_key, ranges_total_len, VirtualRangeReader};
use crate::io::read_fault::{read_exact_field, FieldLocation};
use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;
use std::io::{Read, Seek};
use std::sync::atomic::{AtomicUsize, Ordering};
use sunpack_enc::{Error, PasswordProbe, Workspace};

// Argon2 is memory-hard: bound aggregate scratch space for one batch, rather
// than allocating one workspace per password or retaining it in the cache.
const PARALLEL_WORKSPACE_BYTES: usize = 64 * 1024 * 1024;

#[pyfunction]
pub(crate) fn enc_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let reader = py.detach(|| ManagedReader::open(&archive_path))?;
    enc_fast_verify_passwords_with_reader(py, &reader, passwords)
}

pub(crate) fn enc_fast_verify_passwords_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|p| p.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    verify_prepared(py, InputKey::file("enc", reader)?, &candidates, || {
        prepare(reader.cursor(), reader.len()).map(PasswordContext::Enc)
    })
}

#[pyfunction]
pub(crate) fn enc_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|p| p.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;
    let length = ranges_total_len(&parsed);
    verify_prepared(py, ranges_key("enc", &parsed)?, &candidates, || {
        prepare(VirtualRangeReader::new(parsed.into()), length).map(PasswordContext::Enc)
    })
}

pub(crate) struct EncPasswordContext {
    probe: PasswordProbe,
}
fn prepare<R: Read + Seek>(
    mut reader: R,
    length: u64,
) -> Result<EncPasswordContext, PreparedStatus> {
    let mut bytes = [0; 72];
    read_exact_field(
        &mut reader,
        &mut bytes,
        length,
        "enc.password_proof",
        FieldLocation::Head,
    )?;
    PasswordProbe::parse(&bytes, length)
        .map(|probe| EncPasswordContext { probe })
        .map_err(|e| PreparedStatus::new("damaged", format!("ENC v4 password material: {e:?}")))
}
impl EncPasswordContext {
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
    pub(crate) fn verify(&self, py: Python<'_>, candidates: &[String]) -> PyResult<Py<PyAny>> {
        let found = py.detach(|| self.find_first(candidates));
        let (index, attempts) = match found {
            Some((index, Ok(()))) => (index as i32, index + 1),
            Some((_, Err(Error::Memory))) => {
                return Err(pyo3::exceptions::PyMemoryError::new_err(
                    "ENC Argon2 workspace allocation failed",
                ))
            }
            Some((_, Err(error))) => {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "ENC password proof: {error:?}"
                )))
            }
            None => (-1, candidates.len()),
        };
        let result = PyDict::new(py);
        result.set_item("status", if index >= 0 { "match" } else { "no_match" })?;
        result.set_item("matched_index", index)?;
        result.set_item("attempts", attempts)?;
        // The 32-byte [a-z0-9] proof has about 90 bits of rejection strength.
        // This selects one password; the normal extraction still checks BLAKE3.
        result.set_item("final_confirmation_required", false)?;
        result.set_item("match_evidence", "enc_v4_quick_block")?;
        result.set_item(
            "message",
            if index >= 0 {
                "ENC v4 quick block matched"
            } else {
                "ENC v4 quick block rejected candidates"
            },
        )?;
        Ok(result.into())
    }

    fn find_first(&self, candidates: &[String]) -> Option<(usize, Result<(), Error>)> {
        if candidates.is_empty() {
            return None;
        }
        let workers = rayon::current_num_threads()
            .min((PARALLEL_WORKSPACE_BYTES / self.probe.workspace_bytes()).max(1))
            .min(candidates.len().div_ceil(4))
            .max(1);
        let chunk_size = candidates.len().div_ceil(workers);
        let earliest = AtomicUsize::new(candidates.len());
        let search = |(chunk_index, chunk): (usize, &[String])| {
            let mut workspace = Workspace::default();
            let mut utf16 = Vec::new();
            for (offset, password) in chunk.iter().enumerate() {
                let index = chunk_index * chunk_size + offset;
                if index >= earliest.load(Ordering::Relaxed) {
                    break;
                }
                utf16.clear();
                utf16.extend(password.encode_utf16());
                match self.probe.matches(&utf16, &mut workspace) {
                    Ok(false) => (),
                    outcome => {
                        earliest.fetch_min(index, Ordering::Relaxed);
                        return Some((index, outcome.map(|_| ())));
                    }
                }
            }
            None
        };
        if workers == 1 {
            search((0, candidates))
        } else {
            candidates
                .par_chunks(chunk_size)
                .enumerate()
                .map(search)
                .find_first(Option::is_some)
                .flatten()
        }
    }
}
