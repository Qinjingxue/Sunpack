//! ENC's quick block is a strong, bounded password proof. Authentication belongs
//! to extraction. Reuse the existing generation-aware prepared-context cache.
use super::context::{verify_prepared, InputKey, PasswordContext, PreparedStatus};
use super::input::{parse_ranges, ranges_key, ranges_total_len, VirtualRangeReader};
use super::PasswordVerification;
use crate::io::archive_state::InputExtent;
use crate::io::cancellation::Cancellation;
use crate::io::read_fault::{read_exact_field, FieldLocation};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use rayon::prelude::*;
use std::io::{Read, Seek};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use sunpack_enc::{Error, PasswordProbe, Workspace};

// Argon2 is memory-hard: bound aggregate scratch space for one batch, rather
// than allocating one workspace per password or retaining it in the cache.
const PARALLEL_WORKSPACE_BYTES: usize = 64 * 1024 * 1024;
static ACTIVE_BATCHES: AtomicUsize = AtomicUsize::new(0);
struct ActiveBatch;
impl ActiveBatch {
    fn enter() -> Self {
        ACTIVE_BATCHES.fetch_add(1, Ordering::Relaxed);
        Self
    }
}
impl Drop for ActiveBatch {
    fn drop(&mut self) {
        ACTIVE_BATCHES.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn enc_fast_verify_passwords_with_reader(
    reader: &ManagedReader,
    candidates: &[Arc<str>],
) -> std::io::Result<PasswordVerification> {
    verify_prepared(InputKey::file("enc", reader)?, candidates, || {
        prepare(reader.cursor(), reader.len()).map(PasswordContext::Enc)
    })
}

pub(crate) fn enc_fast_verify_passwords_from_ranges(
    ranges: &[&InputExtent],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let parsed = parse_ranges(ranges, sessions)?;
    let length = ranges_total_len(&parsed);
    verify_prepared(ranges_key("enc", &parsed)?, candidates, || {
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
    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        let found = self.find_first(candidates);
        let (index, attempts) = match found {
            Some((index, Ok(()))) => (index as i32, index + 1),
            Some((_, Err(Error::Memory))) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    "ENC Argon2 workspace allocation failed",
                ))
            }
            Some((_, Err(error))) => {
                return Err(std::io::Error::other(format!(
                    "ENC password proof: {error:?}"
                )))
            }
            None => (-1, candidates.len()),
        };
        // The quick-block proof selects a password. Extraction verifies BLAKE3.
        Ok(PasswordVerification {
            matched_index: usize::try_from(index).ok(),
            attempts,
            final_confirmation_required: Some(false),
            match_evidence: Some("enc_v4_quick_block"),
            ..if index >= 0 {
                PasswordVerification::status("match", "ENC v4 quick block matched")
            } else {
                PasswordVerification::status("no_match", "ENC v4 quick block rejected candidates")
            }
        })
    }

    fn find_first(&self, candidates: &[Arc<str>]) -> Option<(usize, Result<(), Error>)> {
        if candidates.is_empty() {
            return None;
        }
        let _batch = ActiveBatch::enter();
        // Each password already exposes four lanes to the shared executor.
        // Distribute candidate workspaces across active batches; otherwise
        // nested Rayon joins can retain a workspace for every parked candidate.
        let lanes_in_flight = ACTIVE_BATCHES
            .load(Ordering::Relaxed)
            .max(1)
            .saturating_mul(4);
        let workers = rayon::current_num_threads()
            .div_ceil(lanes_in_flight)
            .min((PARALLEL_WORKSPACE_BYTES / self.probe.workspace_bytes()).max(1))
            // Lanes already account for each KDF's executor demand above.
            // Dividing candidate count by four again serializes small batches.
            .min(candidates.len())
            .max(1);
        let chunk_size = candidates.len().div_ceil(workers);
        let earliest = AtomicUsize::new(candidates.len());
        let cancellation = Cancellation::current();
        let search = |(chunk_index, chunk): (usize, &[Arc<str>])| {
            let mut workspace = Workspace::default();
            workspace.set_cancellation(cancellation.flag());
            let mut utf16 = Vec::new();
            for (offset, password) in chunk.iter().enumerate() {
                let index = chunk_index * chunk_size + offset;
                if index >= earliest.load(Ordering::Relaxed) || cancellation.cancelled() {
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
