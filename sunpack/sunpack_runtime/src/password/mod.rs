pub(crate) mod attempts;
pub(crate) mod context;
pub(crate) mod enc;
pub(crate) mod evidence;
pub(crate) mod input;
pub(crate) mod lists;
pub(crate) mod rar;
pub(crate) mod seven_zip;
pub(crate) mod zip;

use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::read_fault::ReadFault;
use crate::io::reader::{ManagedReader, NativeArchiveSession};
use std::{io, sync::Arc};

pub(crate) const VERIFICATION_BATCH_SIZE: usize = 256;

#[derive(Debug)]
pub(crate) struct PasswordVerification {
    // Per evidence path, indices into this batch's ordered surviving passwords.
    pub(crate) password_domains: Vec<Option<Vec<usize>>>,
    pub(crate) volume_attempts: Option<Arc<crate::io::archive_state::VolumeAttemptPlan>>,
    pub(crate) status: &'static str,
    pub(crate) matched_index: Option<usize>,
    pub(crate) matched_indices: Vec<usize>,
    pub(crate) attempts: usize,
    pub(crate) message: String,
    pub(crate) final_confirmation_required: Option<bool>,
    pub(crate) match_evidence: Option<&'static str>,
    pub(crate) read_fault: Option<ReadFault>,
}

impl PasswordVerification {
    pub(crate) fn status(status: &'static str, message: impl Into<String>) -> Self {
        Self {
            password_domains: Vec::new(),
            volume_attempts: None,
            status,
            matched_index: None,
            matched_indices: Vec::new(),
            attempts: 0,
            message: message.into(),
            final_confirmation_required: None,
            match_evidence: None,
            read_fault: None,
        }
    }
}

fn password_read_fault_status(fault: &ReadFault) -> PasswordVerification {
    let status = if fault.possible_missing_volume() {
        "needs_volume_or_tail_damaged"
    } else {
        "damaged"
    };
    PasswordVerification {
        read_fault: Some(fault.clone()),
        ..PasswordVerification::status(status, fault.to_string())
    }
}

pub(crate) fn verify(
    preparation: &mut context::Preparation,
    input: &ArchiveInput,
    passwords: &[Arc<str>],
    sessions: &[NativeArchiveSession],
    eocd_offset: Option<u64>,
) -> io::Result<PasswordVerification> {
    // This entry point receives the same input and sessions for every batch
    // of the plan. Even a cache hit must still check retirement and cancellation.
    if let Some(result) = preparation.verify_prepared(passwords)? {
        return Ok(result);
    }
    let format = input.format_hint.as_str();
    let eocd_offset = eocd_offset.or(input.analysis.zip_eocd_offset);
    if let (Some(plan), Some(head)) = (input.volume_attempts.as_deref(), input.parts.first()) {
        // The plan selects a reader, not eligibility for password screening.
        // Each verifier requests its evidence and retains unresolved paths.
        match format {
            "7z" => return seven_zip::seven_zip_fast_verify_passwords_from_attempts(
                preparation, &head.extent, plan, passwords, sessions),
            "rar" => return rar::rar_fast_verify_passwords_from_attempts(
                preparation, &head.extent, plan, passwords, sessions, input.analysis.rar_native_volume),
            "zip" => return zip::zip_fast_verify_passwords_from_attempts(
                preparation, &head.extent, plan, passwords, input.analysis.zip_spanned, eocd_offset, sessions),
            _ => {}
        }
    }
    if input.mode.structured() {
        if format == "rar" {
            return rar::rar_fast_verify_passwords_from_volumes(preparation, &input.parts, passwords, sessions, input.analysis.rar_native_volume);
        }
        if format == "zip" && input.analysis.zip_spanned {
            return zip::zip_fast_verify_passwords_from_volumes(
                preparation,
                &input.parts,
                passwords,
                eocd_offset,
                sessions,
            );
        }
    }
    // A byte-split stream stops at its first absent disk. Joining the next
    // available extent would put unrelated bytes at plausible proof offsets.
    let mut parts = input.parts.as_ref();
    if input.mode.structured() && matches!(format, "7z" | "zip" | "rar") {
        if let Some(gap) = parts.iter().enumerate()
            .position(|(i, part)| part.volume_number != Some(i as u32 + 1)) {
            if gap == 0 { return Ok(PasswordVerification::status("missing_volume", "logical volume prefix is unavailable")); }
            parts = &parts[..gap];
        }
    }
    let path = match (input.mode, parts) {
        (OpenMode::File, _) | (_, []) => input.entry_path.as_str(),
        (_, [part]) if part.extent.start == 0 && part.extent.end.is_none() => part.extent.path.as_str(),
        _ => {
            let ranges: Vec<_> = parts.iter().map(|part| &part.extent).collect();
            return match format {
                "enc" => enc::enc_fast_verify_passwords_from_ranges(preparation, &ranges, passwords, sessions),
                "rar" => rar::rar_fast_verify_passwords_from_ranges(preparation, &ranges, passwords, sessions),
                "7z" => seven_zip::seven_zip_fast_verify_passwords_from_ranges(
                    preparation,
                    &ranges, passwords, sessions,
                ),
                "zip" => zip::zip_fast_verify_passwords_from_ranges(
                    preparation,
                    &ranges,
                    passwords,
                    eocd_offset,
                    sessions,
                ),
                _ => Ok(unsupported()),
            };
        }
    };
    let reader = sessions
        .iter()
        .find(|session| session.path() == path)
        .map(|session| session.borrowed_reader().1)
        .map_or_else(|| ManagedReader::open(path), Ok)?;
    match format {
        "enc" => enc::enc_fast_verify_passwords_with_reader(preparation, &reader, passwords),
        "rar" => rar::rar_fast_verify_passwords_with_reader(preparation, &reader, passwords),
        "7z" => seven_zip::seven_zip_fast_verify_passwords_with_reader(preparation, &reader, passwords),
        "zip" => zip::zip_fast_verify_passwords_with_reader(preparation, &reader, passwords, eocd_offset),
        _ => Ok(unsupported()),
    }
}

fn unsupported() -> PasswordVerification {
    PasswordVerification::status(
        "unknown_needs_final_verifier",
        "archive format has no bounded password verifier",
    )
}

#[cfg(test)]
#[path = "../../tests/unit/password/logical_input_tests.rs"]
mod logical_input_tests;
