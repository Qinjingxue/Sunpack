pub(crate) mod context;
pub(crate) mod enc;
pub(crate) mod input;
pub(crate) mod lists;
pub(crate) mod rar;
pub(crate) mod seven_zip;
pub(crate) mod zip;

use crate::io::archive_state::{ArchiveInput, OpenMode};
use crate::io::read_fault::ReadFault;
use crate::io::reader::{ManagedReader, NativeArchiveSession};
use std::{io, sync::Arc};

#[derive(Debug)]
pub(crate) struct PasswordVerification {
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
    input: &ArchiveInput,
    passwords: &[Arc<str>],
    sessions: &[NativeArchiveSession],
    eocd_offset: Option<u64>,
) -> io::Result<PasswordVerification> {
    let format = input.format_hint.as_str();
    let eocd_offset = eocd_offset.or(input.analysis.zip_eocd_offset);
    if input.mode.structured() {
        if format == "rar" {
            return rar::rar_fast_verify_passwords_from_volumes(&input.parts, passwords, sessions);
        }
        if format == "zip" && input.analysis.zip_spanned {
            return zip::zip_fast_verify_passwords_from_volumes(
                &input.parts,
                passwords,
                eocd_offset,
                sessions,
            );
        }
        if input.mode == OpenMode::SfxWithVolumes {
            return Ok(unsupported());
        }
    }
    let range = if input.mode == OpenMode::File {
        None
    } else {
        let ranges = if input.ranges.is_empty() {
            input
                .parts
                .iter()
                .map(|part| &part.extent)
                .collect::<Vec<_>>()
        } else {
            input.ranges.iter().collect()
        };
        if ranges.len() == 1 && ranges[0].start == 0 && ranges[0].end.is_none() {
            Some(ranges[0].path.as_str())
        } else if !ranges.is_empty() {
            return match format {
                "enc" => enc::enc_fast_verify_passwords_from_ranges(&ranges, passwords, sessions),
                "rar" => rar::rar_fast_verify_passwords_from_ranges(&ranges, passwords, sessions),
                "7z" => seven_zip::seven_zip_fast_verify_passwords_from_ranges(
                    &ranges, passwords, sessions,
                ),
                "zip" => zip::zip_fast_verify_passwords_from_ranges(
                    &ranges,
                    passwords,
                    eocd_offset,
                    sessions,
                ),
                _ => Ok(unsupported()),
            };
        } else {
            None
        }
    };
    let path = range.unwrap_or(&input.entry_path);
    let reader = sessions
        .iter()
        .find_map(|session| {
            let (session_path, reader) = session.borrowed_reader();
            (session_path == path).then_some(reader)
        })
        .map_or_else(|| ManagedReader::open(path), Ok)?;
    match format {
        "enc" => enc::enc_fast_verify_passwords_with_reader(&reader, passwords),
        "rar" => rar::rar_fast_verify_passwords_with_reader(&reader, passwords),
        "7z" => seven_zip::seven_zip_fast_verify_passwords_with_reader(&reader, passwords),
        "zip" => zip::zip_fast_verify_passwords_with_reader(&reader, passwords, eocd_offset),
        _ => Ok(unsupported()),
    }
}

fn unsupported() -> PasswordVerification {
    PasswordVerification::status(
        "unknown_needs_final_verifier",
        "archive format has no bounded password verifier",
    )
}
