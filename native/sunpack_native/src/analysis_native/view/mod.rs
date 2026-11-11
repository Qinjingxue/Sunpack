use super::diagnostic::{DiagnosticFields, DiagnosticFieldsExt};
use crate::formats::rar::read_vint;
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, ReaderConfig};
use crc32fast::hash as crc32;
use serde_json::Value;
use std::io::{self, Read};

include!("constants.rs");
include!("types.rs");
include!("binary.rs");
include!("impls.rs");
include!("rar.rs");
include!("seven_zip.rs");
include!("signatures.rs");
include!("tar.rs");
include!("report.rs");
include!("lz4.rs");

fn reader_error(error: io::Error) -> io::Error {
    crate::io::resource_error::to_io_error(error)
}

fn set_view_read_fault(
    result: &mut DiagnosticFields,
    fault: &ReadFault,
    legacy_error: &str,
) -> io::Result<()> {
    result.put("error", legacy_error)?;
    result.insert("read_error".into(), fault.to_diagnostic());
    let mut flags = str_list(result, "damage_flags")?;
    for flag in [
        "read_error",
        "input_truncated",
        "probably_truncated",
        "missing_volume",
    ] {
        let applies = match flag {
            "input_truncated" | "probably_truncated" => fault.code == "unexpected_eof",
            "missing_volume" => fault.possible_missing_volume(),
            _ => true,
        };
        if applies && !flags.iter().any(|existing| existing == flag) {
            flags.push(flag.to_string());
        }
    }
    result.put("damage_flags", flags)
}
