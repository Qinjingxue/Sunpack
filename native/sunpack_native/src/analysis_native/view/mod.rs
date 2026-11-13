use crate::formats::rar::read_vint;
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, ReaderConfig};
use crc32fast::hash as crc32;
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
