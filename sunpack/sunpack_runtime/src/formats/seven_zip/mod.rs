use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation};
use aes::{
    cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit},
    Aes256,
};
use crc32fast::hash as crc32;
use lzma_rust2::{
    filter::{bcj::BcjReader, bcj2::Bcj2Reader, delta::DeltaReader},
    Lzma2Reader, LzmaReader,
};
use sevenz_rust2::{EncoderMethod, Password};
use std::io::{Cursor, Read, Seek};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

include!("constants.rs");
include!("types.rs");
include!("header/parse.rs");
include!("header/encoded.rs");
/// The same checked descriptor is used to bound relation CRC reads and by
/// the password header reader. CRC protects format metadata, never output.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RelationNextHeader {
    pub offset: u64,
    pub size: u64,
    pub crc: u32,
}

impl RelationNextHeader {
    pub(crate) fn parse(header: &[u8]) -> Option<Self> {
        let header = header.first_chunk::<SEVEN_Z_HEADER_SIZE>()?;
        if !header.starts_with(SEVEN_Z_MAGIC) || header[6] != 0 {
            return None;
        }
        Self::checked_fields(header)
    }

    pub(crate) fn checked_fields(header: &[u8; SEVEN_Z_HEADER_SIZE]) -> Option<Self> {
        let offset = 32u64.checked_add(u64::from_le_bytes(header[12..20].try_into().ok()?))?;
        let size = u64::from_le_bytes(header[20..28].try_into().ok()?);
        offset.checked_add(size)?;
        Some(Self {
            offset,
            size,
            crc: u32::from_le_bytes(header[28..32].try_into().ok()?),
        })
    }
    pub(crate) fn end(self) -> u64 {
        self.offset + self.size
    }
}

pub(crate) fn relation_header_crc(
    path: &str,
    offset: u64,
    header: RelationNextHeader,
) -> std::io::Result<Option<bool>> {
    let reader = crate::io::reader::ManagedReader::open(path)?.probe_reader();
    if offset
        .checked_add(header.size)
        .is_none_or(|end| end > reader.len())
    {
        return Ok(None);
    }
    let first = reader.read_cached_at(offset, header.size.min(512) as usize)?;
    if !matches!(first.first(), Some(1 | 0x17)) {
        return Ok(None);
    }
    let mut crc = crc32fast::Hasher::new();
    crc.update(&first);
    update_relation_crc(
        &reader,
        offset + first.len() as u64,
        header.size - first.len() as u64,
        &mut crc,
    )?;
    Ok(Some(crc.finalize() == header.crc))
}

pub(crate) fn update_relation_crc(
    reader: &crate::io::reader::ManagedReader,
    mut offset: u64,
    mut remaining: u64,
    crc: &mut crc32fast::Hasher,
) -> std::io::Result<()> {
    while remaining != 0 {
        let len = remaining.min(64 * 1024) as usize;
        let bytes = reader.read_cached_at(offset, len)?;
        if bytes.len() != len {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        crc.update(&bytes);
        remaining -= len as u64;
        offset += len as u64;
    }
    Ok(())
}
