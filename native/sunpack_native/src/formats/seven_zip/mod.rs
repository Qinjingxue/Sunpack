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

fn seven_zip_password(password: Option<&str>) -> Password {
    match password {
        Some(value) if !value.is_empty() => Password::from(value),
        _ => Password::empty(),
    }
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

include!("constants.rs");
include!("types.rs");
include!("header/parse.rs");
include!("header/encoded.rs");
