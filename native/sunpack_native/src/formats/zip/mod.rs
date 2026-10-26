mod filename_encoding;
pub(crate) mod zip64;
pub(crate) use filename_encoding::analyze_zip_filename_encoding;

include!("constants.rs");
include!("directory/mod.rs");
include!("directory/parse.rs");
include!("directory/local.rs");
include!("directory/eocd.rs");
include!("directory/inspect.rs");

/// APPNOTE 4.3.13 permits one digital signature after the directory entries.
/// All directory consumers share this boundary check, including carrier scans.
pub(crate) fn central_directory_complete<E, B: AsRef<[u8]>>(
    cursor: u64,
    end: u64,
    mut read: impl FnMut(u64, usize) -> Result<B, E>,
) -> Result<bool, E> {
    if cursor == end {
        return Ok(true);
    }
    if cursor.checked_add(6).is_none_or(|position| position > end) {
        return Ok(false);
    }
    let bytes = read(cursor, 6)?;
    let signature = bytes.as_ref();
    Ok(signature.len() == 6
        && signature.starts_with(b"PK\x05\x05")
        && cursor.checked_add(6 + u16::from_le_bytes([signature[4], signature[5]]) as u64)
            == Some(end))
}
