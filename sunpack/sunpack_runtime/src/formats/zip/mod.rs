mod filename_encoding;
mod relation;
pub(crate) use relation::*;
pub(crate) mod zip64;
pub(crate) use filename_encoding::analyze_zip_filename_encoding;

include!("constants.rs");
include!("directory/parse.rs");
include!("directory/local.rs");
include!("directory/eocd.rs");

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

// APPNOTE 4.3.16: fixed EOCD (22) plus a u16-sized comment.
pub(crate) const EOCD_SEARCH_BYTES: u64 = 22 + u16::MAX as u64;

/// Read the standard EOCD search window, reusing an existing prefix.
/// The common comment-free case needs only the final 22 bytes.
pub(crate) fn read_eocd_tail(
    reader: &crate::io::reader::ManagedReader,
    archive_start: u64,
    file_size: u64,
    prefix: &[u8],
    bytes_read: &mut u64,
) -> std::io::Result<(Vec<u8>, u64)> {
    let remaining = file_size.saturating_sub(archive_start);
    let tail_len = remaining.min(EOCD_SEARCH_BYTES);
    if tail_len == 0 {
        return Ok((Vec::new(), remaining));
    }

    if remaining <= prefix.len() as u64 {
        let start = (remaining - tail_len) as usize;
        return Ok((
            prefix[start..remaining as usize].to_vec(),
            remaining - tail_len,
        ));
    }

    const EOCD_MIN_SIZE: u64 = 22;
    let fast_len = tail_len.min(EOCD_MIN_SIZE);
    let fast_start = file_size - fast_len;
    let fast = reader.read_at(fast_start, fast_len as usize)?;
    *bytes_read += fast.len() as u64;

    let exact_eocd = fast.len() == EOCD_MIN_SIZE as usize
        && fast.starts_with(EOCD_SIG)
        && u16::from_le_bytes([fast[20], fast[21]]) == 0;
    if exact_eocd || tail_len == fast_len {
        return Ok((fast, remaining - fast_len));
    }

    let preceding_len = tail_len - fast_len;
    let full_start = file_size - tail_len;
    let mut tail = reader.read_at(full_start, preceding_len as usize)?;
    *bytes_read += tail.len() as u64;
    tail.extend_from_slice(&fast);
    Ok((tail, remaining - tail_len))
}
